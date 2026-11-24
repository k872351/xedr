//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// 落地文件扫描：可执行/脚本落地后异步读取内容，用 字符串规则 / YARA（如编译启用）/ PE 启发式 /
// MOTW / 签名 融合打分，给出 clean|suspicious|malicious；策略允许时对高分未签名文件自动隔离。
// 只在独立 worker 中读盘，绝不阻塞 ETW 回调。

type dropScanSettings struct {
	Enabled            bool
	AutoQuarantine     bool
	QuarantineMinScore int
	MaxFileMB          int
}

var (
	dropScanCfgMu sync.RWMutex
	dropScanCfg   = dropScanSettings{Enabled: true, QuarantineMinScore: 80, MaxFileMB: 32}
)

func applyDropScanPolicy(pol map[string]any) {
	raw, ok := pol["drop_scan"].(map[string]any)
	if !ok || raw == nil {
		return
	}
	dropScanCfgMu.Lock()
	defer dropScanCfgMu.Unlock()
	if b, ok := raw["enabled"].(bool); ok {
		dropScanCfg.Enabled = b
	}
	if b, ok := raw["auto_quarantine"].(bool); ok {
		dropScanCfg.AutoQuarantine = b
	}
	if n, ok := numberOf(raw["quarantine_min_score"]); ok && n >= 50 && n <= 200 {
		dropScanCfg.QuarantineMinScore = int(n)
	}
	if n, ok := numberOf(raw["max_file_mb"]); ok && n >= 1 && n <= 128 {
		dropScanCfg.MaxFileMB = int(n)
	}
}

func dropScanSettingsSnapshot() dropScanSettings {
	dropScanCfgMu.RLock()
	defer dropScanCfgMu.RUnlock()
	return dropScanCfg
}

var dropScanScriptExt = map[string]bool{
	".ps1": true, ".vbs": true, ".js": true, ".jse": true, ".hta": true,
	".bat": true, ".cmd": true, ".wsf": true,
}

var dropScanBinaryExt = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".sys": true, ".cpl": true,
}

// 脚本内容可疑特征：每命中一项加分，总分封顶
var dropScanScriptTokens = []struct {
	token, reason string
	score         int
}{
	{"frombase64string", "脚本解码 Base64", 12},
	{"-encodedcommand", "PowerShell 编码命令", 12},
	{" -enc ", "PowerShell 编码命令", 12},
	{"invoke-expression", "动态执行 Invoke-Expression", 10},
	{"iex(", "动态执行 IEX", 10},
	{"downloadstring", "远程下载执行", 15},
	{"downloadfile", "远程下载文件", 12},
	{"net.webclient", "WebClient 下载", 10},
	{"invoke-webrequest", "Invoke-WebRequest 下载", 8},
	{"wscript.shell", "WScript.Shell 执行", 8},
	{"adodb.stream", "ADODB.Stream 写文件", 10},
	{"virtualalloc", "脚本内调用 VirtualAlloc", 15},
	{"add-mppreference", "修改 Defender 排除", 20},
	{"set-mppreference", "修改 Defender 配置", 15},
	{"bitsadmin", "BITS 下载", 10},
	{"certutil -urlcache", "certutil 下载", 15},
	{"-windowstyle hidden", "隐藏窗口执行", 8},
	{"amsiutils", "AMSI 绕过特征", 25},
	{"reflection.assembly]::load", "内存加载程序集", 15},
}

type dropScanReq struct {
	path   string
	source map[string]any
	etype  string
	at     time.Time
}

type dropScanner struct {
	once sync.Once
	ch   chan dropScanReq
	mu   sync.Mutex
	out  []map[string]any
	seen map[string]time.Time
	// sha256 → 最近一次结论，同一文件被复制到多个位置时不重复读规则
	bySHA map[string]map[string]any
}

var dropScan = &dropScanner{
	ch:    make(chan dropScanReq, 64),
	seen:  map[string]time.Time{},
	bySHA: map[string]map[string]any{},
}

func dropScanCandidate(ev map[string]any) (string, bool) {
	et := strings.ToLower(asString(ev["etype"]))
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return "", false
	}
	p := strings.TrimSpace(asString(d["path"]))
	switch et {
	case "file_create", "file_rename", "fim_add", "fim_modify", "fim_rename":
		if et == "file_rename" || et == "fim_rename" {
			p = strings.TrimSpace(firstNonEmpty(asString(d["new_path"]), asString(d["path"]), p))
		}
	case "win_bits":
		p = strings.TrimSpace(firstNonEmpty(asString(d["local_path"]), asString(d["payload_path"]), p))
	case "win_task_create", "win_task_update", "win_task_ops":
		p = strings.TrimSpace(firstNonEmpty(asString(d["task_execute"]), asString(d["payload_path"]), asString(d["path"]), p))
	case "win_smb", "lateral_tool":
		p = strings.TrimSpace(firstNonEmpty(asString(d["path"]), asString(d["matched"]), p))
	default:
		return "", false
	}
	if p == "" || isAgentSelfNoisePath(p) {
		return "", false
	}
	ext := strings.ToLower(filepath.Ext(p))
	if !dropScanScriptExt[ext] && !dropScanBinaryExt[ext] {
		return "", false
	}
	if isWindowsSystemPath(p) {
		return "", false
	}
	if !pathInDropZone(p) && !pathLooksHot(p) && !pathAtDriveRoot(p) {
		sev := strings.ToLower(asString(ev["severity"]))
		if sev != "medium" && sev != "high" && sev != "critical" {
			return "", false
		}
	}
	return p, true
}

// observe 在实时事件管线中调用；只做过滤与入队。
func (s *dropScanner) observe(ev map[string]any) {
	if ev == nil || !dropScanSettingsSnapshot().Enabled {
		return
	}
	p, ok := dropScanCandidate(ev)
	if !ok {
		return
	}
	captureAdd("drop_scan_requests", "received", 1)
	s.once.Do(func() { go s.worker() })
	d, _ := ev["detail"].(map[string]any)
	select {
	case s.ch <- dropScanReq{path: p, source: d, etype: asString(ev["etype"]), at: time.Now()}:
		captureAdd("drop_scan_requests", "queued", 1)
	default:
		captureAdd("drop_scan_requests", "buffer_dropped", 1)
	}
}

func (s *dropScanner) drain() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.out
	s.out = nil
	captureAdd("drop_scan_results", "drained", len(out))
	return out
}

func (s *dropScanner) push(ev map[string]any) {
	captureTag(ev, "drop_scan_results")
	captureAdd("drop_scan_results", "received", 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.out) >= 200 {
		captureAdd("drop_scan_results", "buffer_dropped", 1)
		s.out = s.out[1:]
	}
	s.out = append(s.out, ev)
	captureAdd("drop_scan_results", "queued", 1)
}

func (s *dropScanner) worker() {
	for req := range s.ch {
		captureAdd("drop_scan_requests", "drained", 1)
		// 等写入落定：ETW 文件创建往往早于写完
		if wait := 1500*time.Millisecond - time.Since(req.at); wait > 0 {
			time.Sleep(wait)
		}
		if ev := s.scan(req); ev != nil {
			s.push(ev)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *dropScanner) dedupKey(path string, fi os.FileInfo) string {
	return fmt.Sprintf("%s|%d|%d", strings.ToLower(path), fi.Size(), fi.ModTime().Unix())
}

func (s *dropScanner) markSeen(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if t, ok := s.seen[key]; ok && now.Sub(t) < time.Hour {
		return false
	}
	if len(s.seen) > 4096 {
		for k, t := range s.seen {
			if now.Sub(t) > time.Hour {
				delete(s.seen, k)
			}
		}
		if len(s.seen) > 4096 {
			s.seen = map[string]time.Time{}
		}
	}
	s.seen[key] = now
	return true
}

func readHead(path string, max int64) ([]byte, string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", false, err
	}
	defer f.Close()
	h := sha256.New()
	buf, err := io.ReadAll(io.TeeReader(io.LimitReader(f, max), h))
	if err != nil {
		return nil, "", false, err
	}
	// 未读完的文件继续算完整哈希，内容只保留前 max 字节
	n, _ := io.Copy(h, f)
	return buf, hex.EncodeToString(h.Sum(nil)), n == 0, nil
}

func (s *dropScanner) scan(req dropScanReq) map[string]any {
	cfg := dropScanSettingsSnapshot()
	fi, err := os.Stat(req.path)
	if err != nil || fi.IsDir() || fi.Size() == 0 {
		return nil
	}
	if !s.markSeen(s.dedupKey(req.path, fi)) {
		return nil
	}
	maxBytes := int64(cfg.MaxFileMB) << 20
	if fi.Size() > maxBytes*4 {
		return nil
	}
	content, sha, complete, err := readHead(req.path, maxBytes)
	if err != nil {
		return nil
	}

	ext := strings.ToLower(filepath.Ext(req.path))
	isScript := dropScanScriptExt[ext]
	score := 0
	var reasons []string
	var hits []map[string]any
	engines := []string{"strings"}
	maxRuleSev := ""
	add := func(n int, why string) {
		score += n
		reasons = append(reasons, fmt.Sprintf("%s(+%d)", why, n))
	}
	sevScore := map[string]int{"critical": 60, "high": 45, "medium": 20, "low": 8}
	sevRank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

	s.mu.Lock()
	cached := s.bySHA[sha]
	s.mu.Unlock()
	if cached != nil {
		if prev, ok := cached["rule_hits"].([]map[string]any); ok {
			hits = prev
		}
	} else {
		for _, h := range matchJSONMemoryRules(content) {
			h["type"] = "file_rule"
			hits = append(hits, h)
		}
		if yaraEngineOK {
			engines = append(engines, "yara")
			for _, h := range scanYaraOnRegion(content, 0, 0, filepath.Base(req.path)) {
				h["type"] = "file_yara"
				delete(h, "address")
				delete(h, "pid")
				h["summary"] = fmt.Sprintf("YARA[%s]: %s", asString(h["rule_name"]), filepath.Base(req.path))
				hits = append(hits, h)
			}
		}
	}
	ruleScore := 0
	for _, h := range hits {
		sev := strings.ToLower(asString(h["severity"]))
		n := sevScore[sev]
		if h["building_block"] == true {
			n /= 2
		}
		if asString(h["type"]) == "file_yara" && n < 45 {
			n = 45
		}
		ruleScore += n
		if sevRank[sev] > sevRank[maxRuleSev] {
			maxRuleSev = sev
		}
	}
	if ruleScore > 0 {
		if ruleScore > 90 {
			ruleScore = 90
		}
		add(ruleScore, fmt.Sprintf("规则命中 %d 条", len(hits)))
	}

	detail := map[string]any{
		"path": req.path, "name": filepath.Base(req.path), "ext": ext,
		"size": fi.Size(), "sha256": sha, "sha256_complete": complete,
		"source_etype": req.etype,
	}
	for _, k := range []string{"pid", "process_name", "entity_id", "process_guid"} {
		if v, ok := req.source[k]; ok && v != nil && asString(v) != "" {
			detail[k] = v
		}
	}

	if isScript {
		low := strings.ToLower(string(content))
		tok := 0
		seenReason := map[string]bool{}
		for _, t := range dropScanScriptTokens {
			if strings.Contains(low, t.token) && !seenReason[t.reason] {
				seenReason[t.reason] = true
				tok += t.score
				reasons = append(reasons, fmt.Sprintf("%s(+%d)", t.reason, t.score))
			}
		}
		if tok > 45 {
			tok = 45
		}
		score += tok
	}

	signedValid := false
	if dropScanBinaryExt[ext] {
		engines = append(engines, "pe")
		if meta, err := peFileMetaOf(req.path); err == nil && meta != nil {
			applyPEFileMeta(detail, meta)
			if meta.PackedLikely {
				add(15, "疑似加壳/高熵节")
			}
			if meta.CompileFuture {
				add(10, "编译时间在未来")
			}
			if meta.CompileAncient {
				add(5, "编译时间异常久远")
			}
		}
		valid, status := peSignedValid(req.path)
		signedValid = valid
		if status != "" {
			detail["signed"] = status
		}
		if valid {
			score -= 40
			reasons = append(reasons, "有效 Authenticode 签名(-40)")
		} else if peSignedExplicitBad(status) {
			add(10, "未签名或签名无效")
		}
	}
	if mw := motwOf(req.path); mw.Present {
		detail["motw"] = true
		if mw.ZoneID >= 0 {
			detail["motw_zone"] = mw.ZoneID
			detail["motw_zone_label"] = motwZoneLabel(mw.ZoneID)
		}
		if mw.HostURL != "" {
			detail["motw_host_url"] = mw.HostURL
		}
		if mw.ZoneID == 3 || mw.ZoneID == 4 {
			add(15, "来自互联网（MOTW）")
		}
	}
	if pathAtDriveRoot(req.path) {
		add(10, "落在盘符根目录")
	} else if pathInDropZone(req.path) {
		add(10, "落在投放目录")
	}
	if score < 0 {
		score = 0
	}

	verdict := "clean"
	switch {
	case score >= 70:
		verdict = "malicious"
	case score >= 35:
		verdict = "suspicious"
	}
	detail["verdict"] = verdict
	detail["score"] = score
	detail["reasons"] = reasons
	detail["engines"] = engines
	if len(hits) > 0 {
		sort.SliceStable(hits, func(i, j int) bool {
			return sevRank[strings.ToLower(asString(hits[i]["severity"]))] > sevRank[strings.ToLower(asString(hits[j]["severity"]))]
		})
		if len(hits) > 10 {
			hits = hits[:10]
		}
		detail["rule_hits"] = hits
	}
	s.mu.Lock()
	if len(s.bySHA) > 2048 {
		s.bySHA = map[string]map[string]any{}
	}
	s.bySHA[sha] = map[string]any{"rule_hits": hits}
	s.mu.Unlock()

	if verdict == "clean" {
		return nil
	}

	sev := "medium"
	if verdict == "malicious" {
		sev = "high"
		if maxRuleSev == "critical" {
			sev = "critical"
		}
	}
	if verdict == "malicious" && cfg.AutoQuarantine && score >= cfg.QuarantineMinScore &&
		!signedValid && !isWindowsSystemPath(req.path) {
		res, qerr := quarantineFile(globalCfg, map[string]any{"path": req.path, "sha256": sha})
		if qerr != nil {
			detail["quarantine_error"] = qerr.Error()
		} else {
			detail["quarantined"] = true
			detail["quarantine_dest"] = asString(res["dest"])
		}
	}
	label := map[string]string{"malicious": "恶意", "suspicious": "可疑"}[verdict]
	sum := fmt.Sprintf("落地文件扫描[%s]: %s（%d 分）", label, filepath.Base(req.path), score)
	if detail["quarantined"] == true {
		sum += " 已自动隔离"
	}
	return map[string]any{
		"etype": "file_scan", "summary": sum, "severity": sev,
		"ts": time.Now().Format("2006-01-02T15:04:05"), "detail": detail,
	}
}
