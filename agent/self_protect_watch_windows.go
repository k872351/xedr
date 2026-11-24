//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

// 自保护巡检：服务映像/启动类型被改、ETW 会话丢失时发出告警。

type selfProtectWatch struct {
	mu          sync.Mutex
	expectImage string
	lastService time.Time
	lastETW     time.Time
	emit        func(map[string]any)
}

var spWatch = &selfProtectWatch{}

func (w *selfProtectWatch) setEmit(fn func(map[string]any)) {
	w.mu.Lock()
	w.emit = fn
	w.mu.Unlock()
}

func (w *selfProtectWatch) ensureBaseline() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.expectImage != "" {
		return
	}
	if self, err := os.Executable(); err == nil {
		w.expectImage, _ = filepath.Abs(self)
	}
}

func (w *selfProtectWatch) tick() {
	if !isSelfProtect() {
		return
	}
	w.ensureBaseline()
	now := time.Now()
	w.mu.Lock()
	emit := w.emit
	expect := w.expectImage
	dueSvc := w.lastService.IsZero() || now.Sub(w.lastService) > 2*time.Minute
	dueETW := w.lastETW.IsZero() || now.Sub(w.lastETW) > 2*time.Minute
	if dueSvc {
		w.lastService = now
	}
	if dueETW {
		w.lastETW = now
	}
	w.mu.Unlock()
	if emit == nil {
		return
	}
	if dueSvc {
		if ev := checkServiceTamper(expect); ev != nil {
			emit(ev)
		}
	}
	if dueETW {
		if ev := checkETWSessionTamper(); ev != nil {
			emit(ev)
		}
	}
}

func checkServiceTamper(expectImage string) map[string]any {
	m, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return map[string]any{
			"etype": "agent_self_protect", "severity": "critical",
			"summary": "Agent 服务缺失或无法打开",
			"ts":      time.Now().Format("2006-01-02T15:04:05"),
			"detail": map[string]any{
				"check": "service_missing", "service": serviceName, "error": err.Error(),
				"mitre": []string{"T1562"}, "evidence": "自保护巡检无法打开自身服务",
			},
		}
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return nil
	}
	img := strings.Trim(cfg.BinaryPathName, `"`)
	if i := strings.Index(strings.ToLower(img), ".exe"); i > 0 {
		img = img[:i+4]
	}
	imgAbs, _ := filepath.Abs(img)
	expectAbs, _ := filepath.Abs(expectImage)
	detail := map[string]any{
		"service": serviceName, "image": imgAbs, "expected": expectAbs,
		"start_type": cfg.StartType, "mitre": []string{"T1562"},
	}
	if expectAbs != "" && imgAbs != "" && !strings.EqualFold(imgAbs, expectAbs) {
		detail["check"] = "service_image_tamper"
		detail["evidence"] = "服务映像路径与当前 Agent 可执行文件不一致"
		return map[string]any{
			"etype": "agent_self_protect", "severity": "critical",
			"summary": "Agent 服务映像被篡改",
			"ts":      time.Now().Format("2006-01-02T15:04:05"),
			"detail":  detail,
		}
	}
	// StartType: 2=Automatic 3=Manual 4=Disabled
	if cfg.StartType == 4 {
		detail["check"] = "service_disabled"
		detail["evidence"] = "Agent 服务被设为禁用"
		return map[string]any{
			"etype": "agent_self_protect", "severity": "high",
			"summary": "Agent 服务被禁用",
			"ts":      time.Now().Format("2006-01-02T15:04:05"),
			"detail":  detail,
		}
	}
	return nil
}

func checkETWSessionTamper() map[string]any {
	// logman query -ets 中应能看到会话名
	out, err := runCmd(15*time.Second, "logman", "query", "-ets")
	if err != nil {
		return nil
	}
	if strings.Contains(strings.ToLower(out), strings.ToLower(etwSessionName)) {
		return nil
	}
	// 仅在原生 ETW 能力开启时告警
	if !integrationEnabled("etw") {
		return nil
	}
	return map[string]any{
		"etype": "agent_self_protect", "severity": "high",
		"summary": "ETW 采集会话丢失: " + etwSessionName,
		"ts":      time.Now().Format("2006-01-02T15:04:05"),
		"detail": map[string]any{
			"check": "etw_session_missing", "session": etwSessionName,
			"mitre": []string{"T1562.006"}, "evidence": "预期的实时 ETW 会话不在 logman -ets 列表中",
			"hint":  fmt.Sprintf("output_snip=%s", truncate(out, 200)),
		},
	}
}
