//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx       = modKernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory    = modKernel32.NewProc("ReadProcessMemory")
	procCreateToolhelp32Snap = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW      = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW       = modKernel32.NewProc("Process32NextW")
)

const (
	th32csSnapProcess = 0x00000002
	memCommit         = 0x1000
	pageExecuteRead   = 0x20
	pageExecuteRW     = 0x40
	pageExecuteWrite  = 0x80
	pageReadWrite     = 0x04
	pageWriteCopy     = 0x08
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type processEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// processNameMatch 比较进程名（忽略大小写与路径，兼容缺 .exe）。
func processNameMatch(have, want string) bool {
	a := strings.ToLower(strings.TrimSpace(filepath.Base(have)))
	b := strings.ToLower(strings.TrimSpace(filepath.Base(want)))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return strings.TrimSuffix(a, ".exe") == strings.TrimSuffix(b, ".exe")
}

func scanMemoryTargetName(params map[string]any) string {
	for _, k := range []string{"process_name", "name", "image", "path"} {
		s := strings.TrimSpace(asString(params[k]))
		if s == "" {
			continue
		}
		base := filepath.Base(s)
		if base != "" && base != "." && base != string(filepath.Separator) {
			return base
		}
	}
	return ""
}

// 内存扫描：启发式 + rules.json 字符串 +（-tags yara 时）YARA。
// 定向扫描：优先 pid；pid 已退出时可按 process_name 回退，避免威胁详情里看到进程仍在跑却扫不到。
func scanMemory(params map[string]any) (map[string]any, error) {
	finishWork := beginComponentWork("memory_scan")
	defer finishWork()
	ms := memoryScanSettingsSnapshot()
	mode := ms.Mode
	if force := strings.TrimSpace(asString(params["force_mode"])); force != "" {
		mode = force
	}
	if mode == memModeOff {
		return map[string]any{"ok": true, "skipped": true, "mode": mode}, nil
	}
	useHeuristic := mode == memModeHeuristic || !memoryScanUsesYara(ms)
	useRules := mode != memModeOff && (memoryScanUsesYara(ms) || mode == memModeHeuristic)

	maxProc := ms.MaxProcesses
	if maxProc <= 0 {
		maxProc = 20
	}
	if v := asInt(params["max_processes"]); v > 0 {
		maxProc = v
	}
	targetPID := asInt(params["pid"])
	targetName := scanMemoryTargetName(params)
	requestedPID := targetPID

	self := uint32(os.Getpid())
	procs, err := listPIDs()
	if err != nil {
		return nil, err
	}

	pidAlive := false
	if targetPID > 0 {
		for _, p := range procs {
			if int(p.pid) == targetPID {
				if targetName != "" && !processNameMatch(p.name, targetName) {
					result := map[string]any{"ok": false, "scanned": 0, "scan_status": "identity_unconfirmed", "pid_fallback": "disabled"}
					recordMemoryQuality(result)
					return result, fmt.Errorf("目标进程名称已变化，拒绝扫描其他进程")
				}
				pidAlive = true
				break
			}
		}
		if !pidAlive {
			result := map[string]any{
				"ok": false, "scanned": 0, "finding_count": 0, "pid": requestedPID,
				"scan_status": "target_exited", "pid_fallback": "disabled",
			}
			recordMemoryQuality(result)
			return result, fmt.Errorf("未找到该进程（pid=%d）", requestedPID)
		}
		if guid := strings.TrimSpace(asString(params["process_guid"])); guid != "" {
			parts := strings.SplitN(guid, "_", 2)
			if len(parts) != 2 || parseCreateTime(parts[1]).IsZero() {
				result := map[string]any{"ok": false, "scanned": 0, "scan_status": "identity_unconfirmed"}
				recordMemoryQuality(result)
				return result, fmt.Errorf("目标进程身份缺少有效创建时间")
			}
			if err := verifyProcessIdentity(targetPID, guid); err != nil {
				result := map[string]any{"ok": false, "scanned": 0, "scan_status": "identity_unconfirmed"}
				recordMemoryQuality(result)
				return result, err
			}
		}
	}

	findings := []map[string]any{}
	scanned := 0
	attempted, openFailed, accessDenied, noReadableData, partial, budgetLimited := 0, 0, 0, 0, 0, 0
	scanLimitReached := false
	matchedPIDs := []int{}
	for _, p := range procs {
		if p.pid == self || p.pid == 0 {
			continue
		}
		if targetPID > 0 && int(p.pid) != targetPID {
			continue
		}
		if targetPID == 0 && targetName != "" && !processNameMatch(p.name, targetName) {
			continue
		}
		if targetPID == 0 && targetName == "" && attempted >= maxProc {
			scanLimitReached = true
			break
		}
		// 跳过明显系统关键进程（全机扫描时）；定向扫描不跳过
		if targetPID == 0 && targetName == "" {
			low := strings.ToLower(p.name)
			if low == "csrss.exe" || low == "smss.exe" || low == "wininit.exe" || low == "services.exe" {
				continue
			}
		}
		outcome := &scanProcessOutcome{}
		attempted++
		hits := scanProcess(p.pid, p.name, scanProcessOpts{
			heuristic: useHeuristic,
			rules:     useRules,
			yara:      memoryScanUsesYara(ms),
			integrity: ms.IntegrityChecks,
			maxReadKB: ms.MaxRegionReadKB,
			outcome:   outcome,
		})
		switch {
		case outcome.openFailed:
			openFailed++
			if outcome.accessDenied {
				accessDenied++
			}
		case outcome.readRegions == 0:
			noReadableData++
		default:
			scanned++
			matchedPIDs = append(matchedPIDs, int(p.pid))
			if outcome.partial {
				partial++
			}
		}
		if outcome.budgetLimited {
			budgetLimited++
		}
		findings = append(findings, hits...)
		if len(findings) >= 50 {
			scanLimitReached = true
			break
		}
		// 按名匹配时也可能有多实例；限制数量避免一次扫太多
		if targetPID == 0 && targetName != "" && attempted >= maxProc {
			scanLimitReached = true
			break
		}
	}
	if (requestedPID > 0 || targetName != "") && attempted == 0 {
		hint := ""
		if requestedPID > 0 {
			hint = fmt.Sprintf("pid=%d", requestedPID)
		}
		if targetName != "" {
			if hint != "" {
				hint += " "
			}
			hint += "name=" + targetName
		}
		return map[string]any{
			"ok": false, "scanned": 0, "finding_count": 0,
			"pid": requestedPID, "process_name": targetName,
		}, fmt.Errorf("未找到该进程（%s）", hint)
	}
	integrityScanned := 0
	if ms.IntegrityChecks {
		integrityTarget := targetPID
		if integrityTarget == 0 && len(matchedPIDs) == 1 {
			integrityTarget = matchedPIDs[0]
		}
		// 定向 / 手动扫描不去重，保证每次都能看到完整结论
		extra, n := runIntegrityChecks(integrityTarget, integrityTarget == 0 && asString(params["trigger"]) == "schedule")
		findings = append(findings, extra...)
		integrityScanned = n
	}
	out := map[string]any{
		"ok":                 true,
		"mode":               mode,
		"yara_engine":        yaraEngineOK,
		"rules_rev":          memRulesRev,
		"trigger":            asString(params["trigger"]),
		"scanned":            scanned,
		"attempted":          attempted,
		"open_failed":        openFailed,
		"access_denied":      accessDenied,
		"no_readable_data":   noReadableData,
		"partial":            partial,
		"budget_limited":     budgetLimited,
		"scan_limit_reached": scanLimitReached,
		"integrity_scanned":  integrityScanned,
		"findings":           findings,
		"finding_count":      len(findings),
		"ts":                 time.Now().Format("2006-01-02T15:04:05"),
	}
	out["scan_status"] = "read_completed"
	if scanned == 0 {
		out["scan_status"] = "no_readable_data"
		out["ok"] = false
	} else if openFailed > 0 || noReadableData > 0 || partial > 0 || budgetLimited > 0 || scanLimitReached {
		out["scan_status"] = "partial"
	}
	if (requestedPID > 0 || targetName != "") && scanned == 0 {
		recordMemoryQuality(out)
		return out, fmt.Errorf("目标内存读取未成功，不能视为无命中")
	}
	if requestedPID > 0 {
		out["requested_pid"] = requestedPID
		out["pid_fallback"] = "disabled"
	}
	if targetName != "" {
		out["process_name"] = targetName
	}
	if len(matchedPIDs) > 0 {
		out["matched_pids"] = matchedPIDs
	}
	recordMemoryQuality(out)
	return out, nil
}

type scanProcessOpts struct {
	heuristic bool
	rules     bool
	yara      bool
	integrity bool
	maxReadKB int
	outcome   *scanProcessOutcome
}

type scanProcessOutcome struct {
	readRegions                                      int
	openFailed, accessDenied, partial, budgetLimited bool
}

type pidName struct {
	pid        uint32
	ppid       uint32
	name       string
	createTime string
	guid       string
}

func listPIDs() ([]pidName, error) {
	snap, _, err := procCreateToolhelp32Snap.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %v", err)
	}
	h := windows.Handle(snap)
	defer windows.CloseHandle(h)
	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	r, _, err := procProcess32FirstW.Call(uintptr(h), uintptr(unsafe.Pointer(&pe)))
	if r == 0 {
		return nil, fmt.Errorf("Process32First: %v", err)
	}
	var out []pidName
	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		out = append(out, pidName{pid: pe.ProcessID, ppid: pe.ParentProcessID, name: name})
		pe.Size = uint32(unsafe.Sizeof(pe))
		r, _, _ = procProcess32NextW.Call(uintptr(h), uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}
	return out, nil
}

func scanProcess(pid uint32, name string, opt scanProcessOpts) []map[string]any {
	if opt.outcome == nil {
		opt.outcome = &scanProcessOutcome{}
	}
	outcome := opt.outcome
	if opt.maxReadKB <= 0 {
		opt.maxReadKB = 512
	}
	maxRead := uintptr(opt.maxReadKB * 1024)
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		outcome.openFailed = true
		outcome.accessDenied = err == windows.ERROR_ACCESS_DENIED
		return nil
	}
	defer windows.CloseHandle(h)

	var findings []map[string]any
	var addr uintptr
	rwxRegions := 0
	mzInPrivate := 0
	suspiciousStr := 0

	for {
		var mbi memoryBasicInformation
		n, _, _ := procVirtualQueryEx.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
		if n == 0 {
			break
		}
		size := mbi.RegionSize
		if size == 0 {
			break
		}
		next := mbi.BaseAddress + size
		if next <= addr {
			break
		}
		addr = next

		if mbi.State != memCommit {
			continue
		}
		prot := mbi.Protect
		execish := prot&(pageExecuteRead|pageExecuteRW|pageExecuteWrite) != 0
		rw := prot&(pageReadWrite|pageWriteCopy|pageExecuteRW) != 0
		if !execish && !rw {
			continue
		}
		// 限制单区读取
		readSize := size
		if readSize > maxRead {
			outcome.budgetLimited = true
			outcome.partial = true
			readSize = maxRead
		}
		if readSize < 64 {
			continue
		}
		buf := make([]byte, readSize)
		var read uintptr
		r, _, _ := procReadProcessMemory.Call(uintptr(h), mbi.BaseAddress, uintptr(unsafe.Pointer(&buf[0])), readSize, uintptr(unsafe.Pointer(&read)))
		if r == 0 || read < 64 {
			outcome.partial = true
			continue
		}
		outcome.readRegions++
		if read < readSize {
			outcome.partial = true
		}
		chunk := buf[:read]
		if execish && rw {
			rwxRegions++
		}
		if opt.heuristic {
			// 非镜像可执行区的 PE 由完整性检查报告为 reflective_pe，这里不重复
			integrityCovers := opt.integrity && execish && mbi.Type != memTypeImage
			if !integrityCovers && len(chunk) >= 2 && chunk[0] == 'M' && chunk[1] == 'Z' && (execish || rw) {
				mzInPrivate++
				findings = append(findings, map[string]any{
					"type":     "mz_in_memory",
					"pid":      pid,
					"name":     name,
					"address":  fmt.Sprintf("0x%X", mbi.BaseAddress),
					"protect":  fmt.Sprintf("0x%X", prot),
					"severity": "high",
					"engine":   "heuristic",
					"summary":  fmt.Sprintf("内存 MZ 头: %s pid=%d @0x%X", name, pid, mbi.BaseAddress),
				})
			}
			low := strings.ToLower(string(chunk))
			for _, sig := range []string{"meterpreter", "reflective loader"} {
				if strings.Contains(low, sig) {
					suspiciousStr++
					findings = append(findings, map[string]any{
						"type": "suspicious_string", "pid": pid, "name": name, "sig": sig,
						"address": fmt.Sprintf("0x%X", mbi.BaseAddress), "severity": "high", "engine": "heuristic",
						"summary": fmt.Sprintf("内存可疑串[%s]: %s pid=%d", sig, name, pid),
					})
					break
				}
			}
		}
		if opt.rules {
			for _, hit := range matchJSONMemoryRules(chunk) {
				hit["pid"] = pid
				hit["name"] = name
				hit["address"] = fmt.Sprintf("0x%X", mbi.BaseAddress)
				if hit["summary"] == nil {
					hit["summary"] = fmt.Sprintf("内存规则[%s]: %s pid=%d", hit["rule_id"], name, pid)
				}
				findings = append(findings, hit)
			}
		}
		if opt.yara && yaraEngineOK {
			for _, hit := range scanYaraOnRegion(chunk, mbi.BaseAddress, pid, name) {
				findings = append(findings, hit)
			}
		}
		if len(findings) >= 30 {
			outcome.budgetLimited = true
			outcome.partial = true
			break
		}
	}
	if opt.heuristic && rwxRegions >= 3 {
		findings = append(findings, map[string]any{
			"type": "multi_rwx", "pid": pid, "name": name, "count": rwxRegions,
			"severity": "medium", "engine": "heuristic",
			"summary": fmt.Sprintf("多处 RWX 区: %s pid=%d count=%d", name, pid, rwxRegions),
		})
	}
	_ = filepath.Separator
	return findings
}
