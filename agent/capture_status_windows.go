//go:build windows

package main

import (
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

var (
	captureProbeMu sync.Mutex
	captureProbeAt time.Time
	captureProbe   map[string]any
)

func probeCaptureEnvironment() map[string]any {
	captureProbeMu.Lock()
	defer captureProbeMu.Unlock()
	if captureProbe != nil && time.Since(captureProbeAt) < 60*time.Second {
		return captureProbe
	}
	out := map[string]any{
		"audit_4688_enabled": probeAudit4688(),
		"sysmon_present":     probeSysmonLogQuick(),
		"sysmon":             sysmonStatusSnapshot(),
		"etw_session_ok":     false,
	}
	if captureETWStatusFn != nil {
		mode, ok := captureETWStatusFn()
		out["etw_session_ok"] = ok
		out["etw_mode"] = mode
	}
	captureProbe, captureProbeAt = out, time.Now()
	return out
}

func probeAudit4688() bool {
	ps := `$p='Audit: Process Creation'; try { $g=Get-WinEvent -ListLog Security -ErrorAction Stop; $a=$g.IsEnabled } catch { $false }; if(-not $a){$false}else{ try { $c=auditpol /get /subcategory:$p 2>$null | Out-String; $c -match 'Success|成功' } catch { $false } }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(b)), "success") || strings.Contains(string(b), "成功")
}

func probeSysmonLog() bool {
	ps := `try { $null=Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop; 'yes' } catch { 'no' }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	b, err := cmd.CombinedOutput()
	return err == nil && strings.TrimSpace(string(b)) == "yes"
}

func captureStatusSnapshot() map[string]any {
	m := probeCaptureEnvironment()
	m["entities_rev"] = procEntities.revision()
	return m
}

func componentHealthSnapshot() []map[string]any {
	var out []map[string]any
	addState := func(name string, st string, msg string) {
		switch st {
		case "STARTING":
			recordComponentObservation(name, cStateStarting, msg)
		case "OK":
			recordComponentObservation(name, cStateHealthy, msg)
		case "DEGRADED":
			recordComponentObservation(name, cStateDegraded, msg)
		case "FAILED":
			recordComponentObservation(name, cStateFailed, msg)
		}
		out = append(out, map[string]any{"name": name, "state": st, "message": msg, "observed_at": componentObservedAt(name), "resource_usage": componentResourceSnapshot(name)})
	}
	add := func(name string, on bool, msg string) {
		if !on {
			if msg == "" {
				msg = "disabled or not installed"
			}
			addState(name, "DISABLED", msg)
			return
		}
		state, detail, ok := latestComponentObservation(name, time.Now())
		if !ok {
			if msg == "" {
				msg = "enabled; awaiting runtime observation"
			}
			addState(name, "UNKNOWN", msg)
			return
		}
		stateName := "UNKNOWN"
		switch state {
		case cStateStarting, cStateConfiguring:
			stateName = "STARTING"
		case cStateHealthy:
			stateName = "OK"
		case cStateDegraded:
			stateName = "DEGRADED"
		case cStateFailed:
			stateName = "FAILED"
		case cStateStopped:
			stateName = "DISABLED"
		}
		addState(name, stateName, detail)
	}
	etwOn, etwMsg := integrationEnabled("etw"), ""
	etwState := configuredComponentState(etwOn)
	if captureETWStatusFn != nil {
		m, ok := captureETWStatusFn()
		etwState = observedComponentState(etwOn, true, ok, m == "starting")
		if m == "starting" {
			etwMsg = "启动中"
		} else if !ok && m != "stopped" && m != "" {
			etwMsg = m
		}
	}
	addState("etw", etwState, etwMsg)
	if !integrationEnabled("winevent") {
		addState("winevent", "DISABLED", "disabled by policy")
	} else if globalWinEvent == nil {
		addState("winevent", "UNKNOWN", "Event Log watcher has not been initialized")
	} else {
		state, message := globalWinEvent.status()
		stateName := "UNKNOWN"
		switch state {
		case cStateStarting, cStateConfiguring:
			stateName = "STARTING"
		case cStateHealthy:
			stateName = "OK"
		case cStateDegraded:
			stateName = "DEGRADED"
		case cStateFailed:
			stateName = "FAILED"
		case cStateStopped:
			stateName = "DISABLED"
		}
		addState("winevent", stateName, message)
	}
	add("evm", integrationEnabled("evm"), "")
	add("ptm", integrationEnabled("ptm"), "")
	add("memory_scan", integrationEnabled("memory_scan"), "用户态 YARA + 内存完整性巡检（注入线程/反射 PE/ETW·AMSI 补丁）")
	add("wmi_process", integrationEnabled("wmi_process"), "")
	add("amsi", integrationEnabled("amsi"), "")
	add("api_etw", integrationEnabled("api_etw"), "")
	add("fim", integrationEnabled("fim"), "")
	add("registry", integrationEnabled("registry"), "")
	sm := sysmonStatusSnapshot()
	smOn, _ := sm["present"].(bool)
	smMsg := "未检测到 Sysmon"
	if act, _ := sm["action"].(string); act != "" {
		smMsg = act
	}
	if errS, _ := sm["error"].(string); errS != "" {
		smMsg = errS
	} else if smOn {
		smMsg = "Microsoft-Windows-Sysmon/Operational"
	}
	add("sysmon", smOn, smMsg)
	// FaKmon 内核驱动：可选实验室组件（默认未安装）；有则上报 kernel_* 事件
	kernOn, kernMsg := false, "未加载（默认用户态采集；可选安装 fakmon.sys）"
	if h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(`\\.\FaKmon`),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING, 0, 0,
	); err == nil {
		_ = windows.CloseHandle(h)
		kernOn, kernMsg = true, "FaKmon 已加载（进程/注入/LSASS/自保护）"
	}
	add("kernel_driver", kernOn, kernMsg)
	dpOn, dpMsg := dpDrv.state()
	add("dp_driver", dpOn, "DataProtector 驱动: "+dpMsg)
	if blocked, msg := evaluatePreventions("memory_scan"); blocked {
		add("memory_scan", false, msg)
	}
	if blocked, msg := evaluatePreventions("wmi_process"); blocked {
		add("wmi_process", false, msg)
	}
	return out
}
