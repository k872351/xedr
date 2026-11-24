//go:build !windows

package main

import (
	"runtime"
	"time"
)

func probeCaptureEnvironment() map[string]any {
	return map[string]any{
		"etw_session_ok": false, "audit_4688_enabled": false, "sysmon_present": false,
		"platform": "non-windows",
	}
}

func captureStatusSnapshot() map[string]any {
	m := probeCaptureEnvironment()
	m["entities_rev"] = procEntities.revision()
	return m
}

func componentHealthSnapshot() []map[string]any {
	ids := integrationComponentIDs()
	out := make([]map[string]any, 0, len(ids))
	unsupported := map[string]string{
		"etw":         "ETW is Windows-only",
		"winevent":    "Windows Event Log sensor is unavailable on this platform",
		"wmi_process": "WMI process tracing is Windows-only",
		"registry":    "Windows Registry monitoring is unavailable on this platform",
		"amsi":        "AMSI is Windows-only",
		"api_etw":     "API ETW tracing is Windows-only",
		"device":      "device event sensor is unavailable on this platform",
		"persist":     "persistence change sensor is unavailable on this platform",
	}
	if runtime.GOOS != "linux" {
		unsupported["rootcheck"] = "rootcheck sensor is currently implemented for Windows and Linux"
		unsupported["sca"] = "security configuration assessment is currently implemented for Windows and Linux"
		unsupported["memory_scan"] = "memory scanning is currently implemented for Windows and Linux"
	}
	for _, id := range ids {
		state, message := "UNKNOWN", "platform runtime health reporting is unavailable"
		if reason := unsupported[id]; reason != "" {
			state, message = "UNSUPPORTED", reason
		} else if id == "fim" && runtime.GOOS != "linux" {
			state, message = "UNSUPPORTED", "file integrity sensor is currently implemented for Windows and Linux"
		} else if !integrationEnabled(id) {
			state, message = "DISABLED", "disabled by policy"
		} else if observed, detail, ok := latestComponentObservation(id, time.Now()); ok {
			message = detail
			switch observed {
			case cStateStarting, cStateConfiguring:
				state = "STARTING"
			case cStateHealthy:
				state = "OK"
			case cStateDegraded:
				state = "DEGRADED"
			case cStateFailed:
				state = "FAILED"
			case cStateStopped:
				state = "DISABLED"
			}
		}
		out = append(out, map[string]any{"name": id, "state": state, "message": message, "observed_at": componentObservedAt(id), "resource_usage": componentResourceSnapshot(id)})
	}
	return out
}
