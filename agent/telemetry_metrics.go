package main

import (
	"strings"
	"sync"
	"sync/atomic"
)

// 遥测来源计数（对齐 Elastic：ETW input + Winlog 并存时的可观测性）。
var (
	teleEventsETW      atomic.Uint64
	teleEventsWinevent atomic.Uint64
	teleEventsSysmon   atomic.Uint64
	teleEventsOther    atomic.Uint64
	teleProcWithCmd    atomic.Uint64
	teleProcNoCmd      atomic.Uint64
	// AG-02: stage loss counters (enqueue / buffer / send)
	teleDropEnqueue atomic.Uint64
	teleDropBuffer  atomic.Uint64
	teleDropSend    atomic.Uint64
)

func teleIncDrop(stage string, n uint64) {
	if n == 0 {
		return
	}
	switch stage {
	case "enqueue", "queue_full", "rejected":
		teleDropEnqueue.Add(n)
	case "buffer", "buffer_dropped":
		teleDropBuffer.Add(n)
	case "send", "dropped":
		teleDropSend.Add(n)
	default:
		teleDropBuffer.Add(n)
	}
}

func teleIncSource(ev map[string]any) {
	if ev == nil {
		return
	}
	src := asString(ev["source"])
	if src == "" {
		if d, _ := ev["detail"].(map[string]any); d != nil {
			src = asString(d["source"])
		}
	}
	et := asString(ev["etype"])
	switch {
	case src == "winevent" || et == "winevent_status":
		teleEventsWinevent.Add(1)
	case src == "sysmon" || src == "security_4688" || src == "defender" || strings.Contains(strings.ToLower(et), "sysmon"):
		teleEventsSysmon.Add(1)
	case src == "etw" || strings.Contains(strings.ToLower(et), "etw"):
		teleEventsETW.Add(1)
	case src == "log_tail" || et == "log_tail_line":
		teleEventsOther.Add(1)
	default:
		teleEventsOther.Add(1)
	}
	teleTrackCmdQuality(ev)
}

func teleTrackCmdQuality(ev map[string]any) {
	et := asString(ev["etype"])
	if et != "process_create_etw" && et != "process_create_live" && et != "process_create" {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		return
	}
	if strings.TrimSpace(asString(d["command_line"])) != "" {
		teleProcWithCmd.Add(1)
	} else {
		teleProcNoCmd.Add(1)
	}
}

func telemetryMetricsSnapshot() map[string]any {
	withCmd := teleProcWithCmd.Load()
	noCmd := teleProcNoCmd.Load()
	total := withCmd + noCmd
	fillPct := 0.0
	if total > 0 {
		fillPct = float64(withCmd) * 100 / float64(total)
	}
	enq := teleDropEnqueue.Load()
	buf := teleDropBuffer.Load()
	send := teleDropSend.Load()
	return map[string]any{
		"events_etw":        teleEventsETW.Load(),
		"events_winevent":   teleEventsWinevent.Load(),
		"events_sysmon":     teleEventsSysmon.Load(),
		"events_other":      teleEventsOther.Load(),
		"proc_cmd_fill_pct": round1(fillPct),
		"proc_with_cmd":     withCmd,
		"proc_no_cmd":       noCmd,
		// AG-02 stage loss summary
		"drop_enqueue": enq,
		"drop_buffer":  buf,
		"drop_send":    send,
		"drop_total":   enq + buf + send,
	}
}

var sensorPipeMu sync.RWMutex
var sensorPipeline = map[string]any{
	"primary": "etw_native", "secondary": "winevent", "fallback": "",
}

func setSensorPipeline(primary, secondary, fallback string) {
	sensorPipeMu.Lock()
	defer sensorPipeMu.Unlock()
	if primary != "" {
		sensorPipeline["primary"] = primary
	}
	if secondary != "" {
		sensorPipeline["secondary"] = secondary
	}
	sensorPipeline["fallback"] = fallback
}

func sensorPipelineSnapshot() map[string]any {
	sensorPipeMu.RLock()
	defer sensorPipeMu.RUnlock()
	out := map[string]any{}
	for k, v := range sensorPipeline {
		out[k] = v
	}
	return out
}
