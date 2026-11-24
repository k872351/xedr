package main

import (
	"encoding/json"
	"strings"
	"time"
)

func processLiveEvents(events []map[string]any, cfg Config, responseEnabled bool, throttle *eventThrottle) []map[string]any {
	if len(events) == 0 {
		return events
	}
	out := make([]map[string]any, 0, len(events)+8)
	for _, ev := range events {
		if ev == nil {
			continue
		}
		recordSensorEventReceipt(ev)
		if !integrationEnabled("evm") {
			// skip evm only
		} else {
			recordComponentObservationIfChanged("evm", cStateHealthy, "event rule engine evaluated live telemetry")
			finishWork := beginComponentWork("evm")
			for _, hit := range evmEvaluate(ev) {
				out = append(out, hit)
			}
			finishWork()
		}
		if integrationEnabled("ptm") {
			recordComponentObservationIfChanged("ptm", cStateHealthy, "process threat monitor evaluated live telemetry")
			finishWork := beginComponentWork("ptm")
			for _, hit := range ptmObserve(ev) {
				out = append(out, hit)
			}
			finishWork()
		}
		if integrationEnabled("amsi") || integrationEnabled("api_etw") {
			etype := asString(ev["etype"])
			if integrationEnabled("amsi") && (etype == "api_amsi" || etype == "amsi_hit") {
				recordComponentObservationIfChanged("amsi", cStateHealthy, "AMSI telemetry reached the event pipeline")
			}
			if integrationEnabled("api_etw") && (etype == "api_call" || etype == "api_hit") {
				recordComponentObservationIfChanged("api_etw", cStateHealthy, "API ETW telemetry reached the event pipeline")
			}
			workComponent := "api_etw"
			if etype == "api_amsi" || etype == "amsi_hit" {
				workComponent = "amsi"
			}
			finishWork := beginComponentWork(workComponent)
			for _, hit := range apiRulesEvaluate(ev) {
				out = append(out, hit)
			}
			finishWork()
		}
		finishIOC := beginComponentWork("ioc")
		iocHit := matchEventIOC(ev)
		finishIOC()
		if iocHit != nil {
			out = append(out, iocHit)
		}
		if throttle != nil && !throttle.allow(ev, 2*time.Second) {
			captureFiltered(ev)
			continue
		}
		out = append(out, ev)
	}
	for _, ev := range out {
		runActiveResponse(ev, cfg, responseEnabled)
	}
	return out
}

func recordSensorEventReceipt(ev map[string]any) {
	detail, _ := ev["detail"].(map[string]any)
	source := strings.ToLower(asString(detail["source"]))
	etype := strings.ToLower(asString(ev["etype"]))
	switch {
	case source == "fim" || strings.HasPrefix(etype, "fim_"):
		recordComponentObservationIfChanged("fim", cStateHealthy, "file integrity event processed")
	case source == "persist_watch" || strings.HasPrefix(etype, "persist_"):
		recordComponentObservationIfChanged("persist", cStateHealthy, "persistence change event processed")
	case source == "device_poll" || strings.HasPrefix(etype, "device_"):
		recordComponentObservationIfChanged("device", cStateHealthy, "device change event processed")
	case source == "registry" || strings.HasPrefix(etype, "registry_"):
		recordComponentObservationIfChanged("registry", cStateHealthy, "registry event processed")
	case source == "winevent" || strings.HasPrefix(etype, "win_"):
		recordComponentObservationIfChanged("winevent", cStateHealthy, "Windows Event Log event processed")
	case source == "wmi" || strings.HasPrefix(etype, "process_create_wmi"):
		recordComponentObservationIfChanged("wmi_process", cStateHealthy, "WMI process event processed")
	case source == "etw" || source == "sysmon" || source == "kernel":
		recordComponentObservationIfChanged("etw", cStateHealthy, "ETW telemetry event processed")
	case etype == "memory_scan_hit" || etype == "memory_rule" || etype == "memory_yara":
		recordComponentObservationIfChanged("memory_scan", cStateHealthy, "memory scan result processed")
	}
}

func matchEventIOC(ev map[string]any) map[string]any {
	if agentIOCJSON == "" {
		return nil
	}
	var items []map[string]any
	if json.Unmarshal([]byte(agentIOCJSON), &items) != nil {
		return nil
	}
	blob := strings.ToLower(asString(ev["summary"]))
	d, _ := ev["detail"].(map[string]any)
	for _, k := range []string{"path", "command_line", "image", "sha256", "domain", "remote"} {
		blob += "\n" + strings.ToLower(asString(d[k]))
	}
	for _, it := range items {
		v := strings.ToLower(strings.TrimSpace(asString(it["value"])))
		if len(v) < 4 {
			continue
		}
		if strings.Contains(blob, v) {
			sev := asString(it["severity"])
			if sev == "" {
				sev = "high"
			}
			detail := map[string]any{
				"matched": v, "ioc_type": it["type"], "ioc_value": v,
				"etype": "ioc_hit", "source_etype": ev["etype"],
			}
			if d != nil {
				for _, k := range []string{
					"path", "image", "command_line", "sha256", "md5", "sha1",
					"pid", "ppid", "process_name", "name", "remote", "remote_ip",
					"domain", "query", "local", "proto", "entity_id", "user", "parent_name",
				} {
					if s := asString(d[k]); s != "" {
						detail[k] = d[k]
					}
				}
			}
			return map[string]any{
				"etype": "ioc_hit", "severity": sev, "summary": "IOC 命中: " + v,
				"detail": detail,
			}
		}
	}
	return nil
}
