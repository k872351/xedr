package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

type componentObservation struct {
	state   int
	message string
	at      time.Time
}

var componentObservations = struct {
	sync.RWMutex
	items map[string]componentObservation
}{items: make(map[string]componentObservation)}

// recordComponentObservation stores the latest sensor lifecycle transition.
func recordComponentObservation(id string, state int, message string) {
	id = strings.TrimSpace(strings.ToLower(id))
	if id == "" || (state != cStateStarting && state != cStateConfiguring && state != cStateHealthy && state != cStateDegraded && state != cStateFailed && state != cStateStopped) {
		return
	}
	componentObservations.Lock()
	componentObservations.items[id] = componentObservation{state: state, message: message, at: time.Now()}
	componentObservations.Unlock()
}

func recordComponentObservationIfChanged(id string, state int, message string) {
	id = strings.TrimSpace(strings.ToLower(id))
	if id == "" || (state != cStateStarting && state != cStateConfiguring && state != cStateHealthy && state != cStateDegraded && state != cStateFailed && state != cStateStopped) {
		return
	}
	componentObservations.Lock()
	previous, ok := componentObservations.items[id]
	now := time.Now()
	if !ok || previous.state != state || previous.message != message || now.Sub(previous.at) >= 30*time.Second {
		componentObservations.items[id] = componentObservation{state: state, message: message, at: now}
	}
	componentObservations.Unlock()
}

func latestComponentObservation(id string, now time.Time) (int, string, bool) {
	componentObservations.RLock()
	observation, ok := componentObservations.items[strings.ToLower(strings.TrimSpace(id))]
	componentObservations.RUnlock()
	maxAge := 2 * time.Minute
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "rootcheck":
		maxAge = 13 * time.Hour
	case "sca":
		maxAge = 25 * time.Hour
	}
	if !ok || now.Sub(observation.at) > maxAge || now.Before(observation.at) {
		return cStateUnknown, "runtime status unavailable or stale", false
	}
	return observation.state, observation.message, true
}

// cproto.State 对齐 Elastic diagnostics state.yaml
const (
	cStateStarting    = 0
	cStateConfiguring = 1
	cStateHealthy     = 2
	cStateDegraded    = 3
	cStateFailed      = 4
	cStateUnknown     = 5
)

func integrationComponentIDs() []string {
	ids := []string{
		"etw", "winevent", "wmi_process", "fim", "registry", "evm", "ptm",
		"amsi", "api_etw", "memory_scan", "rootcheck", "sca", "persist", "device",
	}
	if runtime.GOOS == "linux" {
		ids = append(ids, "linux_journal")
	}
	return ids
}

func buildComponentsExpected() []map[string]any {
	var out []map[string]any
	for _, id := range integrationComponentIDs() {
		if !componentSupportedOn(runtime.GOOS, id) || !integrationEnabled(id) {
			continue
		}
		out = append(out, map[string]any{
			"id": id,
			"units": map[string]any{
				"input-" + id: map[string]any{"enabled": true},
			},
		})
	}
	return out
}

func componentObservedAt(id string) string {
	componentObservations.RLock()
	observation, ok := componentObservations.items[strings.ToLower(strings.TrimSpace(id))]
	componentObservations.RUnlock()
	if !ok || observation.at.IsZero() {
		return ""
	}
	return observation.at.UTC().Format(time.RFC3339)
}

func componentRuntimeState(id string) (state int, msg string) {
	if !componentSupportedOn(runtime.GOOS, id) {
		return cStateStopped, "unsupported on this platform"
	}
	on := integrationEnabled(id)
	if !on {
		return cStateStopped, "disabled by policy"
	}
	if observedState, observedMessage, ok := latestComponentObservation(id, time.Now()); ok {
		return observedState, observedMessage
	}
	switch id {
	case "etw":
		if captureETWStatusFn != nil {
			mode, ok := captureETWStatusFn()
			if !ok && mode != "stopped" && mode != "" {
				return cStateDegraded, mode
			}
			if !ok {
				return cStateFailed, mode
			}
		} else {
			return cStateUnknown, "runtime status unavailable"
		}
		return cStateHealthy, ""
	case "wmi_process":
		if !integrationEnabled("wmi_process") {
			return cStateStopped, ""
		}
		return cStateUnknown, "runtime status unavailable"
	default:
		return cStateUnknown, "runtime status unavailable"
	}
}

func buildComponentsActual() []map[string]any {
	var out []map[string]any
	for _, id := range integrationComponentIDs() {
		if !componentSupportedOn(runtime.GOOS, id) {
			continue
		}
		st, msg := componentRuntimeState(id)
		if st == cStateStopped && !integrationEnabled(id) {
			continue
		}
		observedAt := componentObservedAt(id)
		resources := componentResourceSnapshot(id)
		unit := map[string]any{"state": st, "message": msg, "observed_at": observedAt, "resource_usage": resources}
		out = append(out, map[string]any{
			"id": id,
			"state": map[string]any{
				"state": st, "message": msg,
				"version_info":   map[string]any{"name": "forensic-process-runtime"},
				"observed_at":    observedAt,
				"resource_usage": resources,
			},
			"units": map[string]any{"input-" + id: unit},
		})
	}
	return out
}

func inventoryComponentHealthSnapshot(modules []string) []map[string]any {
	out := make([]map[string]any, 0, len(modules))
	seen := make(map[string]bool, len(modules))
	for _, module := range modules {
		id := strings.ToLower(strings.TrimSpace(module))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		state, message := "UNKNOWN", "initial collection has not run"
		componentID := "inventory_" + id
		componentObservations.RLock()
		observation, reported := componentObservations.items[componentID]
		componentObservations.RUnlock()
		maxAge := 10 * time.Minute
		switch id {
		case "network":
			maxAge = 3 * time.Minute
		case "process", "sysinfo", "startup":
			maxAge = 15 * time.Minute
		case "service", "task", "file", "groups", "shares", "usb":
			maxAge = 45 * time.Minute
		case "software", "driver", "netif", "firewall", "certs", "browser_ext":
			maxAge = 90 * time.Minute
		case "hotfix":
			maxAge = 4 * time.Hour
		}
		if reported && time.Since(observation.at) <= maxAge && !time.Now().Before(observation.at) {
			observed, detail := observation.state, observation.message
			message = detail
			switch observed {
			case cStateHealthy:
				state = "OK"
			case cStateDegraded:
				state = "DEGRADED"
			case cStateFailed:
				state = "FAILED"
			case cStateStopped:
				state = "DISABLED"
			case cStateStarting, cStateConfiguring:
				state = "STARTING"
			}
		}
		out = append(out, map[string]any{
			"name": componentID, "state": state, "message": message,
			"observed_at":    componentObservedAt(componentID),
			"resource_usage": componentResourceSnapshot(componentID),
		})
	}
	return out
}

func buildStateYAML(pm *policyManager, cfg Config) map[string]any {
	agentSt := cStateHealthy
	msg := ""
	if pm != nil {
		switch pm.state()["status"] {
		case policyStatusProb:
			agentSt, msg = cStateConfiguring, "policy probation"
		case policyStatusReject:
			agentSt, msg = cStateFailed, "policy rejected"
		case policyStatusRB:
			agentSt, msg = cStateDegraded, "policy rolled back"
		}
	}
	comps := buildComponentsActual()
	ud := upgradeDetailsSnapshot(cfg)
	root := map[string]any{
		"state":         agentSt,
		"message":       msg,
		"fleet_state":   fleetSnapshot(pm)["fleet_state"],
		"fleet_message": fleetSnapshot(pm)["fleet_message"],
		"log_level":     "info",
		"components":    comps,
	}
	if ud != nil {
		root["upgrade_details"] = ud
	}
	return root
}

func componentsYAML(name string, comps []map[string]any) string {
	b, _ := json.MarshalIndent(comps, "", "  ")
	return fmt.Sprintf("# %s\n%s\n", name, string(b))
}

func mapToSimpleYAML(m map[string]any) string {
	var b strings.Builder
	writeYAMLMap(&b, m, 0)
	return b.String()
}

func writeYAMLMap(b *strings.Builder, m map[string]any, indent int) {
	pad := strings.Repeat("  ", indent)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		v := m[k]
		switch t := v.(type) {
		case map[string]any:
			b.WriteString(pad + k + ":\n")
			writeYAMLMap(b, t, indent+1)
		case []map[string]any:
			b.WriteString(pad + k + ":\n")
			for _, item := range t {
				b.WriteString(pad + "  -\n")
				writeYAMLMap(b, item, indent+2)
			}
		case []any:
			b.WriteString(pad + k + ":\n")
			for _, item := range t {
				if im, ok := item.(map[string]any); ok {
					b.WriteString(pad + "  -\n")
					writeYAMLMap(b, im, indent+2)
				}
			}
		default:
			b.WriteString(fmt.Sprintf("%s%s: %v\n", pad, k, yamlScalar(v)))
		}
	}
}

func yamlScalar(v any) string {
	switch t := v.(type) {
	case string:
		if strings.ContainsAny(t, ":#{}[]\n") {
			return fmt.Sprintf("%q", t)
		}
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", t)
	}
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

const cStateStopped = 6
