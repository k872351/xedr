//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// Exercise the actual long-running agent loop with an isolated directory and
// a loopback-only acknowledgement sink; never return remote commands.
func TestLinuxAgentSoak(t *testing.T) {
	if os.Getenv("EDR_AGENT_SOAK") != "1" {
		t.Skip("opt-in test on an isolated VM")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run as an ordinary user")
	}
	duration := 3 * time.Minute
	if value := os.Getenv("EDR_AGENT_SOAK_DURATION"); value != "" {
		parsed, parseErr := time.ParseDuration(value)
		if parseErr != nil || parsed < 3*time.Minute || parsed > 72*time.Hour {
			t.Fatal("EDR_AGENT_SOAK_DURATION must be between 3m and 72h")
		}
		duration = parsed
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := map[string]any{"response_enabled": false, "timeline_process": false, "timeline_file": false, "timeline_network": false, "self_protect": false}
	policy["_sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, policySignMessage(1, policy)))
	applyIntegrationsPolicy(map[string]any{"integrations": map[string]any{
		"memory_scan": false, "fim": false, "rootcheck": false, "sca": false, "linux_journal": false,
		"persist": false, "evm": false, "device": false, "registry": false,
	}})
	var mu sync.Mutex
	var heartbeats, acknowledgements int
	var last time.Time
	var maxGap time.Duration
	var maxRSS, maxCPU, maxDepth float64
	var dropped, rejected float64
	var policyAppliedOK bool
	var policyLKGOK bool
	var progressAt time.Time
	modules := map[string]bool{}
	caps := []string{"ingest.v2", "inventory.delta", "inventory.parts.v1", "inventory.software.extended.v1", "inventory.software.paged.v1", "inventory.assets.paged.v1"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&body)
		}
		out := map[string]any{"ok": true}
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/agent/register":
			out["agent_id"], out["protocol_selected"], out["enabled_capabilities"] = "local-soak-fixture", 2, caps
		case "/api/agent/heartbeat":
			if !last.IsZero() {
				maxGap = max(maxGap, time.Since(last))
			}
			last = time.Now()
			heartbeats++
			out["heartbeat_sec"], out["commands"] = 3, []any{}
			out["policy_rev"] = 1
			out["policy"] = policy
			if h, ok := body["health"].(map[string]any); ok {
				if p, ok := h["policy"].(map[string]any); ok {
					applied := asInt(p["applied_rev"]) == 1
					policyAppliedOK = policyAppliedOK || applied
					policyLKGOK = applied && asInt(p["lkg_rev"]) == 1 && asString(p["status"]) == policyStatusOK
				}
				if f, ok := h["rss_mb"].(float64); ok {
					maxRSS = max(maxRSS, f)
				}
				if f, ok := h["cpu_pct"].(float64); ok {
					maxCPU = max(maxCPU, f)
				}
				if q, ok := h["outbox"].(map[string]any); ok {
					maxDepth = max(maxDepth, float64(asInt(q["depth"])))
					dropped = max(dropped, float64(asInt(q["dropped"])))
					rejected = max(rejected, float64(asInt(q["rejected"])))
				}
			}
			if progressAt.IsZero() {
				progressAt = time.Now()
			} else if time.Since(progressAt) >= 5*time.Minute {
				t.Logf("soak progress heartbeats=%d max_gap=%s max_cpu_pct=%.1f max_rss_mb=%.1f max_queue_depth=%.0f dropped=%.0f rejected=%.0f", heartbeats, maxGap.Round(time.Millisecond), maxCPU, maxRSS, maxDepth, dropped, rejected)
				progressAt = time.Now()
			}
		case "/api/agent/v2/events/batch":
			acked := []string{}
			if events, ok := body["events"].([]any); ok {
				for _, value := range events {
					e, ok := value.(map[string]any)
					if !ok {
						continue
					}
					id := asString(e["uuid"])
					if id == "" {
						continue
					}
					acked = append(acked, id)
					if p, ok := e["payload"].(map[string]any); ok && asString(p["module"]) != "" && stringsHasSnapshotKind(asString(e["kind"])) {
						modules[asString(p["module"])] = true
					}
				}
			}
			acknowledgements += len(acked)
			out["acked"] = acked
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	cfg := Config{ServerURL: srv.URL, Token: "local-test-only", PolicyPubKey: base64.StdEncoding.EncodeToString(pub), StateDir: t.TempDir(), Modules: []string{"sysinfo", "software", "service", "hotfix"}, Intervals: map[string]int{"sysinfo": 15, "software": 20, "service": 20, "hotfix": 30}}
	started := time.Now()
	err = runAgent(ctx, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("duration=%s heartbeats=%d max_gap=%s max_cpu_pct=%.1f max_rss_mb=%.1f max_queue_depth=%.0f dropped=%.0f rejected=%.0f acknowledged=%d snapshots=%v signed_policy_applied=%t policy_lkg=%t", time.Since(started).Round(time.Second), heartbeats, maxGap.Round(time.Millisecond), maxCPU, maxRSS, maxDepth, dropped, rejected, acknowledgements, modules, policyAppliedOK, policyLKGOK)
	minimumBeats := int(duration / (3 * time.Second) * 9 / 10)
	if time.Since(started) < duration-10*time.Second || heartbeats < minimumBeats || maxGap > 12*time.Second || maxRSS <= 0 || dropped != 0 || rejected != 0 || acknowledgements == 0 || !modules["software"] || !modules["sysinfo"] || !modules["service"] || !modules["hotfix"] || !policyAppliedOK || !policyLKGOK {
		t.Fatal("service soak criteria not met")
	}
}

func stringsHasSnapshotKind(kind string) bool {
	return kind == "snapshot" || kind == "snapshot_part" || kind == "snapshot_delta"
}
