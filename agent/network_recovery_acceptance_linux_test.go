//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

// Local-only TCP interruption with synthetic queued data. Does not alter the
// VM's network configuration, connect externally or use production state.
func TestLinuxLoopbackRecoveryAcceptance(t *testing.T) {
	if os.Getenv("EDR_NETWORK_RECOVERY_TEST") != "1" {
		t.Skip("opt-in loopback test")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	box := newOutbox(t.TempDir())
	defer box.st.close()
	if box.st.path == ":memory:" {
		t.Fatal("persistent state unavailable")
	}
	box.useV2.Store(true)
	api := newClient(Config{ServerURL: "http://" + addr, Token: "local-fixture"})
	api.setCredential("", "local-fixture")
	api.client.Timeout = 2 * time.Second
	for i := 0; i < 100; i++ {
		if !box.enqueue(outEvent, 90, map[string]any{"title": "synthetic outage fixture", "i": i}) {
			t.Fatal("enqueue failed")
		}
	}
	if n := box.flush(api); n != 0 || box.pending() != 100 || !box.netBackoff() {
		t.Fatalf("offline queue invalid: sent=%d pending=%d", n, box.pending())
	}
	var mu sync.Mutex
	seen := map[string]int{}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v2/events/batch" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Events []struct {
				UUID string `json:"uuid"`
			} `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid fixture", 400)
			return
		}
		acked := []string{}
		mu.Lock()
		for _, e := range req.Events {
			seen[e.UUID]++
			acked = append(acked, e.UUID)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "acked": acked})
	})}
	listener, err = net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	started := time.Now()
	deadline := started.Add(12 * time.Second)
	for box.pending() > 0 && time.Now().Before(deadline) {
		box.flush(api)
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if box.pending() != 0 || len(seen) != 100 {
		t.Fatalf("pending=%d unique=%d", box.pending(), len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatal(fmt.Sprintf("fixture %s count=%d", id, n))
		}
	}
	if box.dropped.Load() != 0 || box.rejected.Load() != 0 {
		t.Fatal("unexpected data loss")
	}
	t.Logf("offline_pending=100 recovered=%d unique=true pending=%d dropped=0 rejected=0 recovery_ms=%d", len(seen), box.pending(), time.Since(started).Milliseconds())
}
