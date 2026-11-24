//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A two-phase test for a disposable VM. Never point this at a real agent state directory.
func TestLinuxVMRecoveryAcceptance(t *testing.T) {
	phase := os.Getenv("EDR_RECOVERY_PHASE")
	if phase == "" {
		t.Skip("set EDR_RECOVERY_PHASE and use a fresh edr-recovery.* directory")
	}
	dir := os.Getenv("EDR_RECOVERY_TEST_DIR")
	if !filepath.IsAbs(dir) || len(filepath.Base(dir)) < len("edr-recovery.x") || filepath.Base(dir)[:len("edr-recovery.")] != "edr-recovery." {
		t.Fatal("expected an absolute, dedicated edr-recovery.* directory")
	}
	const count = 100
	switch phase {
	case "prepare":
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatal("recovery fixture directory must exist and be empty")
		}
		box := newOutbox(dir)
		if box.st.path == ":memory:" {
			t.Fatal("persistent database unavailable")
		}
		for i := 0; i < count; i++ {
			box.enqueueWithUUID(fmt.Sprintf("recovery-fixture-%03d", i), outEvent, 90, map[string]any{"title": "synthetic recovery fixture", "i": i})
		}
		if box.pending() != count {
			t.Fatalf("committed count=%d, expected=%d", box.pending(), count)
		}
		fmt.Printf("RECOVERY_READY dir=%s committed=%d (test database remains open)\n", dir, count)
		// Keep the test DB open while awaiting a controlled VM interruption.
		time.Sleep(10 * time.Minute)
		box.st.close()
		t.Fatal("no interruption observed")
	case "verify":
		if _, err := os.Stat(stateDBPath(dir)); err != nil {
			t.Fatal("prepared database missing: ", err)
		}
		box := newOutbox(dir)
		defer box.st.close()
		if box.st.path == ":memory:" || box.pending() != count {
			t.Fatalf("persistent recovery count=%d, expected=%d", box.pending(), count)
		}
		var integrity string
		if err := box.st.db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
			t.Fatalf("integrity=%s err=%v", integrity, err)
		}
		for i := 0; i < count; i++ {
			var found int
			if err := box.st.db.QueryRow("SELECT COUNT(*) FROM outbox WHERE uuid=?", fmt.Sprintf("recovery-fixture-%03d", i)).Scan(&found); err != nil || found != 1 {
				t.Fatalf("fixture %d recovered count=%d err=%v", i, found, err)
			}
		}
		t.Logf("recovered=%d/%d unique=true integrity=%s", box.pending(), count, integrity)
	default:
		t.Fatal("phase must be prepare or verify")
	}
}
