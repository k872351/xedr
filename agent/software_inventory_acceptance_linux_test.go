//go:build linux

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Opt-in, read-only acceptance test. No server, credentials or agent service needed.
func TestLinuxInstalledSoftwareAcceptance(t *testing.T) {
	if os.Getenv("EDR_REAL_INVENTORY_TEST") != "1" {
		t.Skip("set EDR_REAL_INVENTORY_TEST=1 on a test endpoint")
	}
	raw, err := exec.Command("dpkg-query", "-W", "-f=${db:Status-Status}\\n").Output()
	if err != nil {
		t.Fatal(err)
	}
	expected := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "installed" {
			expected++
		}
	}
	if expected <= extendedSoftwareLimit || expected > pagedSoftwareLimit {
		t.Fatalf("installed count %d outside acceptance range %d..%d", expected, extendedSoftwareLimit+1, pagedSoftwareLimit)
	}
	items, err := collectSoftwareLimited(pagedSoftwareLimit + 1)
	if err != nil || len(items) != expected {
		t.Fatalf("collector count=%d, expected=%d, err=%v", len(items), expected, err)
	}
	p := newInventory(nil).plan("software", "synthetic-acceptance", items, false)
	p.payload["paged_software"] = true
	encoded, err := json.Marshal(p.payload)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := snapshotPartEvents(readyRow{uuid: "real-inventory-acceptance", payload: encoded})
	if err != nil {
		t.Fatal(err)
	}
	var joined strings.Builder
	for _, part := range parts {
		joined.WriteString(part["payload"].(map[string]any)["fragment"].(string))
	}
	if joined.String() != string(encoded) {
		t.Fatal("fragment reconstruction mismatch")
	}
	t.Logf("uid=%d expected=%d collected=%d parts=%d bytes=%d reconstructed=true", os.Geteuid(), expected, len(items), len(parts), len(encoded))
}
