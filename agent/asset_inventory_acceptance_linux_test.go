//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Read-only, opt-in acceptance. Report counts and integrity only, not row data.
func TestLinuxAssetInventoryAcceptance(t *testing.T) {
	if os.Getenv("EDR_REAL_INVENTORY_TEST") != "1" {
		t.Skip("opt-in test")
	}
	for _, item := range []struct {
		module  string
		collect func(int) ([]any, error)
	}{
		{"service", collectServicesLimited}, {"hotfix", collectHotfixLimited},
	} {
		t.Run(item.module, func(t *testing.T) {
			rows, err := item.collect(pagedSoftwareLimit + 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) == 0 || len(rows) > pagedSoftwareLimit {
				t.Fatalf("incomplete or empty fixture inventory: %d", len(rows))
			}
			if item.module == "hotfix" && len(rows) <= maxItems {
				t.Fatalf("test endpoint needs over %d patch history rows", maxItems)
			}
			p := newInventory(nil).plan(item.module, "local-fixture", rows, false)
			p.payload["paged_inventory"] = true
			encoded, err := json.Marshal(p.payload)
			if err != nil {
				t.Fatal(err)
			}
			parts, err := snapshotPartEvents(readyRow{uuid: "real-asset-" + item.module, payload: encoded})
			if err != nil {
				t.Fatal(err)
			}
			var combined strings.Builder
			for _, part := range parts {
				fragment := part["payload"].(map[string]any)["fragment"].(string)
				combined.WriteString(fragment)
			}
			sum := sha256.Sum256([]byte(combined.String()))
			if combined.String() != string(encoded) || parts[0]["payload"].(map[string]any)["checksum"] != hex.EncodeToString(sum[:]) {
				t.Fatal("reassembly mismatch")
			}
			var decoded struct {
				Items []json.RawMessage
				Keys  []string
			}
			if err := json.Unmarshal([]byte(combined.String()), &decoded); err != nil || len(decoded.Items) != len(rows) || len(decoded.Keys) != len(rows) {
				t.Fatal("item/key count mismatch")
			}
			seen := map[string]bool{}
			for _, key := range decoded.Keys {
				if key == "" || seen[key] {
					t.Fatal("invalid key")
				}
				seen[key] = true
			}
			t.Logf("uid=%d module=%s collected=%d parts=%d bytes=%d unique_keys=true checksum_ok=true", os.Geteuid(), item.module, len(rows), len(parts), len(encoded))
		})
	}
}
