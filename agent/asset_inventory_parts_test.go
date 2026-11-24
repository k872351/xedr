package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAssetInventoryPagedSnapshots(t *testing.T) {
	for _, module := range []string{"service", "hotfix", "user"} {
		t.Run(module, func(t *testing.T) {
			items := make([]any, 1501)
			for i := range items {
				items[i] = map[string]any{"name": fmt.Sprintf("fixture-%d", i), "kb": fmt.Sprintf("fixture-%d", i)}
			}
			p := newInventory(nil).plan(module, "synthetic", items, false)
			p.payload["paged_inventory"] = true
			raw, err := json.Marshal(p.payload)
			if err != nil {
				t.Fatal(err)
			}
			parts, err := snapshotPartEvents(readyRow{uuid: "fixture-" + module, payload: raw})
			if err != nil || len(parts) < 2 {
				t.Fatalf("staging: %v", err)
			}
			var joined strings.Builder
			for _, part := range parts {
				joined.WriteString(part["payload"].(map[string]any)["fragment"].(string))
			}
			if joined.String() != string(raw) {
				t.Fatal("reconstruction mismatch")
			}
		})
	}
}
