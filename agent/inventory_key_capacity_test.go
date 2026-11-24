package main

import (
	"fmt"
	"testing"
)

func TestInventoryDuplicateKeyCapacity(t *testing.T) {
	items := make([]any, pagedSoftwareLimit)
	for i := range items {
		items[i] = map[string]any{"name": "fixture", "version": "1", "arch": "test"}
	}
	// Include a natural key that resembles an automatically generated suffix.
	items[0] = map[string]any{"name": "fixture", "version": "1", "arch": "test#2"}
	p := newInventory(nil).planPaged("software", "fixture", items)
	keys := p.payload["keys"].([]string)
	if len(keys) != len(items) {
		t.Fatalf("keys=%d items=%d", len(keys), len(items))
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if key == "" || seen[key] || len(key) > 300 {
			t.Fatalf("invalid key %q", key)
		}
		seen[key] = true
	}
	if keys[2] != "fixture|1|test#3" || keys[len(keys)-1] != fmt.Sprintf("fixture|1|test#%d", len(items)) {
		t.Fatalf("unexpected suffix sequence: %s, %s", keys[2], keys[len(keys)-1])
	}
}
