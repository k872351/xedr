package main

import (
	"fmt"
	"testing"
	"time"
)

func TestPagedInventoryRefresh(t *testing.T) {
	for _, module := range []string{"software", "service", "hotfix", "user"} {
		t.Run(module, func(t *testing.T) {
			iv := newInventory(nil)
			now := time.Now()
			iv.now = func() time.Time { return now }
			items := make([]any, 1501)
			for i := range items {
				items[i] = map[string]any{"name": fmt.Sprintf("fixture-%d", i), "kb": fmt.Sprintf("fixture-%d", i), "version": "1"}
			}
			first := iv.planPaged(module, "fixture", items)
			if first.skip || first.kind != outSnapshot || first.payload["generation"] != int64(1) {
				t.Fatal("first full not published")
			}
			for i := 0; i < 20; i++ {
				now = now.Add(time.Second)
				if !iv.planPaged(module, "fixture", items).skip {
					t.Fatal("unchanged full repeated")
				}
			}
			items[0].(map[string]any)["version"] = "2"
			changed := iv.planPaged(module, "fixture", items)
			if changed.skip || changed.kind != outSnapshot || changed.payload["generation"] != int64(2) {
				t.Fatal("change did not send full")
			}
			iv.invalidate(module, 2)
			retry := iv.planPaged(module, "fixture", items)
			if retry.skip || retry.kind != outSnapshot || retry.payload["generation"] != int64(3) {
				t.Fatal("failed transfer not retried")
			}
			now = now.Add(invTouchEvery)
			refresh := iv.planPaged(module, "fixture", items)
			if refresh.skip || refresh.kind != outSnapshot || refresh.payload["generation"] != int64(4) {
				t.Fatal("periodic refresh missing")
			}
		})
	}
}
