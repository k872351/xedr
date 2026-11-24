package main

import (
	"runtime"
	"strings"
	"sync"
	"time"
)

const componentAllocationSampleRate = 64

type componentResourceTotals struct {
	calls        uint64
	activeNanos  uint64
	allocBytes   uint64
	lastActivity time.Time
}

var componentResourceUsage = struct {
	sync.RWMutex
	items map[string]componentResourceTotals
}{items: make(map[string]componentResourceTotals)}

// beginComponentWork records synchronous processing time and samples process-wide
// allocations occasionally. Allocation attribution is an estimate, not retained heap.
func beginComponentWork(id string) func() {
	id = strings.ToLower(strings.TrimSpace(id))
	componentResourceUsage.Lock()
	total := componentResourceUsage.items[id]
	total.calls++
	sample := total.calls%componentAllocationSampleRate == 1
	sampleWeight := total.calls
	if sampleWeight > componentAllocationSampleRate {
		sampleWeight = componentAllocationSampleRate
	}
	componentResourceUsage.items[id] = total
	componentResourceUsage.Unlock()

	var before runtime.MemStats
	if sample {
		runtime.ReadMemStats(&before)
	}
	started := time.Now()
	return func() {
		elapsed := time.Since(started)
		var allocated uint64
		if sample {
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			if after.TotalAlloc >= before.TotalAlloc {
				allocated = (after.TotalAlloc - before.TotalAlloc) * sampleWeight
			}
		}
		componentResourceUsage.Lock()
		total := componentResourceUsage.items[id]
		total.activeNanos += uint64(elapsed)
		total.allocBytes += allocated
		total.lastActivity = time.Now()
		componentResourceUsage.items[id] = total
		componentResourceUsage.Unlock()
	}
}

func componentResourceSnapshot(id string) map[string]any {
	componentResourceUsage.RLock()
	total := componentResourceUsage.items[strings.ToLower(strings.TrimSpace(id))]
	componentResourceUsage.RUnlock()
	lastActivity := ""
	if !total.lastActivity.IsZero() {
		lastActivity = total.lastActivity.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"calls_total":              total.calls,
		"active_ms_total":          float64(total.activeNanos) / float64(time.Millisecond),
		"estimated_alloc_mb_total": float64(total.allocBytes) / (1 << 20),
		"last_activity_at":         lastActivity,
		"allocation_sample_rate":   componentAllocationSampleRate,
		"cpu_attribution":          "unavailable",
		"memory_metric":            "sampled_allocations_estimate",
	}
}
