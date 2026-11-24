package main

import (
	"runtime"
	"sync"
	"time"
)

var inventoryQuality = struct {
	sync.Mutex
	rows map[string]map[string]any
}{rows: map[string]map[string]any{}}

var loopQuality = struct {
	sync.Mutex
	rows map[string]map[string]uint64
}{rows: map[string]map[string]uint64{}}

func recordLoopDuration(stage string, elapsed, budget time.Duration) {
	ms := uint64(max(elapsed.Milliseconds(), 0))
	loopQuality.Lock()
	defer loopQuality.Unlock()
	row := loopQuality.rows[stage]
	if row == nil {
		row = map[string]uint64{}
		loopQuality.rows[stage] = row
	}
	row["samples"]++
	row["last_ms"] = ms
	row["max_ms"] = max(row["max_ms"], ms)
	row["budget_ms"] = uint64(max(budget.Milliseconds(), 0))
	if elapsed > budget {
		row["over_budget"]++
	}
}

func loopQualitySnapshot() map[string]map[string]uint64 {
	loopQuality.Lock()
	defer loopQuality.Unlock()
	out := make(map[string]map[string]uint64, len(loopQuality.rows))
	for stage, row := range loopQuality.rows {
		copyRow := make(map[string]uint64, len(row))
		for key, value := range row {
			copyRow[key] = value
		}
		out[stage] = copyRow
	}
	return out
}

var memoryQuality = struct {
	sync.Mutex
	row map[string]any
}{}

func recordMemoryQuality(result map[string]any) {
	row := map[string]any{"observed_at": time.Now().Format(time.RFC3339)}
	for _, key := range []string{"scan_status", "attempted", "scanned", "open_failed", "access_denied", "no_readable_data", "partial", "budget_limited", "scan_limit_reached", "finding_count", "pid_fallback"} {
		if value, ok := result[key]; ok {
			row[key] = value
		}
	}
	memoryQuality.Lock()
	memoryQuality.row = row
	memoryQuality.Unlock()
}

func memoryQualitySnapshot() map[string]any {
	memoryQuality.Lock()
	defer memoryQuality.Unlock()
	row := map[string]any{}
	for key, value := range memoryQuality.row {
		row[key] = value
	}
	return row
}

func inventoryCollectionLimit(module string) int {
	if runtime.GOOS == "linux" && module == "file" {
		return 200
	}
	return maxItems
}

func recordInventoryQuality(module string, returned int, err error) bool {
	limit := inventoryCollectionLimit(module)
	return recordInventoryQualityWithLimit(module, returned, limit, returned >= limit, err)
}

const extendedSoftwareLimit = 1000
const pagedSoftwareLimit = 4000

// The software collector reads one extra record to distinguish a complete
// exact-cap result from a partial collection. No other sensor changes scope.
func boundInventoryProbe(items []any, limit int) ([]any, bool) {
	if len(items) > limit {
		return items[:limit], true
	}
	return items, false
}

func recordInventoryQualityWithLimit(module string, returned, limit int, incomplete bool, err error) bool {
	possible := err == nil && incomplete
	status := "ok"
	if err != nil {
		status = "failed"
	} else if possible {
		status = "possible_truncation"
	} else if returned == 0 {
		status = "empty"
	}
	inventoryQuality.Lock()
	defer inventoryQuality.Unlock()
	row := inventoryQuality.rows[module]
	if row == nil {
		row = map[string]any{}
	}
	row["platform"], row["scope"] = runtime.GOOS, "configured_inventory"
	row["status"], row["returned"], row["limit"] = status, returned, limit
	row["possible_truncation"] = possible
	row["observed_at"] = time.Now().Format(time.RFC3339)
	row["error"] = ""
	if err != nil {
		row["error"] = err.Error()
	}
	if status == "ok" || status == "empty" {
		row["last_success_at"] = row["observed_at"]
	}
	inventoryQuality.rows[module] = row
	return possible
}

func inventoryQualitySnapshot() map[string]map[string]any {
	inventoryQuality.Lock()
	defer inventoryQuality.Unlock()
	out := make(map[string]map[string]any, len(inventoryQuality.rows))
	for module, row := range inventoryQuality.rows {
		copyRow := make(map[string]any, len(row))
		for key, value := range row {
			copyRow[key] = value
		}
		out[module] = copyRow
	}
	return out
}

var captureQuality = struct {
	sync.Mutex
	rows map[string]map[string]uint64
}{rows: map[string]map[string]uint64{}}

const qualitySourceKey = "_capture_quality_source"
const bookmarkAckKey = "_bookmark_ack"

func captureAdd(source, stage string, n int) {
	if source == "" || n <= 0 {
		return
	}
	captureQuality.Lock()
	defer captureQuality.Unlock()
	if captureQuality.rows[source] == nil {
		captureQuality.rows[source] = map[string]uint64{}
	}
	captureQuality.rows[source][stage] += uint64(n)
}

func captureTag(ev map[string]any, source string) {
	if ev != nil {
		ev[qualitySourceKey] = source
	}
}

func captureFiltered(ev map[string]any) {
	source, _ := ev[qualitySourceKey].(string)
	captureAdd(source, "filtered", 1)
	confirmBookmark(ev)
}

func confirmBookmark(ev map[string]any) {
	if ack, ok := ev[bookmarkAckKey].(func()); ok {
		delete(ev, bookmarkAckKey)
		ack()
	}
}

func captureQualitySnapshot() map[string]map[string]uint64 {
	captureQuality.Lock()
	defer captureQuality.Unlock()
	out := make(map[string]map[string]uint64, len(captureQuality.rows))
	for source, row := range captureQuality.rows {
		copyRow := make(map[string]uint64, len(row))
		for stage, count := range row {
			copyRow[stage] = count
		}
		out[source] = copyRow
	}
	return out
}

// A bookmark can advance only over consecutive positively acknowledged entries.
// A gap freezes progress rather than silently skipping data.
type bookmarkProgress struct {
	mu        sync.Mutex
	next      uint64
	pending   map[uint64]string
	confirmed string
	blocked   bool
}

func (p *bookmarkProgress) block() {
	p.mu.Lock()
	p.blocked = true
	p.pending = nil
	p.mu.Unlock()
}

func (p *bookmarkProgress) acknowledge(seq uint64, xml string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.blocked || seq <= p.next || xml == "" {
		return
	}
	if p.pending == nil {
		p.pending = map[uint64]string{}
	}
	p.pending[seq] = xml
	if len(p.pending) > 2048 {
		p.blocked = true
		p.pending = nil
		captureAdd("winevent_native", "bookmark_gap", 1)
		return
	}
	for {
		next, ok := p.pending[p.next+1]
		if !ok {
			break
		}
		p.next++
		p.confirmed = next
		delete(p.pending, p.next)
	}
}

func (p *bookmarkProgress) snapshot() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.confirmed
}

var rootHealth = struct {
	sync.Mutex
	rows map[string]map[string]any
}{rows: map[string]map[string]any{}}

func resetRootHealth() {
	rootHealth.Lock()
	rootHealth.rows = map[string]map[string]any{}
	rootHealth.Unlock()
}

func recordRootHealth(path, field, state string) {
	rootHealth.Lock()
	defer rootHealth.Unlock()
	row := rootHealth.rows[path]
	if row == nil {
		row = map[string]any{}
		rootHealth.rows[path] = row
	}
	row[field] = state
	row[field+"_at"] = time.Now().Format(time.RFC3339)
}

func rootHealthSnapshot() map[string]map[string]any {
	rootHealth.Lock()
	defer rootHealth.Unlock()
	out := make(map[string]map[string]any, len(rootHealth.rows))
	for path, row := range rootHealth.rows {
		copyRow := make(map[string]any, len(row))
		for key, value := range row {
			copyRow[key] = value
		}
		out[path] = copyRow
	}
	return out
}
