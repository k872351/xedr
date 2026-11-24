package main

import (
	"errors"
	"testing"
	"time"
)

func TestLoopQualityRecordsDelayWithoutChangingScheduling(t *testing.T) {
	const stage = "synthetic-loop"
	recordLoopDuration(stage, 100*time.Millisecond, time.Second)
	recordLoopDuration(stage, 2*time.Second, time.Second)
	row := loopQualitySnapshot()[stage]
	if row["samples"] != 2 || row["max_ms"] != 2000 || row["over_budget"] != 1 {
		t.Fatalf("unexpected timing data: %v", row)
	}
}

func TestCaptureQualitySeparatesDropsAndFilters(t *testing.T) {
	const source = "synthetic-quality"
	captureAdd(source, "received", 4)
	captureAdd(source, "buffer_dropped", 2)
	ev := map[string]any{}
	captureTag(ev, source)
	captureFiltered(ev)
	captureAdd(source, "persisted", 1)
	row := captureQualitySnapshot()[source]
	if row["received"] != 4 || row["buffer_dropped"] != 2 || row["filtered"] != 1 || row["persisted"] != 1 {
		t.Fatalf("bad quality row: %v", row)
	}
	row["received"] = 0
	if captureQualitySnapshot()[source]["received"] != 4 {
		t.Fatal("snapshot must not alias counters")
	}
}

func TestBookmarkProgressRequiresContiguousAcknowledgements(t *testing.T) {
	p := &bookmarkProgress{}
	p.acknowledge(2, "second")
	if p.snapshot() != "" {
		t.Fatal("gap advanced bookmark")
	}
	p.acknowledge(1, "first")
	if p.snapshot() != "second" {
		t.Fatal("contiguous acknowledgement did not advance")
	}
	p.block()
	p.acknowledge(3, "third")
	if p.snapshot() != "second" {
		t.Fatal("blocked cursor advanced")
	}
}

func TestBookmarkProgressBoundedGap(t *testing.T) {
	p := &bookmarkProgress{}
	p.acknowledge(1, "first")
	for seq := uint64(3); seq <= 2051; seq++ {
		p.acknowledge(seq, "later")
	}
	p.acknowledge(2, "late missing entry")
	if !p.blocked || p.snapshot() != "first" || len(p.pending) != 0 {
		t.Fatal("unresolved gap must freeze the cursor and bound memory")
	}
}

func TestBookmarkConfirmationRequiresSuccessfulDiskEnqueue(t *testing.T) {
	box := newOutbox(t.TempDir())
	if box.st.path == ":memory:" {
		t.Fatal("expected disk-backed queue")
	}
	var synchronous int
	if err := box.st.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		t.Fatalf("expected SQLite synchronous=FULL, got %d (%v)", synchronous, err)
	}
	p := &bookmarkProgress{}
	if !box.enqueue(outTimeline, 50, map[string]any{"events": []any{map[string]any{"summary": "synthetic"}}}) {
		t.Fatal("expected successful enqueue")
	}
	p.acknowledge(1, "first")
	box.st.close()
	if box.enqueue(outTimeline, 50, map[string]any{"events": []any{map[string]any{"summary": "synthetic second"}}}) {
		p.acknowledge(2, "second")
		t.Fatal("closed queue unexpectedly accepted data")
	}
	if p.snapshot() != "first" {
		t.Fatal("failed persistence advanced cursor")
	}
}

func TestInventoryQualityMarksPossibleTruncation(t *testing.T) {
	if !recordInventoryQuality("synthetic", maxItems, nil) {
		t.Fatal("exact limit must be marked possibly incomplete")
	}
	row := inventoryQualitySnapshot()["synthetic"]
	if row["returned"] != maxItems || row["status"] != "possible_truncation" {
		t.Fatalf("unexpected row: %v", row)
	}
	recordInventoryQuality("synthetic", 3, nil)
	success := inventoryQualitySnapshot()["synthetic"]["last_success_at"]
	recordInventoryQuality("synthetic", 0, errors.New("synthetic failure"))
	if row := inventoryQualitySnapshot()["synthetic"]; row["status"] != "failed" || row["last_success_at"] != success {
		t.Fatalf("failed collection lost previous success: %v", row)
	}
}

func TestSoftwareInventoryProbeDistinguishesExactCap(t *testing.T) {
	items := make([]any, extendedSoftwareLimit)
	bounded, incomplete := boundInventoryProbe(items, extendedSoftwareLimit)
	if incomplete || len(bounded) != extendedSoftwareLimit {
		t.Fatal("exact cap is complete when probe has no extra result")
	}
	bounded, incomplete = boundInventoryProbe(append(items, nil), extendedSoftwareLimit)
	if !incomplete || len(bounded) != extendedSoftwareLimit {
		t.Fatal("extra row must mark collection incomplete")
	}
}
