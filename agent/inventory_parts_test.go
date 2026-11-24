package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSnapshotPartsPreservePayloadAndStableIDs(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"module": "service", "items": []any{map[string]any{"name": strings.Repeat("测试", 40000)}}})
	if err != nil {
		t.Fatal(err)
	}
	r := readyRow{uuid: "synthetic-snapshot-1", payload: raw}
	first, err := snapshotPartEvents(r)
	if err != nil {
		t.Fatal(err)
	}
	again, err := snapshotPartEvents(r)
	if err != nil {
		t.Fatal(err)
	}
	var combined strings.Builder
	sum := sha256.Sum256(raw)
	for i, e := range first {
		p := e["payload"].(map[string]any)
		fragment := p["fragment"].(string)
		if len(fragment) > snapshotPartBytes || !utf8.ValidString(fragment) || e["uuid"] != again[i]["uuid"] || p["checksum"] != hex.EncodeToString(sum[:]) {
			t.Fatal("invalid or unstable part")
		}
		combined.WriteString(fragment)
	}
	if combined.String() != string(raw) {
		t.Fatal("snapshot reconstruction differs")
	}
}

func TestPagedSoftwareForcesStagingBelowByteThreshold(t *testing.T) {
	items := make([]any, 1501)
	for i := range items {
		items[i] = map[string]any{"name": "synthetic"}
	}
	raw, err := json.Marshal(map[string]any{"module": "software", "items": items, "paged_software": true})
	if err != nil || len(raw) >= snapshotPartBytes || !snapshotRequiresPaging(raw) {
		t.Fatal("test requires a small paged snapshot")
	}
	parts, err := snapshotPartEvents(readyRow{uuid: "paged-synthetic", payload: raw})
	if err != nil || len(parts) < 2 {
		t.Fatalf("paging failed: %v", err)
	}
	var combined strings.Builder
	for _, part := range parts {
		combined.WriteString(part["payload"].(map[string]any)["fragment"].(string))
	}
	if combined.String() != string(raw) {
		t.Fatal("paged transfer changed snapshot")
	}
}

func TestSnapshotPartsRetainOriginalUntilAllAcknowledged(t *testing.T) {
	f, srv := newFake()
	box, api := testBox(t, t.TempDir(), srv)
	box.useV2.Store(true)
	box.snapshotParts.Store(true)
	if !box.enqueue(outSnapshot, 50, map[string]any{"module": "service", "items": []any{map[string]any{"name": strings.Repeat("x", snapshotPartBytes+100)}}}) {
		t.Fatal("enqueue failed")
	}
	rows := box.fetchReady()
	parts, err := snapshotPartEvents(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	last := parts[len(parts)-1]["uuid"].(string)
	f.dropFn = func(id string) bool { return id == last }
	if n, err := box.sendV2(api, rows); err != nil || n != 0 || box.pending() != 1 {
		t.Fatalf("partial ack lost original: n=%d pending=%d err=%v", n, box.pending(), err)
	}
	f.dropFn = nil
	if n, err := box.sendV2(api, rows); err != nil || n != 1 || box.pending() != 0 {
		t.Fatalf("complete ack did not clear original: n=%d pending=%d err=%v", n, box.pending(), err)
	}
	for _, part := range parts {
		if f.seen[part["uuid"].(string)] != 2 {
			t.Fatal("retry changed part identity")
		}
	}
}

func TestExtendedSoftwareDoesNotSendToLegacy(t *testing.T) {
	f, srv := newFake()
	box, api := testBox(t, t.TempDir(), srv)
	items := make([]any, maxItems+1)
	for i := range items {
		items[i] = map[string]any{"name": "synthetic"}
	}
	var invalidated bool
	box.onReject = func(kind outboxKind, payload map[string]any, message string) {
		invalidated = kind == outSnapshot && payload["module"] == "software"
	}
	box.enqueue(outSnapshot, 50, map[string]any{"module": "software", "items": items})
	if _, err := box.sendLegacy(api, box.fetchReady()); err != nil || box.pending() != 0 || f.legacy != 0 || !invalidated {
		t.Fatalf("legacy extended inventory was not safely skipped: %v", err)
	}
}
