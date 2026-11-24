package main

import (
	"strings"
	"testing"
)

func TestJournalParsing(t *testing.T) {
	event, cursor, err := parseJournalLine([]byte(`{"__CURSOR":"cursor-1","__REALTIME_TIMESTAMP":"1730000000000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"authentication failure token=private-value","UNRELATED":"not exported"}`))
	if err != nil || cursor != "cursor-1" || event["etype"] != "linux_journal" {
		t.Fatalf("unexpected record: %v, %v", event, err)
	}
	detail := event["detail"].(map[string]any)
	if detail["channel"] != "sshd" || strings.Contains(detail["message"].(string), "private-value") || detail["UNRELATED"] != nil {
		t.Fatalf("unexpected detail: %v", detail)
	}
	if _, _, err := parseJournalLine([]byte(`{"MESSAGE":"no cursor"}`)); err == nil {
		t.Fatal("missing cursor should be rejected")
	}
}

func TestJournalCommitAndCursor(t *testing.T) {
	db := memoryStateDB()
	defer db.db.Close()
	box := &outbox{st: db, kickCh: make(chan struct{}, 1)}
	if err := box.commitJournal("agent", "host", nil, "c1"); err == nil {
		t.Fatal("in-memory outbox must not advance cursor")
	}
	// Use in-memory SQLite solely to test transaction semantics.
	db.path = "test-durable"
	before := captureQualitySnapshot()["linux_journal"]
	event := map[string]any{"etype": "linux_journal"}
	if err := box.commitJournal("agent", "host", []map[string]any{event}, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := box.commitJournal("agent", "host", []map[string]any{event}, "c1"); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM outbox").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("expected one queued record, got %d: %v", rows, err)
	}
	if got := db.kvGet(linuxJournalCursorKey); got != "c1" {
		t.Fatalf("expected c1, got %q", got)
	}
	oldMax := outboxMaxRows
	outboxMaxRows = 1
	defer func() { outboxMaxRows = oldMax }()
	if err := box.commitJournal("agent", "host", []map[string]any{event}, "c2"); err == nil {
		t.Fatal("full outbox should refuse input")
	}
	if got := db.kvGet(linuxJournalCursorKey); got != "c1" {
		t.Fatalf("cursor advanced despite failed write: %q", got)
	}
	after := captureQualitySnapshot()["linux_journal"]
	if after["persisted"]-before["persisted"] != 1 || after["deduplicated"]-before["deduplicated"] != 1 || after["cursor_confirmed"]-before["cursor_confirmed"] != 2 {
		t.Fatalf("unexpected journal quality counters: %v", after)
	}
}
