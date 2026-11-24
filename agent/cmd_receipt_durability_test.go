package main

import "testing"

func TestReceiptFailureClosed(t *testing.T) {
	st := memoryStateDB()
	defer st.close()
	box := &outbox{st: st}
	if box.cmdBegin("fixture-unsafe", "upgrade") {
		t.Fatal("volatile receipt accepted")
	}
	if !box.cmdBegin("fixture", "test") {
		t.Fatal("synthetic receipt missing")
	}
	if box.cmdBegin("fixture", "test") {
		t.Fatal("duplicate claim accepted")
	}
	if box.cmdFinish("missing", true, nil) {
		t.Fatal("missing receipt reported complete")
	}
	if !box.cmdFinish("fixture", true, map[string]any{"fixture": true}) {
		t.Fatal("synthetic result not recorded")
	}
}
