package main

import "testing"

func TestStampEventSchemaAndGaps(t *testing.T) {
	ev := map[string]any{"etype": "x"}
	stampEventSchema(ev)
	if ev["schema_version"] != eventSchemaVersion {
		t.Fatalf("%v", ev)
	}
	seq1, _ := ev["agent_seq"].(uint64)
	ev2 := map[string]any{}
	stampEventSchema(ev2)
	seq2, _ := ev2["agent_seq"].(uint64)
	if seq2 != seq1+1 {
		t.Fatalf("%d %d", seq1, seq2)
	}
	gaps := detectSeqGaps([]uint64{1, 2, 5, 6})
	if len(gaps) != 2 || gaps[0] != 3 || gaps[1] != 4 {
		t.Fatalf("%v", gaps)
	}
}
