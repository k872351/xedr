package main

import (
	"testing"
	"time"
)

func TestIntervalStatsBeaconLike(t *testing.T) {
	base := time.Now().Add(-10 * time.Minute)
	var ts []time.Time
	for i := 0; i < 8; i++ {
		ts = append(ts, base.Add(time.Duration(i)*60*time.Second))
	}
	mean, cv, ok := intervalStats(ts)
	if !ok {
		t.Fatal("expected ok")
	}
	if mean < 55 || mean > 65 {
		t.Fatalf("mean=%v", mean)
	}
	if cv > 0.05 {
		t.Fatalf("cv=%v", cv)
	}
}

func TestIntervalStatsJittery(t *testing.T) {
	base := time.Now()
	ts := []time.Time{
		base,
		base.Add(10 * time.Second),
		base.Add(200 * time.Second),
		base.Add(220 * time.Second),
		base.Add(800 * time.Second),
		base.Add(810 * time.Second),
	}
	_, cv, ok := intervalStats(ts)
	if !ok {
		t.Fatal("expected ok")
	}
	if cv < 0.5 {
		t.Fatalf("expected high cv, got %v", cv)
	}
}

func TestBeaconWatchEmits(t *testing.T) {
	var got map[string]any
	w := &beaconWatcher{slots: map[string]*beaconSlot{}}
	w.setEmit(func(ev map[string]any) { got = ev })
	base := time.Now().Add(-15 * time.Minute)
	for i := 0; i < 6; i++ {
		w.observeNet(map[string]any{
			"remote": "203.0.113.10:443", "pid": uint32(4242),
			"process_name": "evil.exe", "path": `C:\Users\bob\AppData\Local\Temp\evil.exe`,
			"entity_id": "ent-1",
		}, base.Add(time.Duration(i)*90*time.Second))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && got == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if got == nil || asString(got["etype"]) != "beacon_like" {
		t.Fatalf("got=%v", got)
	}
	if asString(got["severity"]) != "high" {
		t.Fatalf("severity=%v", got["severity"])
	}
}
