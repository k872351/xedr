package main

import "testing"

func TestCaptureHealthScoreUnsupportedPlatform(t *testing.T) {
	got := computeCaptureHealthScore(map[string]any{
		"capture_status": map[string]any{"platform": "non-windows"},
	})
	if got["score"] != nil || got["level"] != "unsupported" {
		t.Fatalf("expected unsupported health, got %v", got)
	}
}

func TestCaptureHealthScoreCommandSamples(t *testing.T) {
	for _, tc := range []struct {
		name          string
		with, without uint64
		pct           float64
		want          int
	}{
		{"no samples", 0, 0, 0, 100},
		{"poor", 2, 8, 20, 80},
		{"fair", 6, 4, 60, 92},
		{"good", 9, 1, 90, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := computeCaptureHealthScore(map[string]any{
				"capture_status": map[string]any{"etw_session_ok": true, "etw_mode": "etw_native"},
				"telemetry":      map[string]any{"proc_with_cmd": tc.with, "proc_no_cmd": tc.without, "proc_cmd_fill_pct": tc.pct},
			})
			if got["score"] != tc.want {
				t.Fatalf("score = %v; want %d", got["score"], tc.want)
			}
			if got["cmd_fill_hint"] != (tc.with > 0 || tc.without > 0) {
				t.Fatalf("unexpected sample availability: %v", got["cmd_fill_hint"])
			}
		})
	}
}
