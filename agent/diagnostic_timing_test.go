package main

import (
	"testing"
	"time"
)

func TestDiagnosticTiming(t *testing.T) {
	start := time.Now()
	if got := measureDiagnostic(start, start.Add(125*time.Microsecond), true); got.ElapsedUS != 125 || !got.Available {
		t.Fatalf("unexpected diagnostic measurement: %+v", got)
	}
	if got := measureDiagnostic(start, start.Add(-time.Second), true); got.Available {
		t.Fatal("invalid clock observation reported as available")
	}
}
