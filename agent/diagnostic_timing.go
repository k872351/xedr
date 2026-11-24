package main

import "time"

// diagnosticTiming describes one local self-diagnostic measurement.
// Wall time is not attributed CPU or heap usage.
type diagnosticTiming struct {
	ElapsedUS int64
	Available bool
}

func measureDiagnostic(start, end time.Time, available bool) diagnosticTiming {
	if end.Before(start) {
		return diagnosticTiming{}
	}
	return diagnosticTiming{ElapsedUS: end.Sub(start).Microseconds(), Available: available}
}

func (t diagnosticTiming) fields() map[string]any {
	return map[string]any{"elapsed_us": t.ElapsedUS, "available": t.Available}
}
