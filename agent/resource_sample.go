package main

import (
	"math"
	"time"
)

func round1(f float64) float64 {
	return math.Round(f*10) / 10
}

// cpuSample reports the fraction of total logical CPU capacity used by
// this process. Missing counters and counter resets invalidate the sample.
func cpuSample(previous, current uint64, elapsed time.Duration, logicalCPUs int) (float64, bool) {
	if previous == 0 || current == 0 || current < previous || elapsed < time.Second || logicalCPUs <= 0 {
		return 0, false
	}
	percent := float64(current-previous) / 1e7 / elapsed.Seconds() / float64(logicalCPUs) * 100
	return round1(math.Min(100, percent)), true
}

// resourceCPUSampler holds only the local process CPU sampling baseline.
type resourceCPUSampler struct {
	counter uint64
	at      time.Time
	percent float64
	valid   bool
}

func (s *resourceCPUSampler) update(counter uint64, now time.Time, logicalCPUs int) (float64, bool) {
	if counter == 0 || counter < s.counter || s.at.IsZero() || now.Before(s.at) {
		s.valid = false
		s.counter, s.at = counter, now
	} else if now.Sub(s.at) >= time.Second {
		s.percent, s.valid = cpuSample(s.counter, counter, now.Sub(s.at), logicalCPUs)
		s.counter, s.at = counter, now
	}
	return s.percent, s.valid
}
