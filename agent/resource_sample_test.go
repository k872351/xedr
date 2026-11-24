package main

import (
	"testing"
	"time"
)

func TestResourceCPUSample(t *testing.T) {
	if value, ok := cpuSample(10_000_000, 20_000_000, time.Second, 4); !ok || value != 25 {
		t.Fatalf("value=%v valid=%v", value, ok)
	}
	for _, counters := range [][2]uint64{{0, 20}, {20, 0}, {20, 10}} {
		if _, ok := cpuSample(counters[0], counters[1], time.Second, 4); ok {
			t.Fatal("invalid counters accepted")
		}
	}
	if _, ok := cpuSample(10, 20, time.Millisecond, 4); ok {
		t.Fatal("short sample accepted")
	}
	if value, ok := cpuSample(1, ^uint64(0), time.Second, 1); !ok || value != 100 {
		t.Fatalf("large counter should be capped: %v valid=%v", value, ok)
	}
	if value := round1(300_000_000.25); value != 300_000_000.3 {
		t.Fatalf("rounding must not depend on native int width: %v", value)
	}
}

func BenchmarkResourceCPUSample(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cpuSample(10_000_000, 20_000_000, time.Second, 4)
	}
}

func TestResourceCPUSamplerLifecycle(t *testing.T) {
	var sampler resourceCPUSampler
	start := time.Now()
	if _, valid := sampler.update(10_000_000, start, 4); valid {
		t.Fatal("first sample must have no percentage")
	}
	if value, valid := sampler.update(20_000_000, start.Add(time.Second), 4); !valid || value != 25 {
		t.Fatalf("value=%v valid=%v", value, valid)
	}
	if _, valid := sampler.update(0, start.Add(2*time.Second), 4); valid {
		t.Fatal("missing counter must invalidate previous percentage")
	}
	if _, valid := sampler.update(3_000_000, start.Add(3*time.Second), 4); valid {
		t.Fatal("first sample after reset must remain unknown")
	}
	if value, valid := sampler.update(13_000_000, start.Add(4*time.Second), 4); !valid || value != 25 {
		t.Fatalf("value=%v valid=%v", value, valid)
	}
	if _, valid := sampler.update(14_000_000, start.Add(3*time.Second), 4); valid {
		t.Fatal("backward clock must invalidate previous percentage")
	}
}

func TestResourceCPUSamplerLongSyntheticSequence(t *testing.T) {
	var sampler resourceCPUSampler
	start := time.Now()
	sampler.update(10_000_000, start, 4)
	for i := 1; i <= 100000; i++ {
		counter := uint64(i+1) * 10_000_000
		value, valid := sampler.update(counter, start.Add(time.Duration(i)*time.Second), 4)
		if !valid || value != 25 {
			t.Fatalf("sample %d: value=%v valid=%v", i, value, valid)
		}
	}
}
