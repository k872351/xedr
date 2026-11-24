//go:build windows

package main

import (
	"testing"
	"unsafe"
)

func TestNativeResourceLayout(t *testing.T) {
	var counters processMemoryCounters
	pointerWidth := unsafe.Sizeof(uintptr(0))
	if size := unsafe.Sizeof(counters); size != 8+8*pointerWidth {
		t.Fatalf("unexpected process memory counter size: %d", size)
	}
	if offset := unsafe.Offsetof(counters.WorkingSetSize); offset != 8+pointerWidth {
		t.Fatalf("unexpected working set offset: %d", offset)
	}
	// Read only the current test process. Unsupported native APIs must not panic.
	processUsage()
}
