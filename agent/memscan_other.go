//go:build !windows && !linux

package main

import "fmt"

func scanMemory(params map[string]any) (map[string]any, error) {
	finishWork := beginComponentWork("memory_scan")
	defer finishWork()
	return nil, fmt.Errorf("内存扫描仅支持 Windows")
}

func runIntegritySweep() map[string]any {
	return nil
}
