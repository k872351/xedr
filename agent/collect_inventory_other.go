//go:build !windows && !linux

package main

import (
	"fmt"
	"runtime"
)

func collectHotfix() ([]any, error) {
	return nil, fmt.Errorf("OS patch inventory is unsupported on %s", runtime.GOOS)
}
func collectHotfixLimited(_ int) ([]any, error) { return collectHotfix() }
func collectListen() ([]any, error)             { return collectNetwork() }
