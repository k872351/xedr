//go:build !windows && !linux

package main

func runBundledSCA() []map[string]any {
	return nil
}
