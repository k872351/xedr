//go:build !windows && !linux

package main

func hostMetricsSnapshot() map[string]any { return nil }
