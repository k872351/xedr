//go:build !windows

package main

func enrichLateralEvents(events []map[string]any) []map[string]any { return events }
