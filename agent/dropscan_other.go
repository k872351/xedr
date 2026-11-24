//go:build !windows

package main

type dropScanner struct{}

var dropScan = &dropScanner{}

func applyDropScanPolicy(pol map[string]any)     {}
func (s *dropScanner) observe(ev map[string]any) {}
func (s *dropScanner) drain() []map[string]any   { return nil }
