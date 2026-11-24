//go:build !windows && !linux

package main

func upgradeDetailsSnapshot(cfg Config) map[string]any {
	return nil
}
