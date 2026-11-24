//go:build linux

package main

func upgradeDetailsSnapshot(_ Config) map[string]any {
	return upgradePhaseSnapshot()
}
