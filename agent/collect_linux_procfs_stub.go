//go:build !linux

package main

import "fmt"

// Keep collect_other.go buildable on non-Windows, non-Linux targets. The
// runtime Linux branches never call these functions on those operating systems.
func collectLinuxProcessesProcfs() ([]any, error) {
	return nil, fmt.Errorf("procfs process collection is only available on Linux")
}

func collectLinuxNetworkProcfs() ([]any, error) {
	return nil, fmt.Errorf("procfs network collection is only available on Linux")
}

func collectLinuxServicesFromUnits() ([]any, error) {
	return nil, fmt.Errorf("systemd unit collection is only available on Linux")
}

func collectLinuxServicesFromUnitsLimited(_ int) ([]any, error) {
	return collectLinuxServicesFromUnits()
}

func collectLinuxTasks() ([]any, error) {
	return nil, fmt.Errorf("cron and systemd timer collection is only available on Linux")
}

func collectLinuxStartupEntries() ([]any, error) {
	return nil, fmt.Errorf("Linux startup collection is only available on Linux")
}
