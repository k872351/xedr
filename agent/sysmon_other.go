//go:build !windows

package main

func ensureSysmonManaged(api *APIClient) map[string]any {
	return map[string]any{"managed": false, "present": false, "action": "unsupported"}
}

func sysmonStatusSnapshot() map[string]any {
	return map[string]any{"managed": false, "present": false, "action": "unsupported"}
}

func uninstallManagedSysmon() {}

func setAppliedPolicy(map[string]any) {}

func sysmonManagedEnabled() bool { return false }
