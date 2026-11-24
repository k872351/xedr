package main

// Describes configured collection architecture, not evidence of sensor health.
func platformSensorMode(platform string, wmi, kernel bool) string {
	switch platform {
	case "linux":
		return "linux_inventory"
	case "windows":
		mode := "etw+winevent"
		if wmi {
			mode = "etw+wmi+winevent"
		}
		if kernel {
			mode = "kernel+" + mode
		}
		return mode
	default:
		return "inventory_only"
	}
}

func componentSupportedOn(platform, id string) bool {
	switch id {
	case "etw", "winevent", "wmi_process", "registry", "amsi", "api_etw", "device", "persist":
		return platform == "windows"
	case "linux_journal":
		return platform == "linux"
	case "fim", "rootcheck", "sca", "memory_scan":
		return platform == "windows" || platform == "linux"
	default:
		return true
	}
}
