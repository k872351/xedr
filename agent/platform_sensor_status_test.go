package main

import "testing"

func TestPlatformSensorMode(t *testing.T) {
	if platformSensorMode("linux", true, true) != "linux_inventory" {
		t.Fatal("Linux mode must not claim Windows sensors")
	}
	if platformSensorMode("windows", true, true) != "kernel+etw+wmi+winevent" {
		t.Fatal("Windows mode changed")
	}
	for _, id := range []string{"etw", "winevent", "wmi_process", "registry", "amsi", "api_etw", "device", "persist"} {
		if componentSupportedOn("linux", id) || !componentSupportedOn("windows", id) {
			t.Fatalf("invalid platform support: %s", id)
		}
	}
	if !componentSupportedOn("linux", "linux_journal") || componentSupportedOn("windows", "linux_journal") {
		t.Fatal("journal platform support invalid")
	}
}
