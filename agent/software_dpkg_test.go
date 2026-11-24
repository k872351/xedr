package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestDpkgInventoryExtendedProbe(t *testing.T) {
	var input strings.Builder
	for i := 0; i < pagedSoftwareLimit+1; i++ {
		fmt.Fprintf(&input, "Package: sample-%d\nArchitecture: amd64\nStatus: install ok installed\nVersion: 1.0\n\n", i)
	}
	rows, err := parseDpkgInventory(strings.NewReader(input.String()), pagedSoftwareLimit+1)
	if err != nil || len(rows) != pagedSoftwareLimit+1 {
		t.Fatalf("extended probe count=%d, err=%v", len(rows), err)
	}
}

func TestDpkgInventory(t *testing.T) {
	input := "Package: old\nStatus: deinstall ok config-files\n\nPackage: app\nArchitecture: arm64\nStatus: hold ok installed\nVersion: 1.2"
	rows, err := parseDpkgInventory(strings.NewReader(input), 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	item := rows[0].(map[string]any)
	if item["name"] != "app" || item["arch"] != "arm64" || item["version"] != "1.2" {
		t.Fatal(item)
	}
	rows, err = parseDpkgInventory(strings.NewReader(input+"\n\nPackage: truncated"), 1)
	if rows != nil || err == nil {
		t.Fatal("partial inventory accepted")
	}
	rows, err = parseDpkgInventory(strings.NewReader(""), 10)
	if rows == nil || len(rows) != 0 || err != nil {
		t.Fatal("empty inventory failed")
	}
}
