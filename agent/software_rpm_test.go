package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestRPMInventoryExtendedProbe(t *testing.T) {
	var input strings.Builder
	for i := 0; i < pagedSoftwareLimit+1; i++ {
		fmt.Fprintf(&input, "sample-%d\t1.0\tx86_64\n", i)
	}
	rows, err := parseRPMInventory(strings.NewReader(input.String()), pagedSoftwareLimit+1)
	if err != nil || len(rows) != pagedSoftwareLimit+1 {
		t.Fatalf("extended probe count=%d, err=%v", len(rows), err)
	}
}

func TestRPMInventory(t *testing.T) {
	rows, err := parseRPMInventory(strings.NewReader("example\t1.2-3\taarch64\n"), 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	item := rows[0].(map[string]any)
	if item["arch"] != "aarch64" || item["version"] != "1.2-3" {
		t.Fatal(item)
	}
	if rows, err = parseRPMInventory(strings.NewReader("broken"), 10); rows != nil || err == nil {
		t.Fatal("invalid record accepted")
	}
}
