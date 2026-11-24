//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateExistingConfigRejectsServerChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	raw, _ := json.Marshal(map[string]any{
		"server_url": "https://edr.example/old",
		"agent_id":   "keep-me",
		"token":      "secret-token",
	})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateExistingConfig(path, "https://edr.example/new"); err == nil {
		t.Fatal("different server must require explicit migration")
	}
	if err := validateExistingConfig(path, "https://edr.example/old"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteServerURLPreservesExistingIdentity(t *testing.T) {
	dir := t.TempDir()
	cfgDst := filepath.Join(dir, "agent.json")
	raw, _ := json.Marshal(map[string]any{
		"server_url": "https://edr.example",
		"agent_id":   "stable-id-001",
		"token":      "fa_keep",
	})
	if err := os.WriteFile(cfgDst, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeServerURL(cfgDst, filepath.Join(dir, "missing.json"), "https://edr.example"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(cfgDst)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["agent_id"] != "stable-id-001" || m["token"] != "fa_keep" {
		t.Fatalf("cover install must keep identity, got %#v", m)
	}
}
