//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPEFileMetaOfSelf(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// go test 二进制也是 PE
	meta, err := peFileMetaOf(exe)
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil {
		t.Fatal("nil meta")
	}
	if len(meta.Sections) == 0 {
		t.Fatal("expected sections")
	}
	if meta.MaxEntropy <= 0 || meta.MaxEntropy > 8 {
		t.Fatalf("bad max entropy: %v", meta.MaxEntropy)
	}
	t.Logf("compile=%s imphash=%s max_entropy=%.2f packed=%v sections=%d arch=%v",
		meta.CompileTime, meta.ImpHash, meta.MaxEntropy, meta.PackedLikely, len(meta.Sections), meta.Is64)
}

func TestPEFileMetaSystemDLL(t *testing.T) {
	p := filepath.Join(os.Getenv("WINDIR"), "System32", "kernel32.dll")
	if _, err := os.Stat(p); err != nil {
		t.Skip(err)
	}
	meta, err := peFileMetaOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ImpHash == "" {
		t.Fatal("kernel32 should have imphash")
	}
	if meta.CompileFuture {
		t.Fatal("kernel32 should not have future compile time")
	}
	t.Logf("kernel32 imphash=%s compile=%s", meta.ImpHash, meta.CompileTime)
}

func TestMOTWRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(p, []byte("MZ fake"), 0644); err != nil {
		t.Fatal(err)
	}
	ads := p + ":Zone.Identifier"
	body := "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://evil.example/a\r\nHostUrl=https://cdn.example/sample.exe\r\n"
	if err := os.WriteFile(ads, []byte(body), 0644); err != nil {
		t.Skip("ADS not supported:", err)
	}
	info := motwOf(p)
	if !info.Present || info.ZoneID != 3 {
		t.Fatalf("motw=%+v", info)
	}
	if info.Referrer == "" || info.HostURL == "" {
		t.Fatalf("missing urls: %+v", info)
	}
	d := map[string]any{"path": p}
	attachFileMeta(d, p)
	if d["motw_zone"] != 3 {
		t.Fatalf("detail=%v", d)
	}
	sev := bumpSeverityForFileMeta("info", map[string]any{
		"path": filepath.Join(dir, "Downloads", "x.exe"), "motw_zone": 3,
	})
	// Downloads path may not match drop zone helper without \downloads\ — force
	sev = bumpSeverityForFileMeta("info", map[string]any{
		"path": `C:\Users\bob\Downloads\x.exe`, "motw_zone": 3,
	})
	if sev != "high" {
		t.Fatalf("sev=%s", sev)
	}
	_ = time.Now()
}
