//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBookmarkFileReplacementPreservesConfirmedValue(t *testing.T) {
	dir := t.TempDir()
	if !winevtSaveBookmarkXML(dir, "synthetic", "first") || !winevtSaveBookmarkXML(dir, "synthetic", "second") {
		t.Fatal("confirmed bookmark save failed")
	}
	if winevtSaveBookmarkXML(dir, "synthetic", "") {
		t.Fatal("empty bookmark accepted")
	}
	if winevtSaveBookmarkXML(filepath.Join(dir, "missing"), "synthetic", "invalid") {
		t.Fatal("save into absent directory accepted")
	}
	data, err := os.ReadFile(filepath.Join(dir, "synthetic.xml"))
	if err != nil || string(data) != "second" {
		t.Fatalf("confirmed bookmark lost: %q %v", data, err)
	}
}

func TestCaptureQualitySyntheticBurst(t *testing.T) {
	etw := newETWWatcher()
	win := newWinEventWatcher()
	before := captureQualitySnapshot()
	for i := 0; i < 1000; i++ {
		etw.push(map[string]any{"etype": "quality_test", "summary": "synthetic observation"})
		win.push(map[string]any{"etype": "quality_test", "summary": "synthetic observation"})
	}
	after := captureQualitySnapshot()
	for source, expected := range map[string]uint64{"etw": 400, "winevent": 600} {
		delta := after[source]["buffer_dropped"] - before[source]["buffer_dropped"]
		if delta != expected {
			t.Fatalf("%s: expected %d drops, got %d", source, expected, delta)
		}
		if after[source]["received"]-before[source]["received"] != 1000 {
			t.Fatalf("%s: receive count mismatch", source)
		}
	}
	if got := len(etw.drain()); got != 300 {
		t.Fatalf("ETW drain=%d", got)
	}
	if got := len(win.drain()); got != 200 {
		t.Fatalf("WinEvent drain=%d", got)
	}
}
