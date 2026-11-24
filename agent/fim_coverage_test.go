package main

import (
	"path/filepath"
	"testing"
)

func TestFIMIncompleteRootRetainsOldBaseline(t *testing.T) {
	root := fimRoot{Path: t.TempDir(), Recursive: true}
	oldPath := filepath.Join(root.Path, "nested", "sample.txt")
	old := fimEntry{Path: oldPath, Size: 7}
	previous := map[string]fimEntry{oldPath: old}
	current := map[string]fimEntry{}
	retainIncompleteFIMBaseline(previous, current, []fimRoot{root}, nil)
	if current[oldPath] != old {
		t.Fatal("partial or missing root discarded the previous baseline")
	}
	current = map[string]fimEntry{}
	retainIncompleteFIMBaseline(previous, current, []fimRoot{root}, map[string]fimRoot{root.Path: root})
	if _, retained := current[oldPath]; retained {
		t.Fatal("complete traversal did not establish absence")
	}
}

func TestFIMCoverageHonorsDirectoryAndExtension(t *testing.T) {
	root := fimRoot{Path: t.TempDir(), Exts: extSet(".txt")}
	if !fimRootCoversPath(root, filepath.Join(root.Path, "sample.txt")) {
		t.Fatal("direct file not covered")
	}
	for _, candidate := range []string{filepath.Join(root.Path, "nested", "sample.txt"), filepath.Join(root.Path, "sample.json"), root.Path + "-other"} {
		if fimRootCoversPath(root, candidate) {
			t.Fatalf("out-of-scope file covered: %s", candidate)
		}
	}
}
