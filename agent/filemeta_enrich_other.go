//go:build !windows

package main

func attachFileMeta(detail map[string]any, path string) {}

func attachFileMetaCached(detail map[string]any, path string) {}

func bumpSeverityForFileMeta(sev string, detail map[string]any) string {
	return sev
}

func fileMetaWarmAsync(path string) {}
