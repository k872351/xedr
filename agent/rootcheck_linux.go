//go:build linux

package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const linuxRootcheckMaxEntries = 4000

func startRootcheckLoop(ctx context.Context, box *outbox, aid func() string) {
	go func() {
		recordComponentObservation("rootcheck", cStateStarting, "Linux rootcheck scan pending")
		if integrationEnabled("rootcheck") {
			runRootcheck(box, aid)
		}
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if integrationEnabled("rootcheck") {
					runRootcheck(box, aid)
				}
			}
		}
	}()
}

func runRootcheck(box *outbox, aid func() string) {
	finishWork := beginComponentWork("rootcheck")
	defer finishWork()
	findings, complete := linuxRootcheckFindings()
	if complete {
		recordComponentObservation("rootcheck", cStateHealthy, "Linux filesystem permission and set-id checks completed")
	} else {
		recordComponentObservation("rootcheck", cStateDegraded, "Linux rootcheck completed with unreadable or capped paths")
	}
	if len(findings) == 0 {
		return
	}
	log.Printf("rootcheck: %d Linux findings", len(findings))
	box.enqueue(outEvent, 60, map[string]any{
		"agent_id": aid(), "module": "rootcheck", "severity": "medium",
		"title":  "Linux rootcheck findings",
		"detail": map[string]any{"findings": findings, "count": len(findings)},
	})
}

func linuxRootcheckFindings() ([]map[string]any, bool) {
	var findings []map[string]any
	complete := true
	for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"} {
		info, err := os.Lstat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				complete = false
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Mode().Perm()&0022 != 0 {
			findings = append(findings, map[string]any{
				"type": "sensitive_file_writable", "path": path,
				"mode": info.Mode().Perm().String(), "severity": "high",
			})
		}
	}

	visited := 0
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if visited >= linuxRootcheckMaxEntries {
				complete = false
				return filepath.SkipAll
			}
			if walkErr != nil {
				complete = false
				return nil
			}
			if entry.IsDir() {
				depth := strings.Count(strings.TrimPrefix(path, root), string(os.PathSeparator))
				if path != root && depth >= 3 {
					return filepath.SkipDir
				}
				return nil
			}
			visited++
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				complete = false
				return nil
			}
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0 {
				return nil
			}
			findings = append(findings, map[string]any{
				"type": "setid_file_in_temporary_path", "path": path,
				"mode": info.Mode().Perm().String(), "severity": "high",
			})
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			complete = false
		}
	}
	return findings, complete
}
