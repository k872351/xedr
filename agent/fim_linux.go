//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	linuxFIMInterval = 60 * time.Second
	linuxFIMMaxFiles = 12000
	linuxFIMMaxBytes = 16 << 20
)

type fimWatcher struct {
	mu       sync.Mutex
	stateDir string
	active   bool
	events   []map[string]any
	dropped  int
	extra    []string
	webRoots []string
	baseline map[string]fimEntry
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func newFIMWatcher(_ *stateDB, stateDir string) *fimWatcher {
	return &fimWatcher{stateDir: stateDir, baseline: make(map[string]fimEntry)}
}

func (w *fimWatcher) setExtra(paths []string) {
	w.mu.Lock()
	w.extra = append([]string(nil), paths...)
	w.mu.Unlock()
}

func (w *fimWatcher) running() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.active
}

func (w *fimWatcher) drain() []map[string]any {
	w.mu.Lock()
	out := w.events
	w.events = nil
	dropped := w.dropped
	w.dropped = 0
	w.mu.Unlock()
	captureAdd("fim", "drained", len(out))
	if dropped > 0 {
		out = append(out, map[string]any{
			"etype": "fim_overflow", "severity": "medium", "ts": time.Now().Format(time.RFC3339),
			"summary": "FIM event queue overflow; coalesced " + fmt.Sprint(dropped) + " events",
			"detail":  map[string]any{"source": "fim", "dropped": dropped},
		})
	}
	return out
}

func (w *fimWatcher) start(parent context.Context) {
	w.mu.Lock()
	if w.active {
		w.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	w.active = true
	w.mu.Unlock()
	resetRootHealth()

	if err := os.MkdirAll(w.stateDir, 0700); err != nil {
		log.Printf("fim: create state directory: %v", err)
	}
	var baselineReady bool
	w.baseline, baselineReady = w.loadBaseline()
	if err := w.scanAndApply(ctx, !baselineReady); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("fim: initial scan: %v", err)
	}
	w.wg.Add(1)
	go w.loop(ctx)
}

func (w *fimWatcher) stop() {
	w.mu.Lock()
	cancel, active := w.cancel, w.active
	w.active = false
	w.cancel = nil
	w.mu.Unlock()
	if !active {
		return
	}
	if cancel != nil {
		cancel()
	}
	w.wg.Wait()
	resetRootHealth()
}

func (w *fimWatcher) loop(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(linuxFIMInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.scanAndApply(ctx, false); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("fim: scan: %v", err)
			}
		}
	}
}

func (w *fimWatcher) roots() []fimRoot {
	w.mu.Lock()
	extra := append([]string(nil), w.extra...)
	web := append([]string(nil), w.webRoots...)
	w.mu.Unlock()
	fimWebRootsMu.RLock()
	web = append(web, fimWebRoots...)
	fimWebRootsMu.RUnlock()
	roots := make([]fimRoot, 0, 8+len(extra)+len(web))
	for _, path := range extra {
		if root, ok := parseLinuxFIMPathSpec(path); ok {
			roots = append(roots, root)
		}
	}
	webExts := extSet(".conf", ".php", ".phtml", ".js", ".jsp", ".aspx", ".sh", ".py", ".pl", ".rb")
	for _, path := range web {
		if root, ok := parseLinuxFIMPathSpec(path); ok {
			root.Recursive = true
			root.Exts = webExts
			root.Label, root.Severity, root.HashBase = "web root", "high", true
			roots = append(roots, root)
		}
	}
	roots = append(roots,
		fimRoot{Path: "/etc", Recursive: true, Label: "system configuration", Severity: "medium", HashBase: true, MaxFiles: 5000},
		fimRoot{Path: "/usr/local/bin", Recursive: true, Label: "local executable", Severity: "high", HashBase: true, MaxFiles: 2000},
		fimRoot{Path: "/usr/local/sbin", Recursive: true, Label: "local system executable", Severity: "high", HashBase: true, MaxFiles: 1000},
		fimRoot{Path: "/usr/lib/systemd/system", Recursive: true, Label: "systemd unit", Severity: "medium", HashBase: false, MaxFiles: 3000},
		fimRoot{Path: "/usr/bin", Recursive: true, Label: "system executable", Severity: "medium", HashBase: false, MaxFiles: 5000},
		fimRoot{Path: "/usr/sbin", Recursive: true, Label: "system executable", Severity: "high", HashBase: false, MaxFiles: 2000},
	)
	seen := make(map[string]bool)
	out := make([]fimRoot, 0, len(roots))
	for _, root := range roots {
		clean := filepath.Clean(root.Path)
		if clean == "." || clean == "/" || seen[clean] {
			continue
		}
		covered := false
		for _, parent := range out {
			if parent.Recursive && parent.Exts == nil && linuxFIMContains(parent.Path, clean) {
				covered = true
				break
			}
		}
		if covered {
			recordRootHealth(clean, "watch", "covered_by_parent")
			continue
		}
		root.Path = clean
		seen[clean] = true
		out = append(out, root)
	}
	return out
}

func parseLinuxFIMPathSpec(spec string) (fimRoot, bool) {
	parts := strings.Split(strings.TrimSpace(spec), "|")
	if len(parts) == 0 {
		return fimRoot{}, false
	}
	path := filepath.Clean(strings.TrimSpace(parts[0]))
	if !filepath.IsAbs(path) || path == "/" || path == "." {
		return fimRoot{}, false
	}
	root := fimRoot{Path: path, Label: "custom", Severity: "medium", HashBase: true, MaxFiles: 3000}
	for _, raw := range parts[1:] {
		value := strings.ToLower(strings.TrimSpace(raw))
		switch value {
		case "r", "recursive":
			root.Recursive = true
		case "rule":
			root.Label, root.Severity, root.HashBase = "rule monitored", "info", false
		default:
			if value == "" {
				continue
			}
			root.Exts = make(map[string]bool)
			for _, ext := range strings.Split(value, ",") {
				ext := strings.TrimSpace(ext)
				if ext == "" {
					continue
				}
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				root.Exts[ext] = true
			}
		}
	}
	if root.Exts == nil && root.Label == "rule monitored" {
		root.Exts = fimExecExts
	}
	return root, true
}

func (w *fimWatcher) scanAndApply(ctx context.Context, initial bool) error {
	finishWork := beginComponentWork("fim")
	defer finishWork()
	previous := w.baseline
	current := make(map[string]fimEntry, len(previous))
	completedRoots := make(map[string]fimRoot)
	attemptedRoots := w.roots()
	for _, root := range attemptedRoots {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		info, statErr := os.Lstat(root.Path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			status := "unsupported_path"
			if errors.Is(statErr, os.ErrNotExist) {
				status = "missing"
			} else if statErr != nil {
				status = "inaccessible"
			}
			recordRootHealth(root.Path, "watch", status)
			recordRootHealth(root.Path, "reconcile", "partial")
			continue
		}
		recordRootHealth(root.Path, "watch", "polling")
		recordRootHealth(root.Path, "reconcile", "running")
		limit := root.MaxFiles
		if limit <= 0 || limit > linuxFIMMaxFiles {
			limit = linuxFIMMaxFiles
		}
		count := 0
		truncated := false
		rootReadError := false
		err := filepath.WalkDir(root.Path, func(path string, entry os.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if walkErr != nil {
				rootReadError = true
				return nil
			}
			if entry.IsDir() {
				if path != root.Path && !root.Recursive {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || !root.wants(path) {
				return nil
			}
			key := filepath.Clean(path)
			if _, alreadyScanned := current[key]; alreadyScanned {
				return nil
			}
			count++
			if count > limit || len(current) >= linuxFIMMaxFiles {
				truncated = true
				return filepath.SkipAll
			}
			info, err := entry.Info()
			if err != nil {
				rootReadError = true
				return nil
			}
			entryNow := fimEntry{Path: key, Size: info.Size(), Mtime: info.ModTime().Unix()}
			if old, ok := previous[key]; ok && old.Size == entryNow.Size && old.Mtime == entryNow.Mtime && (!root.HashBase || old.SHA != "") {
				entryNow.SHA = old.SHA
			} else if root.HashBase && entryNow.Size >= 0 && entryNow.Size <= linuxFIMMaxBytes {
				entryNow.SHA = linuxFIMHash(key)
				if entryNow.SHA == "" {
					rootReadError = true
				}
			}
			current[key] = entryNow
			if !initial {
				old, existed := previous[key]
				if !existed {
					w.emitLinuxFIM("fim_add", root, entryNow, nil)
				} else if fimChanged(old, entryNow) {
					w.emitLinuxFIM("fim_modify", root, entryNow, &old)
				}
			}
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("fim: walk %s: %v", root.Path, err)
		}
		if err == nil && !rootReadError && !truncated {
			completedRoots[root.Path] = root
			recordRootHealth(root.Path, "reconcile", "complete")
			recordRootHealth(root.Path, "last_complete", "ok")
		} else {
			recordRootHealth(root.Path, "reconcile", "partial")
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !initial {
		// Incomplete or oversized roots keep their previous baseline so a temporary
		// permission or capacity issue cannot be reported as mass file deletion.
		retainIncompleteFIMBaseline(previous, current, attemptedRoots, completedRoots)
		for path, old := range previous {
			if _, ok := current[path]; ok {
				continue
			}
			for _, root := range completedRoots {
				if fimRootCoversPath(root, path) {
					w.emitLinuxFIM("fim_delete", root, old, &old)
					break
				}
			}
		}
	}
	if err := w.saveBaseline(current); err != nil {
		for _, root := range attemptedRoots {
			recordRootHealth(root.Path, "baseline", "save_failed")
		}
		return err
	}
	w.baseline = current
	for _, root := range attemptedRoots {
		recordRootHealth(root.Path, "baseline", "saved")
	}
	return nil
}

func linuxFIMContains(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func linuxFIMHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, linuxFIMMaxBytes+1)); err != nil || n > linuxFIMMaxBytes {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (w *fimWatcher) emitLinuxFIM(kind string, root fimRoot, current fimEntry, previous *fimEntry) {
	old := fimEntry{}
	if previous != nil {
		old = *previous
	}
	item := fimEvent(kind, root, current, old, nil)
	captureTag(item, "fim")
	captureAdd("fim", "received", 1)
	w.mu.Lock()
	if len(w.events) >= 500 {
		w.events = w.events[1:]
		w.dropped++
		captureAdd("fim", "buffer_dropped", 1)
	}
	w.events = append(w.events, item)
	captureAdd("fim", "queued", 1)
	w.mu.Unlock()
}

func (w *fimWatcher) baselinePath() string {
	return filepath.Join(w.stateDir, "fim-linux-baseline.json")
}

func (w *fimWatcher) loadBaseline() (map[string]fimEntry, bool) {
	data, err := os.ReadFile(w.baselinePath())
	if err != nil {
		return make(map[string]fimEntry), false
	}
	out := make(map[string]fimEntry)
	if err := json.Unmarshal(data, &out); err != nil {
		log.Printf("fim: invalid Linux baseline, creating a new baseline: %v", err)
		return make(map[string]fimEntry), false
	}
	return out, true
}

func (w *fimWatcher) saveBaseline(snapshot map[string]fimEntry) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(w.stateDir, ".fim-linux-baseline-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, w.baselinePath()); err != nil {
		return err
	}
	ok = true
	return nil
}

func applyFIMWebRoots(paths []string) {
	clean := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.Clean(strings.TrimSpace(path))
		if filepath.IsAbs(path) && path != "/" {
			clean = append(clean, path)
		}
	}
	fimWebRootsMu.Lock()
	fimWebRoots = clean
	fimWebRootsMu.Unlock()
}

var (
	fimWebRootsMu sync.RWMutex
	fimWebRoots   []string
)
