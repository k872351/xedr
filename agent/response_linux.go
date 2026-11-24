//go:build linux

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// 单次远程样本上限 64MB（与 Windows 一致）
const pullFileMaxBytesLinux = 64 << 20

func execCommand(cfg Config, cmd agentCommand) (map[string]any, error) {
	switch strings.ToLower(strings.TrimSpace(cmd.Action)) {
	case "kill_process":
		return linuxKillProcess(cmd.Params)
	case "quarantine_file":
		return linuxQuarantineFile(cfg, cmd.Params)
	case "restore_file":
		return linuxRestoreQuarantine(cfg, cmd.Params)
	case "pull_file":
		return linuxPullFileSample(cmd.Params)
	case "refresh_modules":
		return map[string]any{"ok": true, "msg": "will refresh on next collection cycle"}, nil
	default:
		return nil, fmt.Errorf("remote action %q is unsupported on Linux", cmd.Action)
	}
}

func linuxPullFileSample(params map[string]any) (map[string]any, error) {
	path := strings.TrimSpace(asString(params["path"]))
	path = strings.Trim(path, `"'`)
	if path == "" || !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("a valid absolute path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("file not found: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to pull a symlink")
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("only regular files can be pulled")
	}
	if fi.Size() <= 0 {
		return nil, fmt.Errorf("empty file")
	}
	maxBytes := int64(pullFileMaxBytesLinux)
	if n, ok := numberOf(params["max_bytes"]); ok && n > 0 && n < float64(pullFileMaxBytesLinux) {
		maxBytes = int64(n)
	}
	if fi.Size() > maxBytes {
		return map[string]any{"path": abs, "size": fi.Size(), "refused": true, "max_bytes": maxBytes},
			fmt.Errorf("file too large (%d > %d)", fi.Size(), maxBytes)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if want := strings.TrimSpace(asString(params["sha256"])); want != "" && !strings.EqualFold(want, digest) {
		return map[string]any{"path": abs, "refused": true, "sha256": digest},
			fmt.Errorf("sha256 mismatch")
	}
	return map[string]any{
		"ok": true, "path": abs, "filename": filepath.Base(abs), "size": len(raw),
		"sha256": digest, "content_base64": base64.StdEncoding.EncodeToString(raw),
	}, nil
}

func linuxKillProcess(params map[string]any) (map[string]any, error) {
	pid := asInt(params["pid"])
	if pid <= 0 {
		return nil, fmt.Errorf("a positive pid is required")
	}
	if refuseKillSelf(pid) {
		return nil, fmt.Errorf("refusing to terminate the Agent process")
	}
	if guid := strings.TrimSpace(asString(params["process_guid"])); guid != "" {
		guidPID := guid
		if i := strings.IndexByte(guid, '_'); i >= 0 {
			guidPID = guid[:i]
		}
		if parsed, err := strconv.Atoi(guidPID); err != nil || parsed != pid {
			return map[string]any{"pid": pid, "process_guid": guid, "refused": true}, fmt.Errorf("process_guid does not match pid")
		}
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return map[string]any{"pid": pid}, err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return map[string]any{"pid": pid}, fmt.Errorf("send SIGTERM to %d: %w", pid, err)
	}
	return map[string]any{"pid": pid, "signal": "SIGTERM", "signal_sent": true, "verification_required": true}, nil
}

type linuxQuarantineRecord struct {
	ID       string `json:"quarantine_id"`
	Original string `json:"original"`
	Stored   string `json:"stored"`
	SHA256   string `json:"sha256"`
	Mode     uint32 `json:"mode"`
	Size     int64  `json:"size"`
	Created  string `json:"created_at"`
}

func linuxQuarantineFile(cfg Config, params map[string]any) (map[string]any, error) {
	source := strings.TrimSpace(fmt.Sprint(params["path"]))
	if source == "" || !filepath.IsAbs(source) {
		return nil, fmt.Errorf("an absolute file path is required")
	}
	source = filepath.Clean(source)
	info, err := os.Lstat(source)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("only regular, non-symlink files can be quarantined")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink > 1 {
		return nil, fmt.Errorf("refusing to quarantine a file with multiple hard links")
	}
	self, _ := os.Executable()
	if absSelf, e := filepath.Abs(self); e == nil && source == absSelf {
		return nil, fmt.Errorf("refusing to quarantine the running Agent")
	}
	if info.Size() > 512<<20 {
		return nil, fmt.Errorf("file exceeds the 512 MiB quarantine limit")
	}
	digest, err := linuxFileSHA256(source)
	if err != nil {
		return nil, err
	}
	if expected := strings.ToLower(strings.TrimSpace(asString(params["sha256"]))); expected != "" && expected != digest {
		return map[string]any{"path": source, "sha256": digest, "refused": true}, fmt.Errorf("file SHA256 changed before quarantine")
	}
	root := filepath.Join(cfg.StateDir, "quarantine")
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(random[:])
	stored := filepath.Join(root, id+".bin")
	recordPath := filepath.Join(root, id+".json")
	if err := os.Rename(source, stored); err != nil {
		if err := linuxCopyFile(source, stored, info.Mode().Perm()); err != nil {
			return nil, fmt.Errorf("move to quarantine: %w", err)
		}
		copiedDigest, err := linuxFileSHA256(stored)
		if err != nil || copiedDigest != digest {
			_ = os.Remove(stored)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("quarantine copy verification failed")
		}
		if err := os.Remove(source); err != nil {
			_ = os.Remove(stored)
			return nil, fmt.Errorf("remove quarantined source: %w", err)
		}
	}
	storedDigest, err := linuxFileSHA256(stored)
	if err != nil || storedDigest != digest {
		_ = os.Rename(stored, source)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("file changed during quarantine; original path restored")
	}
	record := linuxQuarantineRecord{
		ID: id, Original: source, Stored: stored, SHA256: digest,
		Mode: uint32(info.Mode().Perm()), Size: info.Size(), Created: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err == nil {
		err = os.WriteFile(recordPath, data, 0600)
	}
	if err != nil {
		_ = os.Rename(stored, source)
		return nil, fmt.Errorf("write quarantine metadata: %w", err)
	}
	return map[string]any{"ok": true, "quarantine_id": id, "original": source, "stored": stored, "sha256": digest}, nil
}

func linuxRestoreQuarantine(cfg Config, params map[string]any) (map[string]any, error) {
	root, err := filepath.Abs(filepath.Join(cfg.StateDir, "quarantine"))
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(asString(params["quarantine_id"]))
	if id == "" {
		return nil, fmt.Errorf("quarantine_id is required")
	}
	if len(id) != 32 {
		return nil, fmt.Errorf("invalid quarantine_id")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return nil, fmt.Errorf("invalid quarantine_id")
	}
	metaPath := filepath.Join(root, id+".json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var record linuxQuarantineRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("invalid quarantine metadata: %w", err)
	}
	stored, err := filepath.Abs(record.Stored)
	if err != nil || filepath.Dir(stored) != root || filepath.Base(stored) != id+".bin" {
		return nil, fmt.Errorf("quarantine metadata points outside the quarantine directory")
	}
	digest, err := linuxFileSHA256(stored)
	if err != nil {
		return nil, err
	}
	if digest != record.SHA256 {
		return map[string]any{"quarantine_id": id, "sha256": digest, "refused": true}, fmt.Errorf("quarantined file SHA256 mismatch")
	}
	original := filepath.Clean(record.Original)
	if !filepath.IsAbs(original) {
		return nil, fmt.Errorf("quarantine metadata has an invalid original path")
	}
	if _, err := os.Lstat(original); err == nil {
		return nil, fmt.Errorf("refusing to overwrite existing file %s", original)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(original), 0750); err != nil {
		return nil, err
	}
	if err := os.Rename(stored, original); err != nil {
		if err := linuxCopyFile(stored, original, os.FileMode(record.Mode)); err != nil {
			return nil, fmt.Errorf("restore quarantined file: %w", err)
		}
		if err := os.Remove(stored); err != nil {
			_ = os.Remove(original)
			return nil, err
		}
	}
	if err := os.Chmod(original, os.FileMode(record.Mode)); err != nil {
		return nil, fmt.Errorf("restored file but failed to restore mode: %w", err)
	}
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		return map[string]any{"ok": true, "restored": original, "quarantine_id": id}, fmt.Errorf("restored file but could not remove metadata: %w", err)
	}
	return map[string]any{"ok": true, "restored": original, "quarantine_id": id, "sha256": digest}, nil
}

func linuxFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func linuxCopyFile(source, destination string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(destination)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(destination)
		return err
	}
	return out.Close()
}
