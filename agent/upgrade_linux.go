//go:build linux

package main

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const linuxUpgradeMaxBytes = 80 << 20

func doUpgrade(cfg Config, params map[string]any) (map[string]any, error) {
	url := strings.TrimSpace(paramStr(params, "url"))
	wantSHA, err := normalizeUpgradeSHA256(paramStr(params, "sha256"))
	if err != nil {
		return nil, err
	}
	version := strings.TrimSpace(paramStr(params, "version"))
	if url == "" {
		return nil, fmt.Errorf("upgrade requires url")
	}
	if err := validateUpgradeURL(cfg, url); err != nil {
		return nil, err
	}
	if strings.HasPrefix(url, "/") {
		url = strings.TrimRight(cfg.ServerURL, "/") + url
		if err := validateUpgradeURL(cfg, url); err != nil {
			return nil, err
		}
	}

	setUpgradePhase("DOWNLOADING", version, "UPGRADE")
	keepUpgradePhase := false
	defer func() {
		if !keepUpgradePhase {
			clearUpgradePhase()
		}
	}()
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve current executable: %w", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}
	self, err = filepath.Abs(self)
	if err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("Linux Agent upgrade requires root to replace the installed service binary")
	}
	active := exec.Command("systemctl", "is-active", "--quiet", linuxAgentUnit)
	if err := active.Run(); err != nil {
		return nil, fmt.Errorf("%s must be active under systemd before an automatic upgrade", linuxAgentUnit)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if cfg.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Secret)
		req.Header.Set("X-Agent-Id", cfg.AgentID)
	} else if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	resp, err := upgradeHTTPClient(cfg).Do(req)
	if err != nil {
		return nil, fmt.Errorf("download upgrade package: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("upgrade download HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	dir := filepath.Dir(self)
	mode := os.FileMode(0755)
	if info, statErr := os.Stat(self); statErr == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".forensic-agent-upgrade-*.new")
	if err != nil {
		return nil, fmt.Errorf("create replacement beside executable: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(resp.Body, linuxUpgradeMaxBytes+1))
	if copyErr != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write upgrade package: %w", copyErr)
	}
	if n == 0 || n > linuxUpgradeMaxBytes {
		_ = tmp.Close()
		return nil, fmt.Errorf("upgrade package size is invalid or exceeds %d bytes", linuxUpgradeMaxBytes)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("set replacement permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("sync replacement package: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close replacement package: %w", err)
	}
	gotSHA := hex.EncodeToString(hash.Sum(nil))
	if gotSHA != wantSHA {
		return nil, fmt.Errorf("upgrade sha256 mismatch: expected %s, got %s", wantSHA[:16], gotSHA[:16])
	}
	if err := validateLinuxUpgradeBinary(tmpPath); err != nil {
		return nil, err
	}
	setUpgradePhase("VERIFYING", version, "UPGRADE")
	if err := verifyUpgradeSignature(cfg, params, gotSHA, version, n); err != nil {
		return nil, err
	}

	backup := self + ".bak"
	previousBackup := backup + ".prev"
	_ = os.Remove(previousBackup)
	if _, err := os.Stat(backup); err == nil {
		if err := os.Rename(backup, previousBackup); err != nil {
			return nil, fmt.Errorf("rotate previous upgrade backup: %w", err)
		}
	}
	if err := copyLinuxUpgradeFile(self, backup, mode); err != nil {
		return nil, fmt.Errorf("preserve current binary: %w", err)
	}
	setUpgradePhase("REPLACING", version, "UPGRADE")
	if err := os.Rename(tmpPath, self); err != nil {
		return nil, fmt.Errorf("atomically replace Agent binary: %w", err)
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}

	unit := fmt.Sprintf("forensic-agent-restart-%d", time.Now().UnixNano())
	restart := exec.Command("systemd-run", "--quiet", "--collect", "--unit="+unit,
		"--on-active=3s", "/bin/systemctl", "restart", linuxAgentUnit)
	if output, err := restart.CombinedOutput(); err != nil {
		_ = os.Rename(backup, self)
		return nil, fmt.Errorf("schedule service restart; previous binary restored: %w: %s", err, strings.TrimSpace(string(output)))
	}
	setUpgradePhase("UPGRADING", version, "UPGRADE")
	keepUpgradePhase = true
	return map[string]any{
		"ok": true, "mode": "replaced", "version": version, "bytes": n,
		"sha256": gotSHA, "bak": backup, "sig_ok": true,
		"restart_scheduled": true, "restart_delay_sec": 3,
	}, nil
}

func validateLinuxUpgradeBinary(path string) error {
	binary, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("upgrade package is not a Linux ELF executable: %w", err)
	}
	defer binary.Close()
	want := map[string]elf.Machine{
		"386": elf.EM_386, "amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64,
		"loong64": elf.EM_LOONGARCH, "riscv64": elf.EM_RISCV,
	}[runtime.GOARCH]
	if want == elf.EM_NONE {
		return fmt.Errorf("automatic Linux upgrade is not configured for architecture %s", runtime.GOARCH)
	}
	if binary.Machine != want {
		return fmt.Errorf("upgrade architecture mismatch: running %s, package ELF machine %s", runtime.GOARCH, binary.Machine)
	}
	return nil
}

func copyLinuxUpgradeFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
