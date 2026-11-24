//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

const linuxAgentUnit = "forensic-agent.service"

func isWindowsService() bool { return false }

func runAsService(cfg Config, cfgPath string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runAgent(ctx, cfg, cfgPath)
}

func installService(cfgPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install requires root; run with sudo")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfgPath) == "" {
		cfgPath = filepath.Join(filepath.Dir(exe), "agent.json")
	}
	cfgPath, err = filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read config %s: %w", cfgPath, err)
	}
	var probe struct {
		ServerURL string `json:"server_url"`
		Token     string `json:"token"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if strings.TrimSpace(probe.ServerURL) == "" || strings.TrimSpace(probe.Token) == "" {
		return fmt.Errorf("config must contain server_url and token")
	}
	unitPath := filepath.Join("/etc/systemd/system", linuxAgentUnit)
	unit := "[Unit]\nDescription=Forensic Endpoint Agent\nAfter=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\nType=simple\nExecStart=" + systemdEscape(exe) + " -config " + systemdEscape(cfgPath) +
		"\nRestart=on-failure\nRestartSec=10s\nUMask=0077\nNoNewPrivileges=true\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	if err := runSystemctl("enable", "--now", linuxAgentUnit); err != nil {
		return err
	}
	return nil
}

func uninstallService() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall requires root; run with sudo")
	}
	_ = runSystemctl("disable", "--now", linuxAgentUnit)
	path := filepath.Join("/etc/systemd/system", linuxAgentUnit)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return runSystemctl("daemon-reload")
}

func startServiceCmd() error { return runSystemctl("start", linuxAgentUnit) }
func stopServiceCmd() error  { return runSystemctl("stop", linuxAgentUnit) }

func serviceStatus() error {
	cmd := exec.Command("systemctl", "status", "--no-pager", linuxAgentUnit)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func ensureAgentKeepalive() {}

func ensureServiceRunning() error {
	if err := runSystemctl("is-active", "--quiet", linuxAgentUnit); err == nil {
		return nil
	}
	return runSystemctl("start", linuxAgentUnit)
}

func runSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), message)
	}
	return nil
}

func systemdEscape(value string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}
