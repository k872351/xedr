//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func collectSysinfo() ([]any, error) {
	info := map[string]any{
		"hostname":     hostname(),
		"os_family":    osFamily(),
		"goos":         runtime.GOOS,
		"goarch":       runtime.GOARCH,
		"ip":           primaryIP(),
		"agent_ver":    agentVersion,
		"collected_at": time.Now().Format("2006-01-02T15:04:05"),
		"num_cpu":      runtime.NumCPU(),
	}
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				key, value, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				value = strings.Trim(strings.TrimSpace(value), "\"'")
				switch key {
				case "PRETTY_NAME":
					info["os_name"] = value
				case "VERSION_ID":
					info["os_version"] = value
				}
			}
		}
		if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			info["kernel_release"] = strings.TrimSpace(string(data))
		}
	}
	return []any{info}, nil
}

func collectServices() ([]any, error) {
	return collectServicesLimited(maxItems)
}

func collectServicesLimited(limit int) ([]any, error) {
	if runtime.GOOS == "linux" {
		return collectLinuxServicesFromUnitsLimited(limit)
	}
	var raw string
	var err error
	manager := "systemctl"
	switch runtime.GOOS {
	case "linux":
		raw, err = runCmd(30*time.Second, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain")
		if err != nil {
			raw, err = runCmd(30*time.Second, "rc-status", "-a")
			manager = "rc-status"
		}
	case "darwin":
		raw, err = runCmd(30*time.Second, "launchctl", "list")
		manager = "launchctl"
	default:
		return nil, fmt.Errorf("collect services: unsupported operating system %s", runtime.GOOS)
	}
	if err != nil {
		return nil, fmt.Errorf("collect services with %s: %w", manager, err)
	}
	var out []any
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		switch manager {
		case "systemctl":
			if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
				continue
			}
			out = append(out, map[string]any{"name": fields[0], "status": fields[2], "manager": manager})
		case "rc-status":
			if len(fields) < 2 || fields[0] == "Runlevel:" {
				continue
			}
			out = append(out, map[string]any{"name": strings.TrimSuffix(fields[0], ":"), "status": strings.Trim(fields[len(fields)-1], "[]"), "manager": manager})
		case "launchctl":
			if len(fields) < 3 || fields[0] == "PID" {
				continue
			}
			out = append(out, map[string]any{"name": fields[2], "status": fields[1], "manager": manager})
		}
	}
	return truncateItemsAt(out, limit), nil
}

func collectTasks() ([]any, error) {
	if runtime.GOOS == "linux" {
		return collectLinuxTasks()
	}
	// cron 摘要：/etc/cron* 文件名列表，轻量即可
	var out []any
	for _, p := range []string{"/etc/crontab", "/etc/cron.d"} {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			ents, readErr := os.ReadDir(p)
			if readErr != nil {
				return truncateItems(out), fmt.Errorf("collect cron entries from %s: %w", p, readErr)
			}
			for _, e := range ents {
				out = append(out, map[string]any{"task_name": p + "/" + e.Name(), "status": "file"})
			}
		} else {
			out = append(out, map[string]any{"task_name": p, "status": "file"})
		}
	}
	return truncateItems(out), nil
}

func collectStartup() ([]any, error) {
	if runtime.GOOS == "linux" {
		return collectLinuxStartupEntries()
	}
	var out []any
	for _, p := range []string{"/etc/rc.local", "/etc/init.d", "/etc/systemd/system"} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, map[string]any{"location": "fs", "name": p, "command": p})
		}
	}
	return truncateItems(out), nil
}

func collectNetwork() ([]any, error) {
	if runtime.GOOS == "linux" {
		return collectLinuxNetworkProcfs()
	}
	var raw string
	var err error
	format := "netstat"
	if runtime.GOOS == "linux" {
		raw, err = runCmd(20*time.Second, "ss", "-tanp")
		if err != nil {
			raw, err = runCmd(20*time.Second, "netstat", "-tanp")
		} else {
			format = "ss"
		}
	} else {
		raw, err = runCmd(20*time.Second, "netstat", "-an", "-p", "tcp")
	}
	if err != nil {
		return nil, fmt.Errorf("collect network on %s: %w", runtime.GOOS, err)
	}
	var out []any
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "State") || strings.HasPrefix(fields[0], "Proto") || fields[0] == "Active" {
			continue
		}
		item := map[string]any{"raw": strings.Join(fields, " ")}
		if format == "ss" && len(fields) >= 6 {
			item["proto"], item["state"] = "tcp", fields[0]
			item["local"], item["remote"] = fields[4], fields[5]
		} else if len(fields) >= 5 {
			item["proto"] = fields[0]
			item["local"] = fields[3]
			item["remote"] = fields[4]
			if len(fields) > 5 {
				item["state"] = fields[5]
			}
		}
		out = append(out, item)
	}
	return truncateItems(out), nil
}

func collectProcessesLite() ([]any, error) { return collectProcesses() }
func collectFilesLite() ([]any, error)     { return collectFiles() }

func collectProcesses() ([]any, error) {
	if runtime.GOOS == "linux" {
		return collectLinuxProcessesProcfs()
	}
	raw, err := runCmd(20*time.Second, "ps", "-axo", "pid=,ppid=,user=,comm=,command=")
	if err != nil {
		return nil, fmt.Errorf("collect processes: ps: %w", err)
	}
	var out []any
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		cmd := strings.Join(fields[4:], " ")
		out = append(out, map[string]any{
			"pid":          asInt(fields[0]),
			"ppid":         asInt(fields[1]),
			"user":         fields[2],
			"name":         fields[3],
			"command_line": cmd,
		})
	}
	return truncateItems(out), nil
}

func collectFiles() ([]any, error) {
	var out []any
	accessible := 0
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		accessible++
		var walk func(string, int)
		walk = func(dir string, depth int) {
			if len(out) >= 200 || depth > 3 {
				return
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return
			}
			for _, entry := range entries {
				p := filepath.Join(dir, entry.Name())
				if entry.IsDir() {
					walk(p, depth+1)
					continue
				}
				info, err := entry.Info()
				if err != nil || !info.Mode().IsRegular() {
					continue
				}
				ext := strings.ToLower(filepath.Ext(entry.Name()))
				if ext == ".sh" || ext == ".elf" || ext == ".bin" || info.Mode().Perm()&0111 != 0 {
					out = append(out, map[string]any{"name": entry.Name(), "path": p, "size": info.Size(), "mode": info.Mode().String()})
					if len(out) >= 200 {
						break
					}
				}
			}
		}
		walk(root, 0)
		if len(out) >= 200 {
			break
		}
	}
	if accessible == 0 {
		return nil, fmt.Errorf("collect files: no supported temporary directory is accessible")
	}
	return truncateItems(out), nil
}

func collectUsers() ([]any, error) {
	return collectUsersLimited(maxItems)
}

func collectUsersLimited(limit int) ([]any, error) {
	raw, err := runCmd(10*time.Second, "who")
	if err != nil {
		return nil, fmt.Errorf("collect users: who: %w", err)
	}
	var out []any
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		out = append(out, map[string]any{
			"name":   fields[0],
			"source": "session",
			"state":  strings.Join(fields[1:], " "),
		})
	}
	return truncateItemsAt(out, limit), nil
}

func collectDrivers() ([]any, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("driver inventory unsupported on %s", runtime.GOOS)
	}
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, fmt.Errorf("read Linux kernel module inventory: %w", err)
	}
	var out []any
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		size, _ := strconv.ParseUint(fields[1], 10, 64)
		refs, _ := strconv.Atoi(fields[2])
		deps := []string{}
		if fields[3] != "-" && fields[3] != "" {
			deps = strings.Split(fields[3], ",")
		}
		item := map[string]any{
			"name": fields[0], "size_bytes": size, "ref_count": refs,
			"dependencies": deps, "state": fields[4], "address": fields[5],
			"source": "proc_modules", "type": "kernel_module",
		}
		if version, readErr := os.ReadFile(filepath.Join("/sys/module", fields[0], "version")); readErr == nil {
			item["version"] = strings.TrimSpace(string(version))
		}
		out = append(out, item)
		if len(out) >= maxItems {
			break
		}
	}
	return out, nil
}

func collectNetif() ([]any, error) {
	// Linux 网卡清单后续接 sysfs/netlink；先返回空避免资产页报失败
	return []any{}, nil
}

func collectGroups() ([]any, error) {
	return []any{}, nil
}

func collectFirewall() ([]any, error)  { return []any{}, nil }
func collectShares() ([]any, error)    { return []any{}, nil }
func collectCerts() ([]any, error)     { return []any{}, nil }
func collectUSB() ([]any, error)       { return []any{}, nil }
func collectBrowserExt() ([]any, error) { return []any{}, nil }

func filepathBase(p string) string {
	i := strings.LastIndexAny(p, `/\`)
	if i < 0 {
		return p
	}
	return p[i+1:]
}
