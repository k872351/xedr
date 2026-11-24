//go:build linux

package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func collectLinuxServicesFromUnits() ([]any, error) {
	return collectLinuxServicesFromUnitsLimited(maxItems)
}

func collectLinuxServicesFromUnitsLimited(limit int) ([]any, error) {
	roots := []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}
	enabled := linuxEnabledUnits()
	byName := make(map[string]map[string]any)
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("list systemd unit directory %s: %w", root, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".service") {
				continue
			}
			path := filepath.Join(root, name)
			masked := false
			if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
				path = resolved
				masked = resolved == os.DevNull
			}
			if _, exists := byName[name]; exists {
				continue // /etc overrides vendor unit files; first root wins.
			}
			unit := parseLinuxUnit(path)
			unit["name"] = name
			unit["path"] = path
			unit["manager"] = "systemd"
			unit["source"] = "unit_file"
			unit["enabled"] = enabled[name]
			unit["status"] = "unit_file"
			if enabled[name] {
				unit["status"] = "enabled"
			}
			if masked {
				unit["status"] = "masked"
			}
			byName[name] = unit
		}
	}
	out := make([]any, 0, len(byName))
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, byName[name])
	}
	return truncateItemsAt(out, limit), nil
}

func linuxEnabledUnits() map[string]bool {
	enabled := make(map[string]bool)
	root := "/etc/systemd/system"
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if !(strings.Contains(rel, ".wants"+string(filepath.Separator)) || strings.Contains(rel, ".requires"+string(filepath.Separator))) {
			return nil
		}
		if strings.HasSuffix(path, ".service") {
			enabled[filepath.Base(path)] = true
		}
		return nil
	})
	return enabled
}

func parseLinuxUnit(path string) map[string]any {
	result := map[string]any{}
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()
	section := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if section == "unit" && key == "description" && result["display_name"] == nil {
			result["display_name"] = value
		}
		if section == "service" {
			switch key {
			case "execstart":
				result["command"] = value
				if fields := strings.Fields(value); len(fields) > 0 {
					result["path"] = fields[0]
				}
			case "user":
				result["account"] = value
			case "workingdirectory":
				result["working_directory"] = value
			}
		}
		if section == "timer" {
			if key == "oncalendar" {
				result["on_calendar"] = value
			} else if key == "unit" {
				result["unit"] = value
			}
		}
	}
	return result
}

func collectLinuxTasks() ([]any, error) {
	var out []any
	for _, path := range []string{"/etc/crontab", "/var/spool/cron/crontabs", "/var/spool/cron"} {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue // A restricted spool must not suppress readable system schedules.
		}
		if info.IsDir() {
			entries, readErr := os.ReadDir(path)
			if readErr != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
					continue
				}
				if err := appendLinuxCronFile(filepath.Join(path, entry.Name()), entry.Name(), &out); err != nil {
					return truncateItems(out), err
				}
			}
		} else if err := appendLinuxCronFile(path, "root", &out); err != nil {
			return truncateItems(out), err
		}
	}
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			full := filepath.Join(dir, entry.Name())
			if dir == "/etc/cron.d" {
				if err := appendLinuxCronFile(full, "", &out); err != nil {
					return truncateItems(out), err
				}
			} else {
				out = append(out, map[string]any{
					"task_name": full, "path": full, "command": full,
					"schedule": strings.TrimPrefix(dir, "/etc/cron."), "source": "cron.d",
				})
			}
			if len(out) >= maxItems {
				return truncateItems(out), nil
			}
		}
	}
	for _, root := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".timer") {
				continue
			}
			path := filepath.Join(root, entry.Name())
			unit := parseLinuxUnit(path)
			out = append(out, map[string]any{
				"task_name": strings.TrimSuffix(entry.Name(), ".timer"), "path": path,
				"command": asString(unit["on_calendar"]), "schedule": asString(unit["on_calendar"]),
				"unit": asString(unit["unit"]), "source": "systemd_timer",
			})
			if len(out) >= maxItems {
				return truncateItems(out), nil
			}
		}
	}
	return truncateItems(out), nil
}

func appendLinuxCronFile(path, defaultUser string, out *[]any) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) || os.IsPermission(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open cron file %s: %w", path, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "=") && !strings.ContainsAny(line, " \t") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		isSystem := defaultUser == ""
		commandAt := 5
		if strings.HasPrefix(fields[0], "@") {
			commandAt = 1
		}
		user := defaultUser
		if isSystem {
			commandAt++
			if len(fields) > 5 {
				user = fields[5]
			}
		}
		if len(fields) <= commandAt {
			continue
		}
		scheduleEnd := commandAt
		if strings.HasPrefix(fields[0], "@") {
			scheduleEnd = 1
		}
		*out = append(*out, map[string]any{
			"task_name": fmt.Sprintf("%s:%d", filepath.Base(path), lineNo),
			"path":      path, "user": user, "schedule": strings.Join(fields[:scheduleEnd], " "),
			"command": strings.Join(fields[commandAt:], " "), "source": "cron",
		})
		if len(*out) >= maxItems {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan cron file %s: %w", path, err)
	}
	return nil
}

func collectLinuxStartupEntries() ([]any, error) {
	var out []any
	root := "/etc/systemd/system"
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasSuffix(path, ".service") &&
			(strings.Contains(rel, ".wants"+string(filepath.Separator)) || strings.Contains(rel, ".requires"+string(filepath.Separator))) {
			out = append(out, map[string]any{
				"location": rel, "name": filepath.Base(path), "command": path,
				"path": path, "status": "enabled", "source": "systemd",
			})
		}
		return nil
	})
	if entries, err := os.ReadDir("/etc/init.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join("/etc/init.d", entry.Name())
			info, statErr := entry.Info()
			if statErr == nil && info.Mode().Perm()&0111 != 0 {
				out = append(out, map[string]any{
					"location": "/etc/init.d", "name": entry.Name(), "path": path,
					"command": path, "source": "init.d",
				})
			}
		}
	}
	if data, err := os.ReadFile("/etc/rc.local"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || line == "exit 0" {
				continue
			}
			out = append(out, map[string]any{
				"location": "/etc/rc.local", "name": filepath.Base(strings.Fields(line)[0]),
				"path": "/etc/rc.local", "command": line, "source": "rc.local",
			})
			if len(out) >= maxItems {
				break
			}
		}
	}
	if entries, err := os.ReadDir("/etc/xdg/autostart"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".desktop") {
				continue
			}
			path := filepath.Join("/etc/xdg/autostart", entry.Name())
			name, command := parseLinuxDesktopEntry(path)
			out = append(out, map[string]any{
				"location": "/etc/xdg/autostart", "name": name,
				"path": path, "command": command, "source": "xdg_autostart",
			})
		}
	}
	return truncateItems(out), nil
}

func parseLinuxDesktopEntry(path string) (name, command string) {
	file, err := os.Open(path)
	if err != nil {
		return filepath.Base(path), ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 128*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "Name":
			name = value
		case "Exec":
			command = value
		}
	}
	if name == "" {
		name = filepath.Base(path)
	}
	return
}
