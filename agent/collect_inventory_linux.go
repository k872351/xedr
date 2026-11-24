//go:build linux

package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func collectHotfix() ([]any, error) {
	return collectHotfixLimited(maxItems)
}

func collectHotfixLimited(limit int) ([]any, error) {
	paths := []string{
		"/var/log/dpkg.log",
		"/var/log/dpkg.log.1",
		"/var/log/dpkg.log.2.gz",
		"/var/log/dpkg.log.3.gz",
		"/var/log/dpkg.log.4.gz",
	}
	var out []any
	available := false
	for _, path := range paths {
		rows, ok, err := readDpkgUpdateLogLimited(path, limit+1)
		if err != nil {
			return nil, err
		}
		available = available || ok
		if len(rows) > limit {
			return nil, fmt.Errorf("package update source exceeds inventory budget")
		}
		out = append(out, rows...)
	}
	for _, path := range []string{"/var/log/dnf.rpm.log", "/var/log/yum.log"} {
		rows, ok, err := readRPMUpdateLogLimited(path, limit+1)
		if err != nil {
			return nil, err
		}
		available = available || ok
		if len(rows) > limit {
			return nil, fmt.Errorf("package update source exceeds inventory budget")
		}
		out = append(out, rows...)
	}
	if !available {
		return nil, fmt.Errorf("Linux package update history is unavailable (dpkg/dnf/yum logs not found)")
	}
	return dedupeLinuxPackageUpdatesLimited(out, limit), nil
}

func readRPMUpdateLog(path string) ([]any, bool, error) {
	return readRPMUpdateLogLimited(path, maxItems)
}

func readRPMUpdateLogLimited(path string, limit int) ([]any, bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("open package update history %s: %w", path, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	var out []any
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		for i, field := range fields {
			action := strings.ToLower(strings.TrimSuffix(field, ":"))
			if action != "upgrade" && action != "updated" && action != "upgraded" {
				continue
			}
			nevra := strings.Trim(strings.TrimSuffix(field, ":"), "[](),")
			if strings.EqualFold(nevra, action) && i+1 < len(fields) {
				nevra = strings.Trim(fields[i+1], "[](),")
			}
			name, version, release, arch := splitLinuxNEVRA(nevra)
			if name == "" {
				continue
			}
			timestampFields := fields[:i]
			if len(timestampFields) > 2 {
				timestampFields = timestampFields[:2]
			}
			installedOn := strings.Join(timestampFields, " ")
			out = append(out, map[string]any{
				"package": name, "old_version": "", "new_version": strings.Trim(strings.Join([]string{version, release}, "-"), "-"),
				"architecture": arch, "installed_on": installedOn,
				"source": filepath.Base(path), "inventory": "package_update",
			})
			break
		}
		if len(out) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, true, fmt.Errorf("scan package update history %s: %w", path, err)
	}
	return out, true, nil
}

func splitLinuxNEVRA(value string) (name, version, release, arch string) {
	value = strings.Trim(value, "[](),")
	if dot := strings.LastIndex(value, "."); dot > strings.LastIndex(value, "-") {
		arch = value[dot+1:]
		value = value[:dot]
	}
	releaseAt := strings.LastIndex(value, "-")
	if releaseAt <= 0 || releaseAt == len(value)-1 {
		return "", "", "", ""
	}
	release = value[releaseAt+1:]
	value = value[:releaseAt]
	versionAt := strings.LastIndex(value, "-")
	if versionAt <= 0 || versionAt == len(value)-1 {
		return "", "", "", ""
	}
	name, version = value[:versionAt], value[versionAt+1:]
	return
}

func readDpkgUpdateLog(path string) ([]any, bool, error) {
	return readDpkgUpdateLogLimited(path, maxItems)
}

func readDpkgUpdateLogLimited(path string, limit int) ([]any, bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("open package update history %s: %w", path, err)
	}
	defer file.Close()
	var reader io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return nil, true, fmt.Errorf("read compressed package update history %s: %w", path, err)
		}
		defer gz.Close()
		reader = gz
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	var out []any
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || (fields[2] != "upgrade" && fields[2] != "install") {
			continue
		}
		pkg := fields[3]
		oldVersion, newVersion := "", ""
		if fields[2] == "upgrade" && len(fields) >= 6 {
			oldVersion, newVersion = fields[len(fields)-2], fields[len(fields)-1]
		} else {
			newVersion = fields[len(fields)-1]
		}
		out = append(out, map[string]any{
			"package": pkg, "old_version": oldVersion, "new_version": newVersion,
			"installed_on": fields[0] + " " + fields[1], "source": filepath.Base(path),
			"inventory": "package_update",
		})
		if len(out) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, true, fmt.Errorf("scan package update history %s: %w", path, err)
	}
	return out, true, nil
}

func dedupeLinuxPackageUpdates(items []any) []any {
	return dedupeLinuxPackageUpdatesLimited(items, maxItems)
}

func dedupeLinuxPackageUpdatesLimited(items []any, limit int) []any {
	seen := make(map[string]bool, len(items))
	out := make([]any, 0, len(items))
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		key := strings.Join([]string{
			asString(row["package"]), asString(row["new_version"]), asString(row["installed_on"]),
		}, "|")
		if key == "||" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func collectListen() ([]any, error) { return collectNetwork() }
