//go:build linux

package main

import (
	"bufio"
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func startSCALoop(ctx context.Context, box *outbox, aid func() string) {
	go func() {
		recordComponentObservation("sca", cStateStarting, "Linux baseline assessment pending")
		if integrationEnabled("sca") {
			runLinuxSCA(box, aid)
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if integrationEnabled("sca") {
					runLinuxSCA(box, aid)
				}
			}
		}
	}()
}

func runLinuxSCA(box *outbox, aid func() string) {
	finishWork := beginComponentWork("sca")
	defer finishWork()
	checks := []map[string]any{
		linuxSCAPermission("sca.passwd.permissions", "Account database permissions", "/etc/passwd", 0022),
		linuxSCAPermission("sca.shadow.permissions", "Password database permissions", "/etc/shadow", 0027),
		linuxSCAPermission("sca.sudoers.permissions", "Sudo policy permissions", "/etc/sudoers", 0027),
		linuxSCAPasswordPolicy(),
		linuxSCASSHRootLogin(),
	}
	failed := make([]map[string]any, 0, len(checks))
	complete := true
	for _, check := range checks {
		if check["status"] == "fail" {
			failed = append(failed, check)
		} else if check["status"] == "unknown" {
			complete = false
		}
	}
	if complete {
		recordComponentObservation("sca", cStateHealthy, "Linux baseline checks completed")
	} else {
		recordComponentObservation("sca", cStateDegraded, "Linux baseline checks completed with unavailable inputs")
	}
	if len(failed) == 0 {
		return
	}
	log.Printf("sca: %d failed Linux baseline checks", len(failed))
	box.enqueue(outEvent, 50, map[string]any{
		"agent_id": aid(), "module": "sca", "severity": "medium",
		"title":  "Linux security configuration checks failed",
		"detail": map[string]any{"failed": failed, "count": len(failed), "platform": "linux"},
	})
}

func linuxSCAPermission(id, title, path string, writableMask os.FileMode) map[string]any {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return map[string]any{"id": id, "title": title, "status": "skip", "detail": "file not present"}
	}
	if err != nil || !info.Mode().IsRegular() {
		return map[string]any{"id": id, "title": title, "status": "unknown", "detail": "cannot inspect file"}
	}
	mode := info.Mode().Perm()
	status := "pass"
	if mode&writableMask != 0 {
		status = "fail"
	}
	return map[string]any{"id": id, "title": title, "status": status, "path": path, "mode": mode.String()}
}

func linuxSCAPasswordPolicy() map[string]any {
	file, err := os.Open("/etc/login.defs")
	if err != nil {
		return map[string]any{"id": "sca.password.max_age", "title": "Password maximum age", "status": "unknown", "detail": "cannot read /etc/login.defs"}
	}
	defer file.Close()
	maxAge := -1
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "PASS_MAX_DAYS" {
			maxAge, _ = strconv.Atoi(fields[1])
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return map[string]any{"id": "sca.password.max_age", "title": "Password maximum age", "status": "unknown", "detail": err.Error()}
	}
	if maxAge < 0 {
		return map[string]any{"id": "sca.password.max_age", "title": "Password maximum age", "status": "unknown", "detail": "PASS_MAX_DAYS is not configured"}
	}
	status := "pass"
	if maxAge == 0 || maxAge > 365 {
		status = "fail"
	}
	return map[string]any{"id": "sca.password.max_age", "title": "Password maximum age", "status": status, "max_days": maxAge}
}

func linuxSCASSHRootLogin() map[string]any {
	rootLogin := ""
	seen := make(map[string]bool)
	var scan func(string, int) error
	scan = func(path string, depth int) error {
		if depth > 8 {
			return nil
		}
		path = filepath.Clean(path)
		if seen[path] {
			return nil
		}
		seen[path] = true
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		scanner := bufio.NewScanner(file)
		inMatchBlock := false
		var scanErr error
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "match ") {
				inMatchBlock = true
				continue
			}
			if inMatchBlock {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			if strings.EqualFold(fields[0], "Include") {
				for _, pattern := range fields[1:] {
					if !filepath.IsAbs(pattern) {
						pattern = filepath.Join("/etc/ssh", pattern)
					}
					matches, globErr := filepath.Glob(pattern)
					if globErr != nil {
						scanErr = globErr
						break
					}
					for _, included := range matches {
						if scanErr = scan(included, depth+1); scanErr != nil {
							break
						}
					}
					if scanErr != nil {
						break
					}
				}
				if scanErr != nil {
					break
				}
			} else if rootLogin == "" && strings.EqualFold(fields[0], "PermitRootLogin") {
				rootLogin = strings.ToLower(fields[1])
			}
		}
		_ = file.Close()
		if scanErr != nil {
			return scanErr
		}
		return scanner.Err()
	}
	if err := scan("/etc/ssh/sshd_config", 0); err != nil {
		return map[string]any{"id": "sca.ssh.root_login", "title": "SSH root login policy", "status": "unknown", "detail": err.Error()}
	}
	if rootLogin == "" {
		return map[string]any{"id": "sca.ssh.root_login", "title": "SSH root login policy", "status": "skip", "detail": "no explicit PermitRootLogin directive"}
	}
	status := "pass"
	if rootLogin == "yes" {
		status = "fail"
	}
	return map[string]any{"id": "sca.ssh.root_login", "title": "SSH root login policy", "status": status, "value": rootLogin}
}
