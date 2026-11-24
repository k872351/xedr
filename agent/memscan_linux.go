//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	linuxMemoryMaxScanBytes = 16 << 20
	linuxMemoryMaxFindings  = 50
)

var linuxMemoryScanMu sync.Mutex

type linuxMemoryProcess struct {
	pid  int
	name string
}

func scanMemory(params map[string]any) (map[string]any, error) {
	finishWork := beginComponentWork("memory_scan")
	defer finishWork()
	if !linuxMemoryScanMu.TryLock() {
		return map[string]any{"ok": false, "busy": true}, fmt.Errorf("another Linux memory scan is already running")
	}
	defer linuxMemoryScanMu.Unlock()
	settings := memoryScanSettingsSnapshot()
	mode := settings.Mode
	if override := strings.TrimSpace(asString(params["force_mode"])); override != "" {
		mode = override
	}
	if mode == memModeOff {
		return map[string]any{"ok": true, "skipped": true, "mode": mode}, nil
	}
	if mode != memModeHeuristic && !memoryScanUsesYara(settings) {
		return map[string]any{"ok": false, "mode": mode}, fmt.Errorf("unsupported memory scan mode %q", mode)
	}

	maxProcesses := settings.MaxProcesses
	if maxProcesses <= 0 {
		maxProcesses = 20
	}
	if requested := asInt(params["max_processes"]); requested > 0 && requested < maxProcesses {
		maxProcesses = requested
	}
	if maxProcesses > 80 {
		maxProcesses = 80
	}
	maxRegion := settings.MaxRegionReadKB * 1024
	if maxRegion <= 0 {
		maxRegion = 512 * 1024
	}
	if maxRegion > 4*1024*1024 {
		maxRegion = 4 * 1024 * 1024
	}
	targetPID := asInt(params["pid"])
	targetName := strings.TrimSpace(asString(params["process_name"]))
	if targetName == "" {
		targetName = strings.TrimSpace(asString(params["name"]))
	}
	if targetName != "" {
		targetName = strings.ToLower(filepath.Base(targetName))
	}
	processes, err := linuxMemoryProcesses()
	if err != nil {
		return nil, err
	}
	pidAlive := false
	for _, process := range processes {
		if process.pid == targetPID && targetPID > 0 {
			pidAlive = true
			break
		}
	}
	if targetPID > 0 && !pidAlive && targetName == "" {
		return map[string]any{"ok": false, "pid": targetPID, "scanned": 0}, fmt.Errorf("process pid=%d was not found", targetPID)
	}
	if targetPID > 0 && !pidAlive && targetName != "" {
		targetPID = 0
	}

	findings := make([]map[string]any, 0)
	matchedPIDs := make([]int, 0)
	scanned, denied := 0, 0
	for _, process := range processes {
		if process.pid == os.Getpid() || process.pid <= 1 {
			continue
		}
		if targetPID > 0 && pidAlive && process.pid != targetPID {
			continue
		}
		if targetPID == 0 && targetName != "" && !linuxMemoryNameMatches(process.name, targetName) {
			continue
		}
		if targetPID == 0 && scanned >= maxProcesses {
			break
		}
		processHits, bytesRead, scanErr := scanLinuxProcessMemory(process, maxRegion, linuxMemoryMaxScanBytes, mode)
		if scanErr != nil {
			denied++
			continue
		}
		scanned++
		matchedPIDs = append(matchedPIDs, process.pid)
		for _, hit := range processHits {
			hit["pid"] = process.pid
			hit["name"] = process.name
			findings = append(findings, hit)
			if len(findings) >= linuxMemoryMaxFindings {
				break
			}
		}
		_ = bytesRead
		if len(findings) >= linuxMemoryMaxFindings {
			break
		}
	}
	if scanned == 0 && (targetPID > 0 || targetName != "") {
		reason := fmt.Sprintf("unable to read process memory (permission or process-exit; denied=%d)", denied)
		recordComponentObservation("memory_scan", cStateDegraded, reason)
		return map[string]any{"ok": false, "pid": targetPID, "process_name": targetName, "scanned": 0, "access_denied": denied}, fmt.Errorf("%s", reason)
	}
	if scanned == 0 {
		recordComponentObservation("memory_scan", cStateDegraded, fmt.Sprintf("no process memory regions were readable; denied=%d", denied))
	} else {
		recordComponentObservation("memory_scan", cStateHealthy, fmt.Sprintf("scanned %d process address spaces; %d inaccessible", scanned, denied))
	}
	memRulesMu.RLock()
	rulesRev := memRulesRev
	memRulesMu.RUnlock()
	result := map[string]any{
		"ok": true, "mode": mode, "yara_engine": yaraEngineOK, "rules_rev": rulesRev,
		"trigger": asString(params["trigger"]), "scanned": scanned, "access_denied": denied,
		"integrity_scanned": 0, "findings": findings, "finding_count": len(findings),
		"matched_pids": matchedPIDs, "ts": time.Now().Format(time.RFC3339),
		"platform": runtime.GOOS,
	}
	if targetPID > 0 {
		result["requested_pid"] = targetPID
		if !pidAlive && targetName != "" {
			result["pid_fallback"] = "process_name"
		}
	}
	if targetName != "" {
		result["process_name"] = targetName
	}
	return result, nil
}

func linuxMemoryProcesses() ([]linuxMemoryProcess, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}
	processes := make([]linuxMemoryProcess, 0, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		nameBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(nameBytes))
		if name == "" {
			continue
		}
		processes = append(processes, linuxMemoryProcess{pid: pid, name: name})
	}
	return processes, nil
}

func linuxMemoryNameMatches(have, want string) bool {
	a := strings.ToLower(filepath.Base(strings.TrimSpace(have)))
	b := strings.ToLower(filepath.Base(strings.TrimSpace(want)))
	return a != "" && b != "" && (a == b || strings.TrimSuffix(a, ".exe") == strings.TrimSuffix(b, ".exe"))
}

func scanLinuxProcessMemory(process linuxMemoryProcess, maxRegion, maxTotal int, mode string) ([]map[string]any, int, error) {
	base := filepath.Join("/proc", strconv.Itoa(process.pid))
	mapsBytes, err := os.ReadFile(filepath.Join(base, "maps"))
	if err != nil {
		return nil, 0, err
	}
	mem, err := os.Open(filepath.Join(base, "mem"))
	if err != nil {
		return nil, 0, err
	}
	defer mem.Close()
	useHeuristic := mode == memModeHeuristic || !memoryScanUsesYara(memoryScanSettingsSnapshot())
	useRules := mode == memModeHeuristic || memoryScanUsesYara(memoryScanSettingsSnapshot())
	findings := make([]map[string]any, 0)
	bytesRead := 0
	for _, line := range strings.Split(string(mapsBytes), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(fields[1], "r") {
			continue
		}
		if strings.HasPrefix(fields[len(fields)-1], "[") && fields[len(fields)-1] != "[heap]" && fields[len(fields)-1] != "[stack]" {
			continue
		}
		span := strings.SplitN(fields[0], "-", 2)
		if len(span) != 2 {
			continue
		}
		start, startErr := strconv.ParseUint(span[0], 16, 64)
		end, endErr := strconv.ParseUint(span[1], 16, 64)
		if startErr != nil || endErr != nil || end <= start {
			continue
		}
		size := int(end - start)
		if size < 64 {
			continue
		}
		remaining := maxTotal - bytesRead
		if remaining <= 0 {
			break
		}
		readSize := size
		if readSize > maxRegion {
			readSize = maxRegion
		}
		if readSize > remaining {
			readSize = remaining
		}
		chunk := make([]byte, readSize)
		n, readErr := mem.ReadAt(chunk, int64(start))
		if readErr != nil && n < 64 {
			continue
		}
		if n < 64 {
			continue
		}
		chunk = chunk[:n]
		bytesRead += n
		address := fmt.Sprintf("0x%x", start)
		if useHeuristic {
			lower := strings.ToLower(string(chunk))
			for _, signature := range []string{"meterpreter", "reflective loader"} {
				if strings.Contains(lower, signature) {
					findings = append(findings, map[string]any{
						"type": "suspicious_string", "sig": signature, "address": address,
						"severity": "high", "engine": "heuristic",
						"summary": fmt.Sprintf("suspicious memory string [%s]: %s pid=%d", signature, process.name, process.pid),
					})
					break
				}
			}
		}
		if useRules {
			for _, hit := range matchJSONMemoryRules(chunk) {
				hit["address"] = address
				if hit["summary"] == nil {
					hit["summary"] = fmt.Sprintf("memory rule hit [%s]: %s pid=%d", hit["rule_id"], process.name, process.pid)
				}
				findings = append(findings, hit)
			}
		}
		if memoryScanUsesYara(memoryScanSettingsSnapshot()) && yaraEngineOK {
			for _, hit := range scanYaraOnRegion(chunk, uintptr(start), uint32(process.pid), process.name) {
				findings = append(findings, hit)
			}
		}
		if len(findings) >= linuxMemoryMaxFindings {
			break
		}
	}
	return findings, bytesRead, nil
}

func runIntegritySweep() map[string]any {
	return map[string]any{"ok": true, "skipped": true, "reason": "Linux executable integrity sweep is not implemented"}
}
