//go:build linux

package main

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// collectLinuxProcessesProcfs reads process data from procfs so collection does
// not depend on procps/ps being installed or localized command output.
func collectLinuxProcessesProcfs() ([]any, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc process list: %w", err)
	}
	out := make([]any, 0, len(entries))
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		stat, readErr := os.ReadFile(filepath.Join(base, "stat"))
		if readErr != nil { // Process exited or became inaccessible during collection.
			continue
		}
		statText := strings.TrimSpace(string(stat))
		open, close := strings.IndexByte(statText, '('), strings.LastIndexByte(statText, ')')
		if open < 0 || close <= open || close+2 >= len(statText) {
			continue
		}
		name := strings.TrimSpace(statText[open+1 : close])
		fields := strings.Fields(statText[close+1:])
		if name == "" || len(fields) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1]) // fields start at kernel stat field 3 (state).
		item := map[string]any{
			"pid": pid, "ppid": ppid, "name": name, "process_name": name,
			"state": fields[0], "source": "procfs",
		}
		if cmdline, readErr := os.ReadFile(filepath.Join(base, "cmdline")); readErr == nil && len(cmdline) > 0 {
			command := strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " "))
			if command != "" {
				if len(command) > 4096 {
					command = command[:4096]
				}
				item["command_line"] = command
				item["command"] = command
			}
		}
		if exe, readErr := os.Readlink(filepath.Join(base, "exe")); readErr == nil {
			item["path"] = exe
			item["image"] = exe
		}
		if status, readErr := os.ReadFile(filepath.Join(base, "status")); readErr == nil {
			for _, line := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(line, "Uid:") {
					ids := strings.Fields(strings.TrimPrefix(line, "Uid:"))
					if len(ids) > 0 {
						item["uid"] = ids[0]
						item["user"] = ids[0]
					}
				}
				if strings.HasPrefix(line, "VmRSS:") {
					values := strings.Fields(strings.TrimPrefix(line, "VmRSS:"))
					if len(values) > 0 {
						if kb, parseErr := strconv.ParseUint(values[0], 10, 64); parseErr == nil {
							item["memory_mb"] = float64(kb) / 1024
						}
					}
				}
			}
		}
		out = append(out, item)
		if len(out) >= maxItems {
			break
		}
	}
	if len(out) == 0 {
		return out, nil // Empty is a valid result on restricted procfs mounts.
	}
	return truncateItems(out), nil
}

func collectLinuxNetworkProcfs() ([]any, error) {
	files := []struct {
		path  string
		proto string
		bits  int
	}{
		{"/proc/net/tcp", "tcp", 32}, {"/proc/net/tcp6", "tcp6", 128},
		{"/proc/net/udp", "udp", 32}, {"/proc/net/udp6", "udp6", 128},
	}
	out := make([]any, 0, 64)
	readable := 0
	for _, source := range files {
		data, err := os.ReadFile(source.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read Linux network table %s: %w", source.path, err)
		}
		readable++
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] { // First row is the procfs column header.
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			local, localPort, okLocal := parseProcNetEndpoint(fields[1], source.bits)
			remote, remotePort, okRemote := parseProcNetEndpoint(fields[2], source.bits)
			if !okLocal || !okRemote {
				continue
			}
			state := procNetState(fields[3], source.proto)
			item := map[string]any{
				"proto": source.proto, "protocol": source.proto,
				"local": local, "local_ip": local, "local_port": localPort,
				"remote": remote, "remote_ip": remote, "remote_port": remotePort,
				"state": state, "uid": fields[7], "inode": fields[9], "source": "procfs",
			}
			out = append(out, item)
			if len(out) >= maxItems {
				return out, nil
			}
		}
	}
	if readable == 0 {
		return nil, fmt.Errorf("Linux network tables are unavailable under /proc/net")
	}
	return out, nil
}

func parseProcNetEndpoint(raw string, bits int) (string, int, bool) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return "", 0, false
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, false
	}
	addrBytes, err := hex.DecodeString(parts[0])
	if err != nil || len(addrBytes)*8 != bits {
		return "", 0, false
	}
	if bits == 32 {
		for left, right := 0, len(addrBytes)-1; left < right; left, right = left+1, right-1 {
			addrBytes[left], addrBytes[right] = addrBytes[right], addrBytes[left]
		}
	} else {
		// Linux renders each 32-bit word in host byte order in /proc/net/tcp6.
		for i := 0; i < len(addrBytes); i += 4 {
			addrBytes[i], addrBytes[i+3] = addrBytes[i+3], addrBytes[i]
			addrBytes[i+1], addrBytes[i+2] = addrBytes[i+2], addrBytes[i+1]
		}
	}
	var addr netip.Addr
	if bits == 32 {
		var raw [4]byte
		copy(raw[:], addrBytes)
		addr = netip.AddrFrom4(raw)
	} else {
		var raw [16]byte
		copy(raw[:], addrBytes)
		addr = netip.AddrFrom16(raw)
	}
	return addr.String(), int(port), true
}

func procNetState(raw, proto string) string {
	if proto == "udp" || proto == "udp6" {
		return "open"
	}
	states := map[string]string{
		"01": "established", "02": "syn_sent", "03": "syn_recv", "04": "fin_wait1",
		"05": "fin_wait2", "06": "time_wait", "07": "closed", "08": "close_wait",
		"09": "last_ack", "0A": "listen", "0B": "closing",
	}
	if state := states[strings.ToUpper(raw)]; state != "" {
		return state
	}
	return "unknown"
}
