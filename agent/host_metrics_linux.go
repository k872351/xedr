//go:build linux

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	linuxHostMetricsMu sync.Mutex
	linuxHostMetrics   map[string]any
	linuxHostMetricsAt time.Time
)

// hostMetricsSnapshot exposes low-cost Linux host metrics from procfs and statfs.
// The short cache prevents health heartbeats from repeatedly scanning mounts.
func hostMetricsSnapshot() map[string]any {
	linuxHostMetricsMu.Lock()
	defer linuxHostMetricsMu.Unlock()
	if linuxHostMetrics != nil && time.Since(linuxHostMetricsAt) < 45*time.Second {
		return cloneAnyMap(linuxHostMetrics)
	}

	out := map[string]any{"platform": "linux"}
	if uptime, err := readLinuxUptime(); err == nil {
		out["uptime_sec"] = uptime
	} else {
		out["uptime_error"] = err.Error()
	}
	if load, err := readLinuxLoadAverage(); err == nil {
		out["load_avg_1"] = load[0]
		out["load_avg_5"] = load[1]
		out["load_avg_15"] = load[2]
	} else {
		out["load_error"] = err.Error()
	}
	if mem := readLinuxMemory(); mem != nil {
		out["memory"] = mem
	}
	if disks := readLinuxDiskVolumes(); len(disks) > 0 {
		out["disks"] = disks
	}
	if net := readLinuxNetIO(); net != nil {
		out["net_io"] = net
	}
	if conns, err := collectLinuxNetworkProcfs(); err == nil {
		out["connections_sample"] = map[string]any{"count": len(conns), "note": "procfs socket table"}
	} else {
		out["connections_sample"] = map[string]any{"error": err.Error()}
	}
	linuxHostMetrics = out
	linuxHostMetricsAt = time.Now()
	return cloneAnyMap(out)
}

func cloneAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func readLinuxUptime() (float64, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, os.ErrInvalid
	}
	return strconv.ParseFloat(fields[0], 64)
}

func readLinuxLoadAverage() ([3]float64, error) {
	var out [3]float64
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return out, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return out, os.ErrInvalid
	}
	for i := range out {
		out[i], err = strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return [3]float64{}, err
		}
	}
	return out, nil
}

func readLinuxMemory() map[string]any {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	values := map[string]uint64{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.Fields(s.Text())
		if len(parts) < 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(parts[1], 10, 64)
		if parseErr == nil {
			values[strings.TrimSuffix(parts[0], ":")] = value * 1024
		}
	}
	total := values["MemTotal"]
	available, ok := values["MemAvailable"]
	if !ok {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	if total == 0 {
		return nil
	}
	usedPct := float64(total-minUint64(available, total)) * 100 / float64(total)
	return map[string]any{
		"total_bytes": total, "available_bytes": available,
		"used_pct": round1(usedPct),
	}
}

func readLinuxDiskVolumes() []map[string]any {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	out := make([]map[string]any, 0, 8)
	s := bufio.NewScanner(f)
	for s.Scan() && len(out) < 32 {
		fields := strings.Fields(s.Text())
		if len(fields) < 3 {
			continue
		}
		mount, fsType := unescapeLinuxMount(fields[1]), fields[2]
		if seen[mount] || linuxPseudoFilesystem(fsType) {
			continue
		}
		seen[mount] = true
		var st unix.Statfs_t
		if unix.Statfs(mount, &st) != nil || st.Bsize <= 0 {
			continue
		}
		blockSize := uint64(st.Bsize)
		total := uint64(st.Blocks) * blockSize
		available := uint64(st.Bavail) * blockSize
		free := uint64(st.Bfree) * blockSize
		usedPct := 0.0
		if total > 0 {
			used := total - minUint64(free, total)
			usedPct = float64(used) * 100 / float64(total)
		}
		out = append(out, map[string]any{
			"mount": mount, "total_bytes": total, "free_bytes": available,
			"used_pct": round1(usedPct), "filesystem": fsType,
		})
	}
	return out
}

func linuxPseudoFilesystem(fsType string) bool {
	switch fsType {
	case "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs", "pstore", "debugfs", "tracefs", "configfs", "mqueue", "hugetlbfs", "fusectl", "rpc_pipefs", "autofs":
		return true
	default:
		return false
	}
}

func unescapeLinuxMount(value string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(value)
}

func readLinuxNetIO() map[string]any {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()
	var inBytes, outBytes, inErrors, outErrors, inDropped, outDropped uint64
	interfaces := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 16 {
			continue
		}
		v := make([]uint64, 16)
		valid := true
		for i := range v {
			v[i], err = strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		interfaces++
		inBytes += v[0]
		inErrors += v[2]
		inDropped += v[3]
		outBytes += v[8]
		outErrors += v[10]
		outDropped += v[11]
	}
	if interfaces == 0 {
		return nil
	}
	return map[string]any{
		"nic_in_bytes": inBytes, "nic_out_bytes": outBytes, "nic_in_errors": inErrors,
		"nic_out_errors": outErrors, "nic_in_dropped": inDropped, "nic_out_dropped": outDropped,
		"nic_ifaces": interfaces, "counter_scope": "all_interfaces_including_loopback",
	}
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
