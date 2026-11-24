//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// processUsage reads this Agent's own CPU time, resident pages, and file
// descriptor count from procfs. Linux procfs CPU fields use USER_HZ ticks.
func processUsage() (cpu100ns uint64, rss uint64, handles uint32) {
	if raw, err := os.ReadFile("/proc/self/stat"); err == nil {
		line := string(raw)
		if end := strings.LastIndexByte(line, ')'); end >= 0 && end+1 < len(line) {
			fields := strings.Fields(line[end+1:]) // starts with field 3 (state)
			if len(fields) > 12 {
				userTicks, userErr := strconv.ParseUint(fields[11], 10, 64)     // field 14
				systemTicks, systemErr := strconv.ParseUint(fields[12], 10, 64) // field 15
				if userErr == nil && systemErr == nil {
					cpu100ns = (userTicks + systemTicks) * 100000 // USER_HZ = 100
				}
			}
		}
	}
	if raw, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) > 1 {
			if residentPages, parseErr := strconv.ParseUint(fields[1], 10, 64); parseErr == nil {
				rss = residentPages * uint64(os.Getpagesize())
			}
		}
	}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		handles = uint32(len(entries))
		if handles > 0 { // exclude the descriptor opened by ReadDir itself
			handles--
		}
	}
	return cpu100ns, rss, handles
}
