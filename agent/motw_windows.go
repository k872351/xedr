//go:build windows

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// motwInfo Mark-of-the-Web（Zone.Identifier ADS）。
type motwInfo struct {
	ZoneID     int
	Referrer   string
	HostURL    string
	Present    bool
	CheckedAt  time.Time
}

type motwCacheEntry struct {
	info    motwInfo
	size    int64
	mod     time.Time
	touched time.Time
}

var (
	motwMu    sync.Mutex
	motwCache = map[string]*motwCacheEntry{}
)

const motwCacheMax = 2048

func motwOf(path string) motwInfo {
	path = strings.TrimSpace(path)
	if path == "" {
		return motwInfo{}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return motwInfo{}
	}
	key := strings.ToLower(path)
	motwMu.Lock()
	if e, ok := motwCache[key]; ok && e.size == fi.Size() && e.mod.Equal(fi.ModTime()) {
		e.touched = time.Now()
		info := e.info
		motwMu.Unlock()
		return info
	}
	motwMu.Unlock()

	info := readMOTW(path)
	info.CheckedAt = time.Now()
	motwMu.Lock()
	if len(motwCache) >= motwCacheMax {
		var oldK string
		var oldT time.Time
		for k, e := range motwCache {
			if oldK == "" || e.touched.Before(oldT) {
				oldK, oldT = k, e.touched
			}
		}
		delete(motwCache, oldK)
	}
	motwCache[key] = &motwCacheEntry{info: info, size: fi.Size(), mod: fi.ModTime(), touched: time.Now()}
	motwMu.Unlock()
	return info
}

func readMOTW(path string) motwInfo {
	// NTFS ADS：path:Zone.Identifier
	f, err := os.Open(path + ":Zone.Identifier")
	if err != nil {
		return motwInfo{}
	}
	defer f.Close()
	info := motwInfo{Present: true, ZoneID: -1}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024), 16<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "zoneid":
			if n, e := strconv.Atoi(v); e == nil {
				info.ZoneID = n
			}
		case "referrerurl":
			info.Referrer = v
		case "hosturl":
			info.HostURL = v
		}
	}
	return info
}

func motwZoneLabel(z int) string {
	switch z {
	case 0:
		return "local_machine"
	case 1:
		return "local_intranet"
	case 2:
		return "trusted_sites"
	case 3:
		return "internet"
	case 4:
		return "restricted"
	default:
		return "unknown"
	}
}
