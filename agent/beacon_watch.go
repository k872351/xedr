package main

import (
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

// beaconWatch：对周期性外联做轻量抖动分析（Agent 侧），命中后发 beacon_like。

const (
	beaconWindow     = 30 * time.Minute
	beaconMinSamples = 5
	beaconMaxCV      = 0.35 // 间隔变异系数低于此视为准周期
	beaconMinMeanSec = 20.0
	beaconMaxMeanSec = 3600.0
	beaconEmitCool   = 30 * time.Minute
)

type beaconSlot struct {
	times   []time.Time
	proc    string
	pid     uint32
	entity  string
	path    string
	host    string
	lastEmit time.Time
}

type beaconWatcher struct {
	mu    sync.Mutex
	slots map[string]*beaconSlot
	emit  func(map[string]any)
}

var beaconWatch = &beaconWatcher{slots: map[string]*beaconSlot{}}

func (w *beaconWatcher) setEmit(fn func(map[string]any)) {
	w.mu.Lock()
	w.emit = fn
	w.mu.Unlock()
}

func (w *beaconWatcher) observeNet(detail map[string]any, at time.Time) {
	remote := asString(detail["remote"])
	if remote == "" {
		remote = asString(detail["dest"])
	}
	host, port := splitHostPort(remote)
	if host == "" || isPrivateOrLocalHost(host) {
		return
	}
	w.observe(keyFromDetail(detail, host, port), host, detail, at)
}

func (w *beaconWatcher) observeHTTP(detail map[string]any, at time.Time) {
	host := strings.ToLower(asString(detail["host"]))
	port := asString(detail["port"])
	if host == "" || isPrivateOrLocalHost(host) {
		return
	}
	if httpBrowserNoise(asString(detail["process_name"])) {
		return
	}
	w.observe(keyFromDetail(detail, host, port), host, detail, at)
}

func keyFromDetail(detail map[string]any, host, port string) string {
	ent := asString(detail["entity_id"])
	if ent == "" {
		ent = fmt.Sprintf("pid:%v", detail["pid"])
	}
	return ent + "|" + host + "|" + port
}

func (w *beaconWatcher) observe(key, host string, detail map[string]any, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.slots[key]
	if s == nil {
		s = &beaconSlot{host: host}
		w.slots[key] = s
	}
	s.proc = asString(detail["process_name"])
	if s.proc == "" {
		s.proc = asString(detail["name"])
	}
	s.path = asString(detail["path"])
	if s.path == "" {
		s.path = asString(detail["process_path"])
	}
	if pid, ok := detail["pid"].(uint32); ok {
		s.pid = pid
	} else if pid, ok := toUint32(detail["pid"]); ok {
		s.pid = pid
	}
	s.entity = asString(detail["entity_id"])
	s.times = append(s.times, at)
	cut := at.Add(-beaconWindow)
	i := 0
	for i < len(s.times) && s.times[i].Before(cut) {
		i++
	}
	if i > 0 {
		s.times = append([]time.Time{}, s.times[i:]...)
	}
	if len(s.times) > 64 {
		s.times = s.times[len(s.times)-64:]
	}
	if len(s.times) < beaconMinSamples {
		return
	}
	if !s.lastEmit.IsZero() && at.Sub(s.lastEmit) < beaconEmitCool {
		return
	}
	mean, cv, ok := intervalStats(s.times)
	if !ok || cv > beaconMaxCV || mean < beaconMinMeanSec || mean > beaconMaxMeanSec {
		return
	}
	s.lastEmit = at
	emit := w.emit
	proc, pid, path, entity, n := s.proc, s.pid, s.path, s.entity, len(s.times)
	hostOut := s.host
	if emit == nil {
		return
	}
	sev := "medium"
	if pathLooksHot(path) || cv <= 0.15 {
		sev = "high"
	}
	detailOut := map[string]any{
		"host": hostOut, "pid": pid, "process_name": proc, "path": path,
		"entity_id": entity, "samples": n, "mean_interval_sec": round2(mean),
		"jitter_cv": round2(cv), "window_min": int(beaconWindow.Minutes()),
		"mitre": []string{"T1071"}, "evidence": "同一进程对同一目的地出现准周期外联",
	}
	sum := fmt.Sprintf("疑似Beacon外联: %s → %s (间隔≈%.0fs, CV=%.2f, n=%d)", nameOr2(proc, pid), hostOut, mean, cv, n)
	go emit(map[string]any{
		"etype": "beacon_like", "summary": sum, "severity": sev,
		"ts": at.Format("2006-01-02T15:04:05"), "detail": detailOut,
	})
}

func intervalStats(ts []time.Time) (mean, cv float64, ok bool) {
	if len(ts) < 2 {
		return 0, 0, false
	}
	var gaps []float64
	for i := 1; i < len(ts); i++ {
		g := ts[i].Sub(ts[i-1]).Seconds()
		if g < 1 {
			continue
		}
		gaps = append(gaps, g)
	}
	if len(gaps) < beaconMinSamples-1 {
		return 0, 0, false
	}
	var sum float64
	for _, g := range gaps {
		sum += g
	}
	mean = sum / float64(len(gaps))
	if mean <= 0 {
		return 0, 0, false
	}
	var varSum float64
	for _, g := range gaps {
		d := g - mean
		varSum += d * d
	}
	std := math.Sqrt(varSum / float64(len(gaps)))
	cv = std / mean
	return mean, cv, true
}

func splitHostPort(remote string) (string, string) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", ""
	}
	if strings.HasPrefix(remote, "[") {
		if host, port, err := net.SplitHostPort(remote); err == nil {
			return strings.ToLower(host), port
		}
	}
	if host, port, err := net.SplitHostPort(remote); err == nil {
		return strings.ToLower(host), port
	}
	if i := strings.LastIndex(remote, ":"); i > 0 {
		return strings.ToLower(remote[:i]), remote[i+1:]
	}
	return strings.ToLower(remote), ""
}

func isPrivateOrLocalHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}

func httpBrowserNoise(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome.exe", "msedge.exe", "msedgewebview2.exe", "firefox.exe", "iexplore.exe",
		"brave.exe", "opera.exe", "vivaldi.exe", "safari.exe", "outlook.exe",
		"teams.exe", "ms-teams.exe", "slack.exe", "discord.exe", "searchhost.exe",
		"runtimebroker.exe", "svchost.exe", "systemsettings.exe":
		return true
	default:
		return false
	}
}

func toUint32(v any) (uint32, bool) {
	switch n := v.(type) {
	case uint32:
		return n, true
	case int:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case float64:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	default:
		return 0, false
	}
}
