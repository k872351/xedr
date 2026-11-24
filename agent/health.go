package main

import (
	"os"
	"runtime"
	"sync"
	"time"
)

// healthCollector 采集 Agent 自身资源/队列/传感器状态，随心跳上报，
// 让管理台能区分"Agent 活着但已经卡死/丢数据"与"一切正常"。
type healthCollector struct {
	mu         sync.Mutex
	started    time.Time
	cpuSampler resourceCPUSampler
	sensorsFn  func() map[string]any
	authMode   func() string
	protoFn    func() int
}

func newHealthCollector() *healthCollector {
	h := &healthCollector{started: time.Now()}
	cpu, _, _ := processUsage()
	h.cpuSampler.update(cpu, time.Now(), runtime.NumCPU())
	return h
}

func (h *healthCollector) snapshot(box *outbox) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()

	nativeStart := time.Now()
	cpu, rss, handles := processUsage()
	now := time.Now()
	nativeTiming := measureDiagnostic(nativeStart, now, (runtime.GOOS == "windows" || runtime.GOOS == "linux") && (cpu > 0 || rss > 0 || handles > 0))
	cpuPct, cpuValid := h.cpuSampler.update(cpu, now, runtime.NumCPU())
	var ms runtime.MemStats
	heapStart := time.Now()
	runtime.ReadMemStats(&ms)
	heapTiming := measureDiagnostic(heapStart, time.Now(), true)

	out := map[string]any{
		"cpu_pct":                   cpuPct,
		"rss_mb":                    round1(float64(rss) / (1 << 20)),
		"heap_mb":                   round1(float64(ms.HeapAlloc) / (1 << 20)),
		"goroutines":                runtime.NumGoroutine(),
		"handles":                   handles,
		"uptime_sec":                int(now.Sub(h.started).Seconds()),
		"pid":                       os.Getpid(),
		"version":                   agentVersion,
		"build_id":                  buildID,
		"num_cpu":                   runtime.NumCPU(),
		"resource_metrics_platform": runtime.GOOS,
		"diagnostic_timings": map[string]any{
			"process_resources": nativeTiming.fields(),
			"go_runtime":        heapTiming.fields(),
		},
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		out["cpu_pct"] = nil
		out["rss_mb"] = nil
		out["handles"] = nil
	}
	if !cpuValid {
		out["cpu_pct"] = nil
	}
	if rss == 0 {
		out["rss_mb"] = nil
	}
	if handles == 0 {
		out["handles"] = nil
	}
	if box != nil {
		out["outbox"] = box.stats()
	}
	if h.sensorsFn != nil {
		out["sensors"] = h.sensorsFn()
	}
	if h.authMode != nil {
		out["auth"] = h.authMode()
	}
	if h.protoFn != nil {
		out["protocol"] = h.protoFn()
	}
	return out
}
