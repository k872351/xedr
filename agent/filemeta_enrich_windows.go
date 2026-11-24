//go:build windows

package main

import (
	"strings"
	"sync"
	"time"
)

// attachFileMeta 向 detail 写入 PE 静态元数据与 MOTW；path 为空时尝试 detail["path"]。
// 热路径应优先用 attachFileMetaCached；本函数可触发磁盘解析。
func attachFileMeta(detail map[string]any, path string) {
	if detail == nil {
		return
	}
	if path == "" {
		path = asString(detail["path"])
	}
	if path == "" {
		return
	}
	if mw := motwOf(path); mw.Present {
		detail["motw"] = true
		if mw.ZoneID >= 0 {
			detail["motw_zone"] = mw.ZoneID
			detail["motw_zone_label"] = motwZoneLabel(mw.ZoneID)
		}
		if mw.Referrer != "" {
			detail["motw_referrer"] = mw.Referrer
		}
		if mw.HostURL != "" {
			detail["motw_host_url"] = mw.HostURL
		}
	}
	if !peExtHot(path) {
		return
	}
	meta, err := peFileMetaOf(path)
	if err != nil || meta == nil {
		return
	}
	applyPEFileMeta(detail, meta)
}

func applyPEFileMeta(detail map[string]any, meta *peFileMeta) {
	if meta.CompileTime != "" {
		detail["pe_compile_time"] = meta.CompileTime
		detail["pe_compile_ts"] = meta.CompileTS
	}
	if meta.CompileFuture {
		detail["pe_compile_future"] = true
	}
	if meta.CompileAncient {
		detail["pe_compile_ancient"] = true
	}
	if meta.ImpHash != "" {
		detail["imphash"] = meta.ImpHash
	}
	if meta.MaxEntropy > 0 {
		detail["pe_max_entropy"] = meta.MaxEntropy
	}
	if meta.PackedLikely {
		detail["pe_packed_likely"] = true
	}
	if len(meta.Sections) > 0 {
		// 只带摘要，避免事件膨胀
		top := meta.Sections
		if len(top) > 8 {
			top = top[:8]
		}
		detail["pe_sections"] = top
	}
	if meta.Is64 {
		detail["pe_arch"] = "x64"
	} else {
		detail["pe_arch"] = "x86"
	}
}

// attachFileMetaCached 仅读缓存；未命中则异步预热，不阻塞 ETW。
func attachFileMetaCached(detail map[string]any, path string) {
	if detail == nil {
		return
	}
	if path == "" {
		path = asString(detail["path"])
	}
	if path == "" {
		return
	}
	key := strings.ToLower(path)
	hit := false
	peFileMetaMu.Lock()
	if e, ok := peFileMetaCache[key]; ok && e.meta != nil && e.err == nil {
		applyPEFileMeta(detail, e.meta)
		hit = true
	}
	peFileMetaMu.Unlock()
	motwMu.Lock()
	if e, ok := motwCache[key]; ok && e.info.Present {
		detail["motw"] = true
		if e.info.ZoneID >= 0 {
			detail["motw_zone"] = e.info.ZoneID
			detail["motw_zone_label"] = motwZoneLabel(e.info.ZoneID)
		}
		if e.info.Referrer != "" {
			detail["motw_referrer"] = e.info.Referrer
		}
		if e.info.HostURL != "" {
			detail["motw_host_url"] = e.info.HostURL
		}
		hit = true
	}
	motwMu.Unlock()
	if !hit || peExtHot(path) {
		fileMetaWarmAsync(path)
	}
}

var (
	fileMetaWarmOnce sync.Once
	fileMetaWarmCh   = make(chan string, 128)
)

func fileMetaWarmAsync(path string) {
	if path == "" {
		return
	}
	fileMetaWarmOnce.Do(func() {
		go func() {
			for p := range fileMetaWarmCh {
				_, _ = peFileMetaOf(p)
				_ = motwOf(p)
				time.Sleep(50 * time.Millisecond)
			}
		}()
	})
	select {
	case fileMetaWarmCh <- path:
	default:
	}
}

// bumpSeverityForFileMeta 根据 MOTW / 异常编译时间 / 疑似加壳提升文件事件严重级别。
func bumpSeverityForFileMeta(sev string, detail map[string]any) string {
	rank := func(s string) int {
		switch strings.ToLower(s) {
		case "critical":
			return 4
		case "high":
			return 3
		case "medium":
			return 2
		case "low":
			return 1
		default:
			return 0
		}
	}
	cur := sev
	raise := func(want string) {
		if rank(want) > rank(cur) {
			cur = want
		}
	}
	zone, _ := detail["motw_zone"].(int)
	if zone == 0 {
		if v, ok := detail["motw_zone"].(float64); ok {
			zone = int(v)
		}
	}
	path := asString(detail["path"])
	if (zone == 3 || zone == 4) && peExtHot(path) {
		if pathInDropZone(path) || pathLooksHot(path) {
			raise("high")
		} else {
			raise("medium")
		}
	}
	if detail["pe_compile_future"] == true && peExtHot(path) {
		raise("medium")
	}
	if detail["pe_compile_ancient"] == true && peExtHot(path) &&
		!isWindowsSystemPath(path) && (pathInDropZone(path) || pathLooksHot(path)) {
		raise("medium")
	}
	if detail["pe_packed_likely"] == true && (pathInDropZone(path) || pathLooksHot(path)) {
		raise("medium")
	}
	return cur
}
