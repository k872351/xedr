//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	evtSubscribeActionError        = 0
	evtSubscribeActionDeliver      = 1
	evtSubscribeToFuture           = 1
	evtSubscribeStartAfterBookmark = 3
	evtRenderEventXML              = 1
	evtRenderBookmark              = 2
	evtQueryChannelPath            = 0x1
	evtQueryReverseDirection       = 0x200
	evtQueryTolerateQueryErrors    = 0x1000
)

var (
	modWevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtSubscribe      = modWevtapi.NewProc("EvtSubscribe")
	procEvtClose          = modWevtapi.NewProc("EvtClose")
	procEvtRender         = modWevtapi.NewProc("EvtRender")
	procEvtCreateBookmark = modWevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = modWevtapi.NewProc("EvtUpdateBookmark")
	procEvtQuery          = modWevtapi.NewProc("EvtQuery")
	procEvtNext           = modWevtapi.NewProc("EvtNext")
)

// 各通道投递计数（心跳可观测：Sysmon 已装但仍 EventID=0 时能区分「未订阅」vs「订了没推上来」）
var (
	winevtStatsMu sync.Mutex
	winevtStats   = map[string]map[string]any{}
)

func winevtNoteStat(id string, key string, add uint64) {
	winevtStatsMu.Lock()
	defer winevtStatsMu.Unlock()
	st := winevtStats[id]
	if st == nil {
		st = map[string]any{"id": id}
		winevtStats[id] = st
	}
	cur, _ := st[key].(uint64)
	st[key] = cur + add
	st["updated_at"] = time.Now().Format("2006-01-02T15:04:05")
}

func winevtSetStat(id string, kv map[string]any) {
	winevtStatsMu.Lock()
	defer winevtStatsMu.Unlock()
	st := winevtStats[id]
	if st == nil {
		st = map[string]any{"id": id}
		winevtStats[id] = st
	}
	for k, v := range kv {
		st[k] = v
	}
	st["updated_at"] = time.Now().Format("2006-01-02T15:04:05")
}

func winevtChannelStatsSnapshot() []map[string]any {
	winevtStatsMu.Lock()
	defer winevtStatsMu.Unlock()
	out := make([]map[string]any, 0, len(winevtStats))
	for _, st := range winevtStats {
		cp := map[string]any{}
		for k, v := range st {
			cp[k] = v
		}
		out = append(out, cp)
	}
	return out
}

func winevtTryNative(ctx context.Context, bookmarkDir string, push func(map[string]any)) error {
	if err := modWevtapi.Load(); err != nil {
		return err
	}
	_ = os.MkdirAll(bookmarkDir, 0700)
	defs := winevtAvailableChannels(winevtChannelDefsFiltered())
	if len(defs) == 0 {
		return errors.New("no event channels")
	}

	var wg sync.WaitGroup
	for _, ch := range defs {
		wg.Add(1)
		go func(c winevtChannel) {
			defer wg.Done()
			winevtRunChannel(ctx, bookmarkDir, c, push)
		}(ch)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("all channel subscriptions ended")
}

func winevtAvailableChannels(defs []winevtChannel) []winevtChannel {
	var out []winevtChannel
	for _, d := range defs {
		if winevtChannelOK(d.Channel) {
			out = append(out, d)
		}
	}
	return out
}

func winevtChannelOK(channel string) bool {
	p, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return false
	}
	q, _ := windows.UTF16PtrFromString("*")
	h, _, _ := procEvtQuery.Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath)
	if h == 0 {
		return false
	}
	procEvtClose.Call(h)
	return true
}

func winevtRunChannel(ctx context.Context, bookmarkDir string, ch winevtChannel, push func(map[string]any)) {
	for {
		if ctx.Err() != nil {
			return
		}
		err := winevtSubscribeOnce(ctx, bookmarkDir, ch, push)
		if err != nil && ctx.Err() == nil {
			log.Printf("winevent[%s]: %v", ch.ID, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		} else {
			return
		}
	}
}

func winevtBookmarkPath(dir, id string) string {
	return filepath.Join(dir, id+".xml")
}

func winevtHasBookmark(dir, id string) bool {
	fi, err := os.Stat(winevtBookmarkPath(dir, id))
	return err == nil && fi.Size() > 0
}

// winevtCatchUpChannel 反向拉取通道近期事件（无书签首次订阅 / Sysmon 刚装好时补时间线）。
func winevtCatchUpChannel(ch winevtChannel, push func(map[string]any), maxN int) int {
	if maxN <= 0 {
		return 0
	}
	chPtr, err := windows.UTF16PtrFromString(ch.Channel)
	if err != nil {
		return 0
	}
	xpPtr, err := windows.UTF16PtrFromString(ch.XPath)
	if err != nil {
		return 0
	}
	flags := uintptr(evtQueryChannelPath | evtQueryReverseDirection | evtQueryTolerateQueryErrors)
	h, _, _ := procEvtQuery.Call(0, uintptr(unsafe.Pointer(chPtr)), uintptr(unsafe.Pointer(xpPtr)), flags)
	if h == 0 {
		return 0
	}
	defer winevtCloseHandle(h)

	n := 0
	parsed := 0
	for n < maxN {
		var evt uintptr
		var returned uint32
		r0, _, _ := procEvtNext.Call(h, 1, uintptr(unsafe.Pointer(&evt)), 200, 0, uintptr(unsafe.Pointer(&returned)))
		if r0 == 0 || returned == 0 || evt == 0 {
			break
		}
		xmlText, err := winevtRenderEventXML(evt)
		winevtCloseHandle(evt)
		n++
		if err != nil {
			continue
		}
		if ev := winevtParseXML(xmlText, ch.Channel); ev != nil {
			parsed++
			push(ev)
		}
	}
	winevtSetStat(ch.ID, map[string]any{
		"channel": ch.Channel, "catchup_scanned": uint64(n), "catchup_parsed": uint64(parsed),
	})
	if parsed > 0 {
		log.Printf("winevent[%s]: catch-up %d/%d events from %s", ch.ID, parsed, n, ch.Channel)
	}
	return parsed
}

func winevtSubscribeOnce(ctx context.Context, bookmarkDir string, ch winevtChannel, push func(map[string]any)) error {
	deliver := make(chan uintptr, 2048)
	var dropped uint32
	var delivered uint64
	var sequence uint64
	progress := &bookmarkProgress{}
	cb := syscall.NewCallback(func(action, _ /*ctx*/, evt uintptr) uintptr {
		if action == evtSubscribeActionError {
			captureAdd("winevent_native", "bookmark_gap", 1)
			progress.block()
			return 1
		}
		if action != evtSubscribeActionDeliver || evt == 0 {
			return 1
		}
		select {
		case deliver <- evt:
		default:
			atomic.AddUint32(&dropped, 1)
			captureAdd("winevent_native", "buffer_dropped", 1)
			progress.block()
			procEvtClose.Call(evt)
		}
		return 1
	})
	// 回调必须对 GC 保持可达，否则订阅会静默停收
	defer runtime.KeepAlive(cb)

	chPtr, err := windows.UTF16PtrFromString(ch.Channel)
	if err != nil {
		return err
	}
	xpPtr, err := windows.UTF16PtrFromString(ch.XPath)
	if err != nil {
		return err
	}

	hadBookmark := winevtHasBookmark(bookmarkDir, ch.ID)
	// 无书签：先回补近期事件，避免 ToFuture 导致「Sysmon 已装但时间线 EventID=0」
	if !hadBookmark {
		limit := 40
		if ch.ID == "sysmon" {
			limit = 200
		} else if ch.ID == "security" {
			limit = 80
		}
		winevtCatchUpChannel(ch, push, limit)
	}

	bookmark := winevtLoadBookmark(bookmarkDir, ch.ID)
	defer winevtCloseHandle(bookmark)

	flags := uintptr(evtSubscribeToFuture)
	if hadBookmark && bookmark != 0 {
		flags = evtSubscribeStartAfterBookmark
	}

	sub, _, e1 := procEvtSubscribe.Call(
		0,
		0,
		uintptr(unsafe.Pointer(chPtr)),
		uintptr(unsafe.Pointer(xpPtr)),
		bookmark,
		0,
		cb,
		flags,
	)
	if sub == 0 {
		// StartAfterBookmark 失败时回退 ToFuture，避免整通道挂死
		if flags == evtSubscribeStartAfterBookmark {
			log.Printf("winevent[%s]: StartAfterBookmark failed (%v), fallback ToFuture", ch.ID, e1)
			captureAdd("winevent_native", "bookmark_gap", 1)
			winevtCatchUpChannel(ch, push, 40)
			sub, _, e1 = procEvtSubscribe.Call(
				0, 0,
				uintptr(unsafe.Pointer(chPtr)),
				uintptr(unsafe.Pointer(xpPtr)),
				0, 0, cb,
				evtSubscribeToFuture,
			)
			flags = evtSubscribeToFuture
		}
	}
	if sub == 0 {
		winevtSetStat(ch.ID, map[string]any{"channel": ch.Channel, "subscribe_error": fmt.Sprintf("%v", e1)})
		if e1 != nil && e1 != syscall.Errno(0) {
			return e1
		}
		return errors.New("EvtSubscribe failed")
	}
	defer winevtCloseHandle(sub)
	winevtSetStat(ch.ID, map[string]any{
		"channel": ch.Channel, "subscribed": true,
		"flag": map[bool]string{true: "after_bookmark", false: "to_future"}[flags == evtSubscribeStartAfterBookmark],
	})
	push(map[string]any{
		"etype": "winevent_status", "summary": "Windows Event Log channel active: " + ch.ID,
		"severity": "info", "ts": time.Now().Format("2006-01-02T15:04:05"),
		"detail": map[string]any{"source": ch.ID, "channel": ch.Channel, "backend": "wevtapi"},
	})
	log.Printf("winevent[%s]: subscribed %s (%s)", ch.ID, ch.Channel,
		map[bool]string{true: "after_bookmark", false: "to_future"}[flags == evtSubscribeStartAfterBookmark])

	saveTick := time.NewTicker(15 * time.Second)
	defer saveTick.Stop()
	lastSaved := ""
	saveConfirmed := func() {
		xmlText := progress.snapshot()
		if xmlText == "" || xmlText == lastSaved {
			return
		}
		if winevtSaveBookmarkXML(bookmarkDir, ch.ID, xmlText) {
			lastSaved = xmlText
		} else {
			captureAdd("winevent_native", "bookmark_save_failed", 1)
		}
	}

	for {
		select {
		case <-ctx.Done():
			saveConfirmed()
			runtime.KeepAlive(cb)
			return ctx.Err()
		case <-saveTick.C:
			saveConfirmed()
			if d := atomic.SwapUint32(&dropped, 0); d > 0 {
				winevtNoteStat(ch.ID, "dropped", uint64(d))
				log.Printf("winevent[%s]: dropped %d events (queue full)", ch.ID, d)
			}
			runtime.KeepAlive(cb)
		case h := <-deliver:
			sequence++
			captureAdd("winevent_native", "received", 1)
			xmlText, err := winevtRenderEventXML(h)
			checkpoint := ""
			if bookmark != 0 {
				if ok, _, _ := procEvtUpdateBookmark.Call(bookmark, h); ok != 0 {
					checkpoint, _ = winevtRenderBookmark(bookmark)
				}
			}
			procEvtClose.Call(h)
			if err != nil {
				winevtNoteStat(ch.ID, "render_err", 1)
				captureAdd("winevent_native", "render_failed", 1)
				progress.block()
				continue
			}
			if ev := winevtParseXML(xmlText, ch.Channel); ev != nil {
				if checkpoint != "" {
					seq := sequence
					ev[bookmarkAckKey] = func() { progress.acknowledge(seq, checkpoint) }
				} else {
					progress.block()
					captureAdd("winevent_native", "bookmark_gap", 1)
				}
				delivered++
				winevtNoteStat(ch.ID, "delivered", 1)
				if delivered == 1 || delivered%50 == 0 {
					log.Printf("winevent[%s]: delivered %d events", ch.ID, delivered)
				}
				push(ev)
			} else {
				winevtNoteStat(ch.ID, "parsed_nil", 1)
				progress.block()
				captureAdd("winevent_native", "parse_failed", 1)
			}
		}
	}
}

func winevtLoadBookmark(dir, id string) uintptr {
	path := filepath.Join(dir, id+".xml")
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		h, _, _ := procEvtCreateBookmark.Call(0)
		return h
	}
	// 文件为 UTF-8 书签 XML
	p, err := windows.UTF16PtrFromString(string(raw))
	if err != nil {
		h, _, _ := procEvtCreateBookmark.Call(0)
		return h
	}
	h, _, _ := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
	if h == 0 {
		h, _, _ = procEvtCreateBookmark.Call(0)
	}
	return h
}

func winevtSaveBookmarkXML(dir, id, xmlText string) bool {
	if xmlText == "" {
		return false
	}
	path := filepath.Join(dir, id+".xml")
	tmp, err := os.CreateTemp(dir, ".bookmark-*.tmp")
	if err != nil {
		return false
	}
	name := tmp.Name()
	defer os.Remove(name)
	defer tmp.Close()
	if _, err := tmp.WriteString(xmlText); err != nil {
		return false
	}
	if err := tmp.Sync(); err != nil {
		return false
	}
	if err := tmp.Close(); err != nil {
		return false
	}
	return os.Rename(name, path) == nil
}

func winevtRenderBookmark(bookmark uintptr) (string, error) {
	return winevtRender(bookmark, evtRenderBookmark)
}

func winevtRenderEventXML(evt uintptr) (string, error) {
	return winevtRender(evt, evtRenderEventXML)
}

func winevtRender(handle uintptr, flags uint32) (string, error) {
	var used, props uint32
	r0, _, err := procEvtRender.Call(0, handle, uintptr(flags), 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if r0 == 0 && err != nil && err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "", err
	}
	if used == 0 {
		used = 65536
	}
	buf := make([]uint16, (used+1)/2)
	for tries := 0; tries < 3; tries++ {
		r0, _, err = procEvtRender.Call(
			0, handle, uintptr(flags),
			uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)),
		)
		if r0 != 0 {
			return windows.UTF16ToString(buf[:used/2]), nil
		}
		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]uint16, (used+1)/2)
			continue
		}
		if err != nil && err != syscall.Errno(0) {
			return "", err
		}
		break
	}
	return "", errors.New("EvtRender failed")
}

func winevtCloseHandle(h uintptr) {
	if h != 0 {
		procEvtClose.Call(h)
	}
}

func stringsJoin(a []string, sep string) string {
	if len(a) == 0 {
		return ""
	}
	s := a[0]
	for i := 1; i < len(a); i++ {
		s += sep + a[i]
	}
	return s
}
