//go:build windows

package main

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

// 注册表修改者归属：Kernel-Registry ETW 带写入方 PID/TID。
// SetValueKey/DeleteValueKey 事件只有 KeyObject（内核对象地址）没有键路径，
// 所以记录 CreateKey 的「KeyObject → 相对路径」，再按「值名 + 路径后缀 + 时间窗」与 RegNotify 检出的变更匹配。

var guidKernelRegistry = etw.MustParseGUIDFromString("{70EB4F03-C1DE-4F73-A051-33D13D5413BD}")

const (
	regEvCreateKey   = 1
	regEvDeleteKey   = 3
	regEvSetValue    = 5
	regEvDeleteValue = 6

	regETWKeywords = 0x100 | 0x200 | 0x1000 | 0x4000 // SetValue | DeleteValue | CreateKey | DeleteKey

	regETWRing     = 8192
	regETWObjMax   = 30000
	regETWWindow   = 8 * time.Second
	regETWWaitStep = 250 * time.Millisecond
	regETWWaitMax  = 2500 * time.Millisecond
)

var controlSetRe = regexp.MustCompile(`\\controlset\d{3}\\`)

// setETWFlushTimer 把实时会话的缓冲刷新间隔设为 sec 秒；该库建会话时为 0（缓冲满才交付），低频事件会延迟数秒。
func setETWFlushTimer(name string, sec uint32) error {
	u16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	prop := etw.NewRealTimeEventTraceSessionProperties(name)
	prop.FlushTimer = sec
	return etw.ControlTrace(0, u16, prop, etw.EVENT_TRACE_CONTROL_UPDATE)
}

var regETWWantIDs = map[uint16]bool{regEvCreateKey: true, regEvDeleteKey: true, regEvSetValue: true, regEvDeleteValue: true}

type regWrite struct {
	at        time.Time
	pid, tid  uint32
	op        uint16
	keyObj    string
	valueName string // 小写
	relName   string // CreateKey 的相对路径（小写、已归一化）
}

type regETWTracker struct {
	active   atomic.Bool
	self     uint32
	mu       sync.Mutex
	ring     []regWrite
	next     int
	full     bool
	objName  map[string]string
	objOrder []string
	lastWait time.Time
}

var regETW = &regETWTracker{
	self:    uint32(os.Getpid()),
	ring:    make([]regWrite, regETWRing),
	objName: map[string]string{},
}

// normRegPath 统一成不含根的相对路径，便于后缀比较：
//
//	\REGISTRY\MACHINE\SOFTWARE\X → software\x
//	\REGISTRY\USER\S-1-5-21-..._Classes\CLSID\X → software\classes\clsid\x
//	HKU\S-1-5-21-...\Software\X → software\x
func normRegPath(p string) string {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(p), `\`))
	// 内核报告实际控制集（ControlSet001），RegNotify 侧用的是 CurrentControlSet 链接
	s = controlSetRe.ReplaceAllString(s, `\currentcontrolset\`)
	for _, pre := range []string{`registry\machine\`, `hklm\`} {
		if strings.HasPrefix(s, pre) {
			return strings.TrimPrefix(s, pre)
		}
	}
	for _, pre := range []string{`registry\user\`, `hku\`} {
		if strings.HasPrefix(s, pre) {
			s = strings.TrimPrefix(s, pre)
			i := strings.Index(s, `\`)
			if i < 0 {
				return ""
			}
			sid, rest := s[:i], s[i+1:]
			if strings.HasSuffix(sid, "_classes") {
				return `software\classes\` + rest
			}
			return rest
		}
	}
	if strings.HasPrefix(s, `software\classes\`) {
		return s
	}
	return s
}

func (t *regETWTracker) push(w regWrite) {
	t.mu.Lock()
	t.ring[t.next] = w
	t.next = (t.next + 1) % len(t.ring)
	if t.next == 0 {
		t.full = true
	}
	if w.op == regEvCreateKey && w.keyObj != "" && w.relName != "" {
		if _, ok := t.objName[w.keyObj]; !ok {
			t.objOrder = append(t.objOrder, w.keyObj)
		}
		t.objName[w.keyObj] = w.relName
		if len(t.objOrder) > regETWObjMax {
			drop := t.objOrder[:len(t.objOrder)-regETWObjMax]
			for _, k := range drop {
				delete(t.objName, k)
			}
			t.objOrder = append([]string(nil), t.objOrder[len(drop):]...)
		}
	}
	t.mu.Unlock()
}

// onPrepared 在属性解析前读取少量字段并跳过完整解析（该库对 SetValueKey 的完整解析会丢事件头）。
func (t *regETWTracker) onPrepared(h *etw.EventRecordHelper) {
	h.Skip()
	hd := h.EventRec.EventHeader
	if hd.ProcessId == t.self {
		return
	}
	w := regWrite{
		at:  hd.UTCTimeStamp().Local(),
		pid: hd.ProcessId, tid: hd.ThreadId,
		op: hd.EventDescriptor.Id,
	}
	w.keyObj, _ = h.GetPropertyString("KeyObject")
	switch w.op {
	case regEvCreateKey:
		rel, _ := h.GetPropertyString("RelativeName")
		w.relName = normRegPath(rel)
	case regEvSetValue, regEvDeleteValue:
		vn, _ := h.GetPropertyString("ValueName")
		w.valueName = strings.ToLower(vn)
		if kn, _ := h.GetPropertyString("KeyName"); kn != "" {
			w.relName = normRegPath(kn)
		}
	case regEvDeleteKey:
		if kn, _ := h.GetPropertyString("KeyName"); kn != "" {
			w.relName = normRegPath(kn)
		}
	}
	t.push(w)
}

type regActor struct {
	pid, tid   uint32
	at         time.Time
	confidence string // etw_exact | etw_value | etw_ambiguous
}

// attribute 查找写入某键值的进程。key 为 RegNotify 侧的完整键路径，valueName 中 "(默认)"/"(key)" 有特殊含义。
func (t *regETWTracker) attribute(key, valueName, change string) (regActor, bool) {
	if !t.active.Load() {
		return regActor{}, false
	}
	nk := normRegPath(key)
	vn := strings.ToLower(valueName)
	if vn == "(默认)" {
		vn = ""
	}
	var ops []uint16
	subkey := false
	switch {
	case valueName == "(key)" && change == "delete":
		ops, subkey = []uint16{regEvDeleteKey}, true
	case valueName == "(key)":
		ops, subkey = []uint16{regEvCreateKey}, true
	case change == "delete":
		ops = []uint16{regEvDeleteValue}
	default:
		ops = []uint16{regEvSetValue}
	}
	deadline := time.Now().Add(regETWWaitMax)
	t.mu.Lock()
	canWait := time.Since(t.lastWait) > 2*time.Second
	if canWait {
		t.lastWait = time.Now()
	}
	t.mu.Unlock()
	for {
		if a, ok := t.scan(nk, vn, ops, subkey); ok {
			return a, true
		}
		if !canWait || time.Now().After(deadline) {
			return regActor{}, false
		}
		time.Sleep(regETWWaitStep)
	}
}

func (t *regETWTracker) scan(nk, vn string, ops []uint16, subkey bool) (regActor, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(t.ring)
	count := t.next
	if t.full {
		count = n
	}
	cut := time.Now().Add(-regETWWindow)
	var cand []regWrite
	for i := 0; i < count; i++ {
		w := t.ring[(t.next-1-i+n)%n]
		if w.at.Before(cut) {
			break
		}
		if !opIn(w.op, ops) {
			continue
		}
		if subkey {
			if w.relName != "" && (strings.HasSuffix(nk, w.relName) || strings.HasSuffix(w.relName, nk)) {
				return regActor{pid: w.pid, tid: w.tid, at: w.at, confidence: "etw_exact"}, true
			}
			continue
		}
		if w.valueName != vn {
			continue
		}
		name := w.relName
		if name == "" {
			name = t.objName[w.keyObj]
		}
		if name != "" && strings.HasSuffix(nk, name) {
			return regActor{pid: w.pid, tid: w.tid, at: w.at, confidence: "etw_exact"}, true
		}
		cand = append(cand, w)
	}
	if len(cand) == 0 {
		return regActor{}, false
	}
	conf := "etw_value"
	for _, c := range cand[1:] {
		if c.pid != cand[0].pid {
			conf = "etw_ambiguous"
			break
		}
	}
	return regActor{pid: cand[0].pid, tid: cand[0].tid, at: cand[0].at, confidence: conf}, true
}

func opIn(op uint16, ops []uint16) bool {
	for _, o := range ops {
		if o == op {
			return true
		}
	}
	return false
}
