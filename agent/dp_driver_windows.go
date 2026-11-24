//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// DataProtector minifilter (optional component). When the driver is loaded the agent
// pushes the master key ring and block/audit policy, and drains threat-engine events.

var (
	modFltlib             = windows.NewLazySystemDLL("fltlib.dll")
	procFilterConnectPort = modFltlib.NewProc("FilterConnectCommunicationPort")
	procFilterSendMessage = modFltlib.NewProc("FilterSendMessage")
	dpPortName, _         = windows.UTF16PtrFromString(`\DataProtectorPolicyPort`)
)

const dpMaxQueryBytes = 8 << 20 // driver-side cap per message

type dpDriver struct {
	mu        sync.Mutex
	port      windows.Handle
	events    []map[string]any
	keys      *dpKeyRing
	keysSent  string // hash of the ring last accepted by the driver
	block     bool
	blockSent int // -1 unknown, 0 audit, 1 block
	status    string

	stateDir    string
	loadAt      time.Time // last fltmc load attempt by the agent
	loadedByUs  time.Time // successful load by the agent (crash-guard window starts here)
	autoLoadOff bool
}

// Crash guard for auto-loading the (demand-start) minifilter after boot: a marker is
// written before each load and removed once the driver has run stably. If the agent
// starts and finds the marker, the previous load was followed by a crash/reboot, so
// auto-load is disabled (until the installer runs again) instead of crash-looping.
const (
	dpLoadPendingFile  = "dp_load_pending"
	dpLoadDisabledFile = "dp_load_disabled"
	dpLoadStableAfter  = 2 * time.Minute
	dpLoadRetryEvery   = 10 * time.Minute
)

func (d *dpDriver) markerPath(name string) string { return filepath.Join(d.stateDir, name) }

func dpServiceRegistered() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\DataProtector`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func (d *dpDriver) initAutoLoad() {
	if d.stateDir == "" {
		d.autoLoadOff = true
		return
	}
	if _, err := os.Stat(d.markerPath(dpLoadDisabledFile)); err == nil {
		d.autoLoadOff = true
		d.status = "自动加载已停用（此前加载后系统异常重启）"
		return
	}
	if _, err := os.Stat(d.markerPath(dpLoadPendingFile)); err == nil {
		_ = os.WriteFile(d.markerPath(dpLoadDisabledFile), []byte(time.Now().Format(time.RFC3339)), 0o644)
		_ = os.Remove(d.markerPath(dpLoadPendingFile))
		d.autoLoadOff = true
		d.status = "自动加载已停用（此前加载后系统异常重启）"
		log.Printf("dp_driver: 上次加载驱动后系统未正常运行，已停用自动加载；重新安装后恢复")
	}
}

// tryLoadLocked loads the registered minifilter (it is demand-start, so nothing loads it at boot).
func (d *dpDriver) tryLoadLocked() {
	if d.autoLoadOff || !dpServiceRegistered() || time.Since(d.loadAt) < dpLoadRetryEvery {
		return
	}
	d.loadAt = time.Now()
	_ = os.WriteFile(d.markerPath(dpLoadPendingFile), []byte(d.loadAt.Format(time.RFC3339)), 0o644)
	out, err := exec.Command("fltmc.exe", "load", "DataProtector").CombinedOutput()
	if err != nil {
		_ = os.Remove(d.markerPath(dpLoadPendingFile))
		d.status = "已安装但未加载: " + strings.TrimSpace(string(out))
		return
	}
	d.loadedByUs = time.Now()
	log.Printf("dp_driver: 已自动加载 DataProtector 驱动")
}

func (d *dpDriver) confirmStableLocked() {
	if !d.loadedByUs.IsZero() && time.Since(d.loadedByUs) >= dpLoadStableAfter {
		_ = os.Remove(d.markerPath(dpLoadPendingFile))
		d.loadedByUs = time.Time{}
	}
}

var dpDrv = &dpDriver{port: windows.InvalidHandle, blockSent: -1, status: "未连接"}

func (d *dpDriver) connectLocked() error {
	if d.port != windows.InvalidHandle {
		return nil
	}
	if err := procFilterConnectPort.Find(); err != nil {
		return err
	}
	var h windows.Handle
	hr, _, _ := procFilterConnectPort.Call(uintptr(unsafe.Pointer(dpPortName)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&h)))
	if hr != 0 {
		return fmt.Errorf("FilterConnectCommunicationPort hr=0x%08X", uint32(hr))
	}
	d.port = h
	d.keysSent = ""
	d.blockSent = -1
	log.Printf("dp_driver: 已连接 DataProtector 驱动")
	return nil
}

func (d *dpDriver) closeLocked() {
	if d.port != windows.InvalidHandle {
		_ = windows.CloseHandle(d.port)
		d.port = windows.InvalidHandle
	}
}

// sendLocked issues one command; on failure the port is dropped so the next tick reconnects.
func (d *dpDriver) sendLocked(cmd uint32, value []byte, out []byte) (int, error) {
	msg := dpMessage(cmd, value)
	defer func() {
		for i := range msg {
			msg[i] = 0 // may carry key material
		}
	}()
	var ret uint32
	var outPtr uintptr
	if len(out) > 0 {
		outPtr = uintptr(unsafe.Pointer(&out[0]))
	}
	hr, _, _ := procFilterSendMessage.Call(uintptr(d.port),
		uintptr(unsafe.Pointer(&msg[0])), uintptr(len(msg)),
		outPtr, uintptr(len(out)), uintptr(unsafe.Pointer(&ret)))
	if hr != 0 {
		return 0, fmt.Errorf("FilterSendMessage cmd=%d hr=0x%08X", cmd, uint32(hr))
	}
	return int(ret), nil
}

func (d *dpDriver) applyPolicy(pol map[string]any) {
	if pol == nil {
		return
	}
	dp, _ := pol["dp_driver"].(map[string]any)
	block := false
	if dp != nil {
		block, _ = dp["block"].(bool)
	}
	d.mu.Lock()
	d.block = block
	d.mu.Unlock()
}

func (d *dpDriver) applyCrypto(m map[string]any) {
	ring, err := parseDPCrypto(m)
	if err != nil {
		log.Printf("dp_driver: 忽略密钥下发: %v", err)
		return
	}
	if ring == nil {
		return // keep whatever ring the driver already holds
	}
	d.mu.Lock()
	d.keys = ring
	d.mu.Unlock()
}

func ringHash(r *dpKeyRing) string {
	ids := make([]uint32, 0, len(r.Keys))
	for id := range r.Keys {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	h := sha256.New()
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], r.ActiveKeyID)
	h.Write(b[:])
	for _, id := range ids {
		binary.LittleEndian.PutUint32(b[:], id)
		h.Write(b[:])
		h.Write(r.Keys[id])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (d *dpDriver) syncConfigLocked() {
	if d.keys != nil {
		if h := ringHash(d.keys); h != d.keysSent {
			if _, err := d.sendLocked(dpCmdSetCryptoKeys, encodeDPCryptoKeys(d.keys), nil); err != nil {
				log.Printf("dp_driver: 下发主密钥失败: %v", err)
				d.closeLocked()
				return
			}
			d.keysSent = h
			log.Printf("dp_driver: 主密钥环已下发（当前 key_id=%d，共 %d 把）", d.keys.ActiveKeyID, len(d.keys.Keys))
		}
	}
	want := 0
	if d.block {
		want = 1
	}
	if want == d.blockSent {
		return
	}
	pick := func(audit, block uint32) uint32 {
		if want == 1 {
			return block
		}
		return audit
	}
	for _, p := range []struct {
		cmd  uint32
		size int
		flag uint32
	}{
		{dpCmdSetThreatPolicy, 24, pick(dpThreatFlagsAudit, dpThreatFlagsBlock)},
		{dpCmdSetHashProtectPolicy, 8, pick(dpHashFlagsAudit, dpHashFlagsBlock)},
		{dpCmdSetLateralPolicy, 8, pick(dpLateralFlagsAudit, dpLateralFlagsBlock)},
		{dpCmdSetStaticScanPolicy, 16, dpStaticFlagsAudit},
	} {
		if _, err := d.sendLocked(p.cmd, dpPolicyStruct(p.size, p.flag), nil); err != nil {
			log.Printf("dp_driver: 下发拦截策略失败: %v", err)
			d.closeLocked()
			return
		}
	}
	d.blockSent = want
	log.Printf("dp_driver: 拦截模式=%v", want == 1)
}

func (d *dpDriver) pollLocked() {
	hdr := make([]byte, dpThreatHeaderLen)
	if _, err := d.sendLocked(dpCmdQueryThreatEvents, nil, hdr); err != nil {
		log.Printf("dp_driver: 查询事件失败: %v", err)
		d.closeLocked()
		return
	}
	count := binary.LittleEndian.Uint32(hdr[4:8])
	need := int(binary.LittleEndian.Uint32(hdr[8:12]))
	if count == 0 || need <= dpThreatHeaderLen {
		return
	}
	need += 64 * dpThreatEntryLen // headroom: the driver only drains when everything fits
	if need > dpMaxQueryBytes {
		need = dpMaxQueryBytes
	}
	buf := make([]byte, need)
	n, err := d.sendLocked(dpCmdQueryThreatEvents, nil, buf)
	if err != nil {
		log.Printf("dp_driver: 拉取事件失败: %v", err)
		d.closeLocked()
		return
	}
	evs, err := parseDPThreatEvents(buf[:n])
	if err != nil {
		return
	}
	if len(d.events) < 5000 {
		d.events = append(d.events, evs...)
	}
}

func (d *dpDriver) tick() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.connectLocked(); err != nil {
		if !d.autoLoadOff && dpServiceRegistered() {
			d.tryLoadLocked()
			if d.connectLocked() != nil {
				if !strings.HasPrefix(d.status, "已安装但未加载") {
					d.status = "已安装，等待加载"
				}
				return
			}
		} else {
			if !d.autoLoadOff {
				d.status = "未安装"
			}
			return
		}
	}
	d.confirmStableLocked()
	d.syncConfigLocked()
	if d.port == windows.InvalidHandle {
		d.status = "连接中断"
		return
	}
	d.pollLocked()
	d.pollStaticScanLocked()
	if d.port != windows.InvalidHandle {
		d.status = "已连接"
	}
}

func (d *dpDriver) run(ctx context.Context, stateDir string) {
	d.mu.Lock()
	d.stateDir = stateDir
	d.initAutoLoad()
	d.mu.Unlock()
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	d.tick()
	for {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			d.closeLocked()
			d.mu.Unlock()
			return
		case <-t.C:
			d.tick()
		}
	}
}

func (d *dpDriver) drain() []map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.events
	d.events = nil
	return out
}

func (d *dpDriver) state() (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.port != windows.InvalidHandle, d.status
}
