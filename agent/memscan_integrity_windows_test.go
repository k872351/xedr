//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procVirtualAllocEx     = modKernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx   = modKernel32.NewProc("VirtualProtectEx")
	procCreateRemoteThread = modKernel32.NewProc("CreateRemoteThread")
)

// 只读全量巡检，看本机误报；设置 EDR_INTEGRITY_FLEET=1 才运行。
func TestIntegrityFleetNoise(t *testing.T) {
	if os.Getenv("EDR_INTEGRITY_FLEET") != "1" {
		t.Skip("set EDR_INTEGRITY_FLEET=1 to run")
	}
	t0 := time.Now()
	findings, scanned := runIntegrityChecks(0, false)
	t.Logf("scanned=%d findings=%d elapsed=%s", scanned, len(findings), time.Since(t0))
	for _, f := range findings {
		t.Logf("[%s] %s %s", f["severity"], f["type"], f["summary"])
	}
}

// 真实向子进程注入代码并改写 ntdll，杀软可能拦截；设置 EDR_INTEGRITY_E2E=1 才运行。
func TestIntegrityDetectsInjectionAndPatches(t *testing.T) {
	if os.Getenv("EDR_INTEGRITY_E2E") != "1" {
		t.Skip("set EDR_INTEGRITY_E2E=1 to run")
	}
	cmd := exec.Command("cmd.exe", "/c", "ping -n 30 127.0.0.1 >nul")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(800 * time.Millisecond)
	pid := uint32(cmd.Process.Pid)

	h, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)

	// 带 MZ 头的私有 RWX 内存，线程从 +0x100 的 jmp $ 开始
	payload := make([]byte, 0x200)
	payload[0], payload[1] = 'M', 'Z'
	payload[0x100], payload[0x101] = 0xEB, 0xFE
	mem, _, e := procVirtualAllocEx.Call(uintptr(h), 0, 0x1000, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if mem == 0 {
		t.Fatal(e)
	}
	var wrote uintptr
	if err := windows.WriteProcessMemory(h, mem, &payload[0], uintptr(len(payload)), &wrote); err != nil {
		t.Fatal(err)
	}
	th, _, e := procCreateRemoteThread.Call(uintptr(h), 0, 0, mem+0x100, 0, 0, 0)
	if th == 0 {
		t.Fatal(e)
	}
	defer windows.CloseHandle(windows.Handle(th))

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	var old uint32
	patch := func(addr uintptr, b []byte) {
		r, _, e := procVirtualProtectEx.Call(uintptr(h), addr, uintptr(len(b)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&old)))
		if r == 0 {
			t.Fatal(e)
		}
		if err := windows.WriteProcessMemory(h, addr, &b[0], uintptr(len(b)), &wrote); err != nil {
			t.Fatal(err)
		}
	}
	patch(ntdll.NewProc("EtwEventWrite").Addr(), []byte{0xC3})

	// mov r11,imm64; jmp r11：把 NtWriteVirtualMemory 挂到私有内存
	tgt := uint64(mem + 0x100)
	hook := []byte{0x49, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0xFF, 0xE3}
	for i := 0; i < 8; i++ {
		hook[2+i] = byte(tgt >> (8 * i))
	}
	patch(ntdll.NewProc("NtWriteVirtualMemory").Addr(), hook)

	// 模块覆盖：kernel32!Beep 起 128 字节改成 NOP
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	nops := make([]byte, 128)
	for i := range nops {
		nops[i] = 0x90
	}
	patch(k32.NewProc("Beep").Addr(), nops)

	mods, _ := snapshotModuleSpans(pid)
	var cmdBase, k32Base uintptr
	var cmdPath, k32Path string
	for _, m := range mods {
		switch {
		case strings.HasSuffix(m.path, `\cmd.exe`):
			cmdBase, cmdPath = m.base, m.path
		case strings.HasSuffix(m.path, `system32\kernel32.dll`):
			k32Base, k32Path = m.base, m.path
		}
	}
	// IAT 挂钩：cmd.exe 导入表第一项指向私有内存
	if d, err := loadDiskPE(cmdPath); err == nil && d.iatRVA != 0 {
		ptr := make([]byte, 8)
		for i := 0; i < 8; i++ {
			ptr[i] = byte(uint64(mem+0x100) >> (8 * i))
		}
		patch(cmdBase+uintptr(d.iatRVA), ptr)
	}
	// EAT 挂钩：kernel32 导出表第一项指到镜像之外
	if d, err := loadDiskPE(k32Path); err == nil && d.eatRVA != 0 {
		v := d.sizeOfImage + 0x10000
		patch(k32Base+uintptr(d.eatRVA), []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
	}

	findings, _ := runIntegrityChecks(int(pid), false)
	got := map[string]string{}
	for _, f := range findings {
		got[asString(f["type"])] = asString(f["severity"])
		t.Logf("[%s] %s %s", f["severity"], f["type"], f["summary"])
	}
	want := map[string]string{
		"process_injection": "critical", "etw_patch": "critical", "ntdll_hook": "high",
		"module_stomping": "high", "iat_hook": "high", "eat_hook": "high",
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("%s: want severity %s, got %q", k, sev, got[k])
		}
	}
}
