//go:build windows

package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 内存完整性检查（用户态、只读）：
//   - 线程起始地址不在任何镜像模块内（注入线程）
//   - 私有/映射可执行内存里带 PE 头（反射加载 / 手工映射）
//   - ntdll/amsi 关键函数被打补丁或挂钩（与本进程干净副本逐字节比对）
//   - 已映射镜像不在模块链表中（断链隐藏模块，仅定向扫描时检查）
// 跨进程写内存 / APC 等 Threat-Intelligence ETW 事件需要 PPL，这里用状态推断补位。

const (
	memTypeImage   = 0x1000000
	memTypeMapped  = 0x40000
	memTypePrivate = 0x20000

	threadQueryLimitedInformation   = 0x0800
	threadQuerySetWin32StartAddress = 9

	integrityCompareBytes = 8
	integrityMaxProcesses = 400
	integrityMaxFindings  = 60
	integrityDedupTTL     = 12 * time.Hour
)

var (
	modNtdllInteg                = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationThread = modNtdllInteg.NewProc("NtQueryInformationThread")
	procK32GetMappedFileNameW    = modKernel32.NewProc("K32GetMappedFileNameW")
)

// JIT / 浏览器类进程合法地使用私有可执行内存，相关发现降级为 medium（只进时间线）。
var integrityJITHosts = map[string]bool{
	"chrome.exe": true, "msedge.exe": true, "msedgewebview2.exe": true, "firefox.exe": true,
	"brave.exe": true, "opera.exe": true, "iexplore.exe": true, "node.exe": true, "code.exe": true,
	"java.exe": true, "javaw.exe": true, "dotnet.exe": true, "powershell.exe": true, "pwsh.exe": true,
	"powershell_ise.exe": true, "w3wp.exe": true, "teams.exe": true, "ms-teams.exe": true,
	"slack.exe": true, "discord.exe": true, "devenv.exe": true, "searchhost.exe": true,
	"widgets.exe": true, "msmpeng.exe": true, "mssense.exe": true,
}

var integritySkipNames = map[string]bool{
	"system": true, "registry": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true,
	"services.exe": true, "memory compression": true, "secure system": true, "[system process]": true,
}

type integrityFunc struct {
	name string
	kind string // etw_patch | amsi_patch | ntdll_hook
	rva  uintptr
	ref  []byte
}

type integrityRef struct {
	dll   string
	path  string // 本进程中该 DLL 的完整路径（小写），只和同路径模块比对，天然跳过 WOW64 的 32 位副本
	funcs []integrityFunc
}

var (
	integrityRefsOnce sync.Once
	integrityRefs     []integrityRef

	integrityDedupMu sync.Mutex
	integrityDedup   = map[string]time.Time{}
)

func readProcMem(h windows.Handle, addr uintptr, n int) ([]byte, bool) {
	if n <= 0 || addr == 0 {
		return nil, false
	}
	buf := make([]byte, n)
	var got uintptr
	if err := windows.ReadProcessMemory(h, addr, &buf[0], uintptr(n), &got); err != nil || int(got) < n {
		return nil, false
	}
	return buf, true
}

func moduleFilePath(h windows.Handle) string {
	var buf [windows.MAX_PATH]uint16
	n, err := windows.GetModuleFileName(h, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func loadIntegrityRefs() []integrityRef {
	integrityRefsOnce.Do(func() {
		specs := []struct {
			dll   string
			kind  string
			funcs []string
		}{
			{"ntdll.dll", "etw_patch", []string{"EtwEventWrite", "EtwEventWriteFull", "EtwEventWriteTransfer", "NtTraceEvent"}},
			{"amsi.dll", "amsi_patch", []string{"AmsiScanBuffer", "AmsiScanString", "AmsiOpenSession"}},
			{"ntdll.dll", "ntdll_hook", []string{
				"NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
				"NtReadVirtualMemory", "NtCreateThreadEx", "NtMapViewOfSection", "NtQueueApcThread",
			}},
		}
		self := windows.CurrentProcess()
		byDll := map[string]int{}
		for _, s := range specs {
			h, err := windows.LoadLibraryEx(s.dll, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
			if err != nil {
				continue
			}
			idx, ok := byDll[s.dll]
			if !ok {
				integrityRefs = append(integrityRefs, integrityRef{dll: s.dll, path: strings.ToLower(moduleFilePath(h))})
				idx = len(integrityRefs) - 1
				byDll[s.dll] = idx
			}
			for _, fn := range s.funcs {
				addr, err := windows.GetProcAddress(h, fn)
				if err != nil || addr == 0 {
					continue
				}
				ref, ok := readProcMem(self, addr, integrityCompareBytes)
				if !ok {
					continue
				}
				integrityRefs[idx].funcs = append(integrityRefs[idx].funcs, integrityFunc{
					name: fn, kind: s.kind, rva: addr - uintptr(h), ref: ref,
				})
			}
		}
	})
	return integrityRefs
}

func snapshotThreadsByPID() map[uint32][]uint32 {
	out := map[uint32][]uint32{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		out[te.OwnerProcessID] = append(out[te.OwnerProcessID], te.ThreadID)
		te.Size = uint32(unsafe.Sizeof(te))
	}
	return out
}

type modSpan struct {
	base uintptr
	end  uintptr
	path string
}

func snapshotModuleSpans(pid uint32) ([]modSpan, bool) {
	var snap windows.Handle
	var err error
	for i := 0; i < 3; i++ {
		snap, err = windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
		if err != windows.ERROR_BAD_LENGTH {
			break
		}
	}
	if err != nil {
		return nil, false
	}
	defer windows.CloseHandle(snap)
	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	var out []modSpan
	for err = windows.Module32First(snap, &me); err == nil; err = windows.Module32Next(snap, &me) {
		out = append(out, modSpan{
			base: me.ModBaseAddr,
			end:  me.ModBaseAddr + uintptr(me.ModBaseSize),
			path: strings.ToLower(windows.UTF16ToString(me.ExePath[:])),
		})
		me.Size = uint32(unsafe.Sizeof(me))
	}
	return out, len(out) > 0
}

func threadStartAddress(tid uint32) (uintptr, bool) {
	h, err := windows.OpenThread(windows.THREAD_QUERY_INFORMATION, false, tid)
	if err != nil {
		h, err = windows.OpenThread(threadQueryLimitedInformation, false, tid)
		if err != nil {
			return 0, false
		}
	}
	defer windows.CloseHandle(h)
	var start uintptr
	r, _, _ := procNtQueryInformationThread.Call(
		uintptr(h), threadQuerySetWin32StartAddress,
		uintptr(unsafe.Pointer(&start)), unsafe.Sizeof(start), 0,
	)
	if r != 0 || start == 0 {
		return 0, false
	}
	return start, true
}

func mappedFileName(h windows.Handle, addr uintptr) string {
	if procK32GetMappedFileNameW.Find() != nil {
		return ""
	}
	var buf [1024]uint16
	n, _, _ := procK32GetMappedFileNameW.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func isExecProtect(p uint32) bool {
	return p&(windows.PAGE_EXECUTE|windows.PAGE_EXECUTE_READ|windows.PAGE_EXECUTE_READWRITE|windows.PAGE_EXECUTE_WRITECOPY) != 0
}

func memTypeLabel(t uint32) string {
	switch t {
	case memTypePrivate:
		return "private"
	case memTypeMapped:
		return "mapped"
	case memTypeImage:
		return "image"
	}
	return fmt.Sprintf("0x%X", t)
}

// patchShape 描述被改写字节的形态，便于研判。
func patchShape(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch {
	case b[0] == 0xC3 || b[0] == 0xC2:
		return "直接返回(ret)"
	case len(b) >= 3 && b[0] == 0x33 && b[1] == 0xC0 && b[2] == 0xC3:
		return "xor eax,eax; ret"
	case len(b) >= 3 && b[0] == 0x31 && b[1] == 0xC0 && b[2] == 0xC3:
		return "xor eax,eax; ret"
	case b[0] == 0xB8 && len(b) >= 6 && b[5] == 0xC3:
		return "mov eax,imm; ret"
	case b[0] == 0xE9 || b[0] == 0xEB:
		return "跳转挂钩(jmp)"
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0x25:
		return "跳转挂钩(jmp [rip])"
	case len(b) >= 2 && (b[0] == 0x48 || b[0] == 0x49) && (b[1] == 0xB8 || b[1] == 0xBA || b[1] == 0xBB):
		return "跳转挂钩(mov reg,abs; jmp)"
	case b[0] == 0xCC:
		return "断点(int3)"
	}
	return "字节被修改"
}

func isReturnPatch(shape string) bool {
	return strings.Contains(shape, "ret")
}

// hookTarget 解析入口处跳转指令的目的地址；无法解析返回 0。
func hookTarget(h windows.Handle, fnAddr uintptr, b []byte) uintptr {
	le32 := func(p []byte) int32 {
		return int32(uint32(p[0]) | uint32(p[1])<<8 | uint32(p[2])<<16 | uint32(p[3])<<24)
	}
	le64 := func(p []byte) uintptr {
		var v uint64
		for i := 7; i >= 0; i-- {
			v = v<<8 | uint64(p[i])
		}
		return uintptr(v)
	}
	switch {
	case len(b) >= 5 && b[0] == 0xE9:
		return uintptr(int64(fnAddr) + 5 + int64(le32(b[1:5])))
	case len(b) >= 6 && b[0] == 0xFF && b[1] == 0x25:
		slot := uintptr(int64(fnAddr) + 6 + int64(le32(b[2:6])))
		if p, ok := readProcMem(h, slot, 8); ok {
			return le64(p)
		}
	case len(b) >= 10 && (b[0] == 0x48 || b[0] == 0x49) && b[1] >= 0xB8 && b[1] <= 0xBF:
		return le64(b[2:10])
	}
	return 0
}

func addrMemType(h windows.Handle, a uintptr) uint32 {
	if a == 0 {
		return 0
	}
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQueryEx(h, a, &mbi, unsafe.Sizeof(mbi)); err != nil || mbi.State != windows.MEM_COMMIT {
		return 0
	}
	return mbi.Type
}

func processImagePath(h windows.Handle) string {
	var buf [windows.MAX_PATH * 2]uint16
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil || n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

type execRegion struct {
	base    uintptr
	alloc   uintptr
	size    uintptr
	protect uint32
	typ     uint32
	mz      bool
}

type integrityOpts struct {
	verbose bool // 定向扫描：额外报告断链镜像 / 私有可执行内存统计
}

func integrityFinding(typ, sev string, pid uint32, name, summary string, extra map[string]any) map[string]any {
	f := map[string]any{
		"type": typ, "pid": pid, "name": name, "severity": sev,
		"engine": "integrity", "summary": summary,
	}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

func inspectProcessIntegrity(pid uint32, name string, tids []uint32, refs []integrityRef, opt integrityOpts) []map[string]any {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	low := strings.ToLower(name)
	jit := integrityJITHosts[low]
	var out []map[string]any

	// 1) 遍历地址空间：收集非镜像可执行区，记录镜像分配基址
	var regions []execRegion
	imageBases := map[uintptr]bool{}
	var addr uintptr
	for i := 0; i < 200000; i++ {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		if mbi.RegionSize == 0 {
			break
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
		if mbi.State != windows.MEM_COMMIT {
			continue
		}
		if mbi.Type == memTypeImage {
			imageBases[mbi.AllocationBase] = true
			continue
		}
		if !isExecProtect(mbi.Protect) || mbi.Protect&windows.PAGE_GUARD != 0 {
			continue
		}
		r := execRegion{base: mbi.BaseAddress, alloc: mbi.AllocationBase, size: mbi.RegionSize, protect: mbi.Protect, typ: mbi.Type}
		if hdr, ok := readProcMem(h, mbi.BaseAddress, 2); ok && hdr[0] == 'M' && hdr[1] == 'Z' {
			r.mz = true
		} else if mbi.AllocationBase != mbi.BaseAddress {
			// 反射加载常见：头部页已改回只读，代码节为 RX；看分配基址
			if hdr, ok := readProcMem(h, mbi.AllocationBase, 2); ok && hdr[0] == 'M' && hdr[1] == 'Z' {
				r.mz = true
			}
		}
		regions = append(regions, r)
	}

	findRegion := func(a uintptr) *execRegion {
		for i := range regions {
			if a >= regions[i].base && a < regions[i].base+regions[i].size {
				return &regions[i]
			}
		}
		return nil
	}

	// 2) 线程起始地址：落在非镜像内存即为注入线程特征
	type badThread struct {
		tid   uint32
		start uintptr
		reg   *execRegion
		typ   uint32
	}
	var bad []badThread
	var allStarts []uintptr
	for _, tid := range tids {
		start, ok := threadStartAddress(tid)
		if !ok {
			continue
		}
		allStarts = append(allStarts, start)
		if reg := findRegion(start); reg != nil {
			bad = append(bad, badThread{tid: tid, start: start, reg: reg, typ: reg.typ})
			continue
		}
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(h, start, &mbi, unsafe.Sizeof(mbi)); err == nil &&
			mbi.State == windows.MEM_COMMIT && mbi.Type != memTypeImage && mbi.Type != 0 {
			bad = append(bad, badThread{tid: tid, start: start, typ: mbi.Type})
		}
	}

	reportedRegion := map[uintptr]bool{}
	for _, b := range bad {
		if len(out) >= 8 {
			break
		}
		if b.reg != nil && b.reg.mz {
			reportedRegion[b.reg.alloc] = true
			out = append(out, integrityFinding("process_injection", "critical", pid, name,
				fmt.Sprintf("进程注入：%s pid=%d 线程 %d 起始于带 PE 头的非镜像可执行内存 @0x%X", name, pid, b.tid, b.start),
				map[string]any{
					"tid": b.tid, "address": fmt.Sprintf("0x%X", b.start),
					"region_base": fmt.Sprintf("0x%X", b.reg.alloc), "region_type": memTypeLabel(b.reg.typ),
					"protect": fmt.Sprintf("0x%X", b.reg.protect),
					"mitre":   []string{"T1055", "T1620"},
					"evidence": "线程起始地址在非镜像内存 + 该内存含 MZ 头",
				}))
			continue
		}
		sev := "high"
		if jit {
			sev = "medium"
		}
		out = append(out, integrityFinding("unbacked_thread", sev, pid, name,
			fmt.Sprintf("无模块线程：%s pid=%d 线程 %d 起始于%s内存 @0x%X", name, pid, b.tid, memTypeLabel(b.typ), b.start),
			map[string]any{
				"tid": b.tid, "address": fmt.Sprintf("0x%X", b.start), "region_type": memTypeLabel(b.typ),
				"jit_host": jit, "mitre": []string{"T1055"},
				"evidence": "线程起始地址不属于任何已加载镜像",
			}))
	}

	// 3) 非镜像可执行内存中的 PE（反射加载 / 手工映射）
	// 安全软件、内存加载驱动 DLL 的工具也会这样做：宿主进程签名有效时降为 medium（只进时间线）
	imagePath := processImagePath(h)
	signedChecked, hostSigned := false, false
	var pePerProc int
	for _, r := range regions {
		if !r.mz || reportedRegion[r.alloc] || len(out) >= 12 {
			continue
		}
		reportedRegion[r.alloc] = true
		pePerProc++
		if pePerProc > 3 {
			continue
		}
		if !signedChecked {
			signedChecked = true
			if imagePath != "" {
				hostSigned, _ = peSignedValid(imagePath)
			}
		}
		sev := "high"
		if jit || hostSigned {
			sev = "medium"
		}
		out = append(out, integrityFinding("reflective_pe", sev, pid, name,
			fmt.Sprintf("内存反射 PE：%s pid=%d 在%s可执行内存 @0x%X 发现 PE 头", name, pid, memTypeLabel(r.typ), r.alloc),
			map[string]any{
				"address": fmt.Sprintf("0x%X", r.alloc), "region_type": memTypeLabel(r.typ),
				"protect": fmt.Sprintf("0x%X", r.protect), "size": uint64(r.size),
				"path": imagePath, "host_signed": hostSigned,
				"jit_host": jit, "mitre": []string{"T1620"},
				"evidence": "非文件映射的可执行内存以 MZ 开头",
			}))
	}
	if pePerProc > 3 && len(out) > 0 {
		out[len(out)-1]["more_regions"] = pePerProc - 3
	}

	// 4) ntdll / amsi 关键函数完整性
	mods, modsOK := snapshotModuleSpans(pid)
	reportedFn := map[string]bool{}
	if modsOK {
		for _, ref := range refs {
			if ref.path == "" || len(ref.funcs) == 0 {
				continue
			}
			var base uintptr
			for _, m := range mods {
				if m.path == ref.path {
					base = m.base
					break
				}
			}
			if base == 0 {
				continue
			}
			for _, fn := range ref.funcs {
				fnAddr := base + fn.rva
				got, ok := readProcMem(h, fnAddr, 16)
				if !ok || string(got[:len(fn.ref)]) == string(fn.ref) {
					continue
				}
				shape := patchShape(got)
				target := hookTarget(h, fnAddr, got)
				targetType := addrMemType(h, target)
				sev, title := "high", ""
				var mitre []string
				switch fn.kind {
				case "etw_patch":
					title = "ETW 被篡改"
					mitre = []string{"T1562.006"}
					if isReturnPatch(shape) {
						sev = "critical"
					}
				case "amsi_patch":
					title = "AMSI 被篡改"
					mitre = []string{"T1562.001"}
					if isReturnPatch(shape) {
						sev = "critical"
					}
				default:
					// 跳到已加载模块里的挂钩是合法拦截（Chromium 沙箱、安全软件、游戏覆盖层）
					if targetType == memTypeImage {
						continue
					}
					title = "ntdll 挂钩"
					mitre = []string{"T1562.001"}
					sev = "medium"
					if isReturnPatch(shape) || (target != 0 && targetType != 0) {
						sev = "high"
					}
				}
				extra := map[string]any{
					"module": ref.dll, "function": fn.name, "patch_shape": shape,
					"address":  fmt.Sprintf("0x%X", fnAddr),
					"expected": hex.EncodeToString(fn.ref), "actual": hex.EncodeToString(got[:len(fn.ref)]),
					"mitre":    mitre,
					"evidence": "函数入口字节与干净副本不一致",
				}
				if target != 0 {
					extra["hook_target"] = fmt.Sprintf("0x%X", target)
					extra["hook_target_type"] = memTypeLabel(targetType)
					if targetType != memTypeImage && targetType != 0 {
						extra["evidence"] = "函数入口被改为跳转到非镜像内存"
					}
				}
				reportedFn[fmt.Sprintf("0x%X", fnAddr)] = true
				out = append(out, integrityFinding(fn.kind, sev, pid, name,
					fmt.Sprintf("%s：%s pid=%d %s!%s %s", title, name, pid, ref.dll, fn.name, shape), extra))
			}
		}
		// 5) 镜像代码页 / EAT / IAT 完整性（覆盖全部模块，含 32 位进程）
		out = append(out, inspectImageIntegrity(h, pid, name, mods, allStarts, jit, reportedFn)...)
	}

	// 5) 定向扫描：断链镜像 + 私有可执行内存统计
	if opt.verbose && modsOK {
		known := map[uintptr]bool{}
		for _, m := range mods {
			known[m.base] = true
		}
		n := 0
		for base := range imageBases {
			if known[base] || n >= 5 {
				continue
			}
			file := mappedFileName(h, base)
			lf := strings.ToLower(file)
			// 资源型加载（LOAD_LIBRARY_AS_IMAGE_RESOURCE）和系统 MUI 不入链表，属正常
			if lf == "" || strings.HasSuffix(lf, ".mui") || strings.HasSuffix(lf, ".mun") || strings.Contains(lf, `\windows\`) {
				continue
			}
			n++
			out = append(out, integrityFinding("unlinked_image", "medium", pid, name,
				fmt.Sprintf("断链镜像：%s pid=%d 映射了不在模块链表中的镜像 %s", name, pid, file),
				map[string]any{
					"address": fmt.Sprintf("0x%X", base), "mapped_file": file,
					"mitre": []string{"T1055", "T1564"}, "evidence": "MEM_IMAGE 区域未出现在 PEB 模块链表",
				}))
		}
		privExec, rwx := 0, 0
		for _, r := range regions {
			if r.typ == memTypePrivate {
				privExec++
				if r.protect&windows.PAGE_EXECUTE_READWRITE != 0 {
					rwx++
				}
			}
		}
		if privExec > 0 && !jit {
			out = append(out, integrityFinding("private_exec_memory", "medium", pid, name,
				fmt.Sprintf("私有可执行内存：%s pid=%d 共 %d 段（RWX %d 段）", name, pid, privExec, rwx),
				map[string]any{"count": privExec, "rwx": rwx, "mitre": []string{"T1055"},
					"evidence": "非文件映射的可执行内存，需结合线程与网络行为判断"}))
		}
	}
	return out
}

func integrityDedupKey(f map[string]any) string {
	return fmt.Sprintf("%v|%v|%v|%v|%v", f["type"], f["pid"], f["name"], f["function"], f["address"])
}

func integrityFresh(f map[string]any) bool {
	k := integrityDedupKey(f)
	now := time.Now()
	integrityDedupMu.Lock()
	defer integrityDedupMu.Unlock()
	if len(integrityDedup) > 5000 {
		for key, t := range integrityDedup {
			if now.Sub(t) > integrityDedupTTL {
				delete(integrityDedup, key)
			}
		}
	}
	if t, ok := integrityDedup[k]; ok && now.Sub(t) < integrityDedupTTL {
		return false
	}
	integrityDedup[k] = now
	return true
}

// runIntegrityChecks 对全部进程（或指定 pid）做完整性检查；dedup=true 时同一发现 12 小时内只报一次。
func runIntegrityChecks(targetPID int, dedup bool) ([]map[string]any, int) {
	procs, err := listPIDs()
	if err != nil {
		return nil, 0
	}
	threads := snapshotThreadsByPID()
	refs := loadIntegrityRefs()
	self := uint32(windowsGetpid())
	var findings []map[string]any
	scanned := 0
	for _, p := range procs {
		if p.pid == 0 || p.pid == 4 || p.pid == self {
			continue
		}
		if targetPID > 0 && int(p.pid) != targetPID {
			continue
		}
		if integritySkipNames[strings.ToLower(p.name)] {
			continue
		}
		if scanned >= integrityMaxProcesses {
			break
		}
		scanned++
		for _, f := range inspectProcessIntegrity(p.pid, p.name, threads[p.pid], refs, integrityOpts{verbose: targetPID > 0}) {
			if dedup && !integrityFresh(f) {
				continue
			}
			findings = append(findings, f)
			if len(findings) >= integrityMaxFindings {
				return findings, scanned
			}
		}
	}
	return findings, scanned
}

func windowsGetpid() uint32 {
	return windows.GetCurrentProcessId()
}

// runIntegritySweep 定时全量巡检入口。
func runIntegritySweep() map[string]any {
	ms := memoryScanSettingsSnapshot()
	if ms.Mode == memModeOff || !ms.IntegrityChecks {
		return nil
	}
	t0 := time.Now()
	findings, scanned := runIntegrityChecks(0, true)
	return map[string]any{
		"ok": true, "mode": "integrity_sweep", "trigger": "integrity_schedule",
		"scanned": scanned, "findings": findings, "finding_count": len(findings),
		"elapsed_ms": time.Since(t0).Milliseconds(),
		"ts":         time.Now().Format("2006-01-02T15:04:05"),
	}
}
