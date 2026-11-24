//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 镜像代码完整性：
//   - 被改写的代码页（工作集里不再共享的镜像页）逐字节对比磁盘 → 模块覆盖 / 内联挂钩
//   - 关键系统 DLL 的导出地址表（EAT）对比磁盘
//   - 所有模块的导入地址表（IAT）指向非镜像内存
// 内存中的 PE 头时间戳/镜像大小与磁盘不一致时（系统更新后旧进程）跳过该模块。

var procK32QueryWorkingSetEx = modKernel32.NewProc("K32QueryWorkingSetEx")

type wsExInfo struct {
	VirtualAddress    uintptr
	VirtualAttributes uintptr
}

const (
	imgPage            = 0x1000
	wsValidBit         = 1
	wsSharedBit        = 1 << 15
	codeIntMaxPages    = 60000
	codeIntMaxModified = 48
	codeIntMaxModules  = 400
)

var integrityCriticalDLLs = map[string]bool{
	"ntdll.dll": true, "kernel32.dll": true, "kernelbase.dll": true, "amsi.dll": true,
	"advapi32.dll": true, "sechost.dll": true, "user32.dll": true, "ws2_32.dll": true,
	"wininet.dll": true, "winhttp.dll": true, "crypt32.dll": true,
}

// .NET / CRT 运行时会合法改写自身代码页，不做模块覆盖告警
func stompingSkipModule(name string) bool {
	n := strings.ToLower(name)
	switch {
	case n == "clr.dll", n == "coreclr.dll", n == "clrjit.dll", n == "mscorjit.dll",
		n == "mscorlib.ni.dll", n == "system.ni.dll", n == "ucrtbase.dll":
		return true
	case strings.HasPrefix(n, "msvcr"), strings.HasPrefix(n, "msvcp"), strings.HasPrefix(n, "vcruntime"):
		return true
	}
	return false
}

type moduleView struct {
	span      modSpan
	disk      *diskPE
	name      string
	verified  int8 // 0 未查 1 一致 -1 不一致
	modified  bool
	findCount int
}

func (m *moduleView) versionOK(h windows.Handle) bool {
	if m.verified != 0 {
		return m.verified > 0
	}
	m.verified = -1
	hdr, ok := readProcMem(h, m.span.base, 0x400)
	if !ok {
		return false
	}
	lf := binary.LittleEndian.Uint32(hdr[0x3c:])
	if lf+24+60 > uint32(len(hdr)) {
		return false
	}
	ts := binary.LittleEndian.Uint32(hdr[lf+8:])
	soi := binary.LittleEndian.Uint32(hdr[lf+24+56:])
	if ts == m.disk.timeStamp && soi == m.disk.sizeOfImage {
		m.verified = 1
	}
	return m.verified > 0
}

func moduleViews(mods []modSpan) []*moduleView {
	var out []*moduleView
	for _, m := range mods {
		if len(out) >= codeIntMaxModules {
			break
		}
		if m.path == "" {
			continue
		}
		d, err := loadDiskPE(m.path)
		if err != nil || d == nil {
			continue
		}
		out = append(out, &moduleView{span: m, disk: d, name: strings.ToLower(filepath.Base(m.path))})
	}
	return out
}

func inModuleSpans(mods []modSpan, a uintptr) bool {
	for _, m := range mods {
		if a >= m.base && a < m.end {
			return true
		}
	}
	return false
}

type diffRun struct {
	off, n int
}

// diffRuns 返回 mem 与 disk 不同（排除重定位字节）的连续区段，间隔 < 8 字节的合并。
func diffRuns(mem, disk []byte, mask []bool) []diffRun {
	var runs []diffRun
	n := len(disk)
	if len(mem) < n {
		n = len(mem)
	}
	for i := 0; i < n; i++ {
		if mem[i] == disk[i] || (i < len(mask) && mask[i]) {
			continue
		}
		if k := len(runs) - 1; k >= 0 && i-(runs[k].off+runs[k].n) < 8 {
			runs[k].n = i - runs[k].off + 1
			continue
		}
		runs = append(runs, diffRun{off: i, n: 1})
	}
	return runs
}

func inspectImageIntegrity(h windows.Handle, pid uint32, name string, mods []modSpan, threadStarts []uintptr, jit bool, reported map[string]bool) []map[string]any {
	views := moduleViews(mods)
	if len(views) == 0 {
		return nil
	}
	var out []map[string]any
	out = append(out, modifiedCodePages(h, pid, name, views, threadStarts, jit, reported)...)
	out = append(out, eatHooks(h, pid, name, views, mods, jit)...)
	out = append(out, iatHooks(h, pid, name, views, mods, jit)...)
	return out
}

func modifiedCodePages(h windows.Handle, pid uint32, name string, views []*moduleView, threadStarts []uintptr, jit bool, reported map[string]bool) []map[string]any {
	if procK32QueryWorkingSetEx.Find() != nil {
		return nil
	}
	type pageRef struct {
		view *moduleView
		rva  uint32
	}
	var refs []pageRef
	var infos []wsExInfo
	for _, v := range views {
		for _, s := range v.disk.sections {
			if !s.exec {
				continue
			}
			size := max32(s.vsize, s.rawLen)
			for off := uint32(0); off < size && len(infos) < codeIntMaxPages; off += imgPage {
				rva := s.va + off
				infos = append(infos, wsExInfo{VirtualAddress: v.span.base + uintptr(rva)})
				refs = append(refs, pageRef{view: v, rva: rva})
			}
		}
	}
	if len(infos) == 0 {
		return nil
	}
	r, _, _ := procK32QueryWorkingSetEx.Call(uintptr(h), uintptr(unsafe.Pointer(&infos[0])), uintptr(len(infos))*unsafe.Sizeof(infos[0]))
	if r == 0 {
		return nil
	}

	type locus struct {
		rva     uint32
		n       int
		fn      string
		fnOff   uint32
		shape   string
		target  uintptr
		ttype   uint32
		atEntry bool
	}
	type modHits struct {
		view   *moduleView
		hooks  []locus
		stomp  []locus
		minor  []locus
		thread bool
		bytes  int
	}
	hits := map[*moduleView]*modHits{}
	checked := 0
	for i, inf := range infos {
		a := inf.VirtualAttributes
		if a&wsValidBit == 0 || a&wsSharedBit != 0 {
			continue
		}
		if checked >= codeIntMaxModified {
			break
		}
		ref := refs[i]
		v := ref.view
		if !v.versionOK(h) {
			continue
		}
		checked++
		mem, ok := readProcMem(h, v.span.base+uintptr(ref.rva), imgPage)
		if !ok {
			continue
		}
		disk := v.disk.readRVA(ref.rva, imgPage)
		if len(disk) == 0 {
			continue
		}
		runs := diffRuns(mem, disk, v.disk.relocMask(ref.rva, uint32(len(disk))))
		if len(runs) == 0 {
			continue
		}
		mh := hits[v]
		if mh == nil {
			mh = &modHits{view: v}
			hits[v] = mh
		}
		pageStart := v.span.base + uintptr(ref.rva)
		for _, ts := range threadStarts {
			if ts >= pageStart && ts < pageStart+imgPage {
				mh.thread = true
			}
		}
		for _, run := range runs {
			rva := ref.rva + uint32(run.off)
			mh.bytes += run.n
			fn, fnOff := v.disk.nearestExport(rva)
			lc := locus{rva: rva, n: run.n, fn: fn, fnOff: fnOff}
			// 仅函数入口附近（≤3 字节）才按挂钩分析，避免函数体中段 1 字节差异误报
			if fn != "" && fnOff <= 3 && run.n <= 32 {
				entry := v.span.base + uintptr(rva-fnOff)
				code, _ := readProcMem(h, entry, 16)
				lc.atEntry = true
				lc.shape = patchShape(code)
				lc.target = hookTarget(h, entry, code)
				lc.ttype = addrMemType(h, lc.target)
				key := fmt.Sprintf("0x%X", entry)
				if reported[key] {
					continue
				}
				// 跳到已加载镜像里的挂钩是合法拦截（安全软件、Chromium 沙箱、兼容垫片）
				if lc.ttype == memTypeImage && !isReturnPatch(lc.shape) {
					continue
				}
				// Chromium / Electron / 运行时常改写该入口，噪声极高
				if lc.fn == "SetUnhandledExceptionFilter" {
					continue
				}
				reported[key] = true
				mh.hooks = append(mh.hooks, lc)
				continue
			}
			if stompingSkipModule(v.name) {
				continue
			}
			if run.n >= 32 {
				mh.stomp = append(mh.stomp, lc)
			} else {
				mh.minor = append(mh.minor, lc)
			}
		}
	}

	var out []map[string]any
	loc := func(v *moduleView, ls []locus) []string {
		var s []string
		for i, l := range ls {
			if i >= 5 {
				break
			}
			where := fmt.Sprintf("+0x%X", l.rva)
			if l.fn != "" {
				where = fmt.Sprintf("%s+0x%X", l.fn, l.fnOff)
			}
			item := fmt.Sprintf("%s(%dB)", where, l.n)
			if l.shape != "" {
				item += " " + l.shape
			}
			if l.target != 0 {
				item += fmt.Sprintf(" → 0x%X[%s]", l.target, memTypeLabel(l.ttype))
			}
			s = append(s, item)
		}
		return s
	}
	for v, mh := range hits {
		mod := v.name
		if len(mh.hooks) > 0 {
			sev := "high"
			if jit && !isReturnPatch(mh.hooks[0].shape) {
				sev = "medium"
			}
			kind := "inline_hook"
			mitre := []string{"T1562.001"}
			switch {
			case mod == "amsi.dll":
				kind = "amsi_patch"
				sev = "critical"
			case mod == "ntdll.dll" && strings.HasPrefix(mh.hooks[0].fn, "Etw"):
				kind = "etw_patch"
				mitre = []string{"T1562.006"}
				sev = "critical"
			}
			out = append(out, integrityFinding(kind, sev, pid, name,
				fmt.Sprintf("函数被挂钩/篡改：%s pid=%d %s 共 %d 处，%s", name, pid, mod, len(mh.hooks), strings.Join(loc(v, mh.hooks), "；")),
				map[string]any{
					"module": mod, "module_path": v.span.path, "locations": loc(v, mh.hooks),
					"function": mh.hooks[0].fn, "address": fmt.Sprintf("0x%X", v.span.base+uintptr(mh.hooks[0].rva)),
					"jit_host": jit, "mitre": mitre,
					"evidence": "镜像代码页被改写，函数入口与磁盘文件不一致且不是跳往已加载模块",
				}))
		}
		if len(mh.stomp) > 0 {
			sev := "medium"
			if integrityCriticalDLLs[mod] || mh.thread {
				sev = "high"
			}
			if mh.thread && integrityCriticalDLLs[mod] {
				sev = "critical"
			}
			out = append(out, integrityFinding("module_stomping", sev, pid, name,
				fmt.Sprintf("模块代码被覆盖：%s pid=%d %s 被改写 %d 字节%s", name, pid, mod, mh.bytes, map[bool]string{true: "，且有线程从被改写处启动", false: ""}[mh.thread]),
				map[string]any{
					"module": mod, "module_path": v.span.path, "locations": loc(v, mh.stomp),
					"modified_bytes": mh.bytes, "thread_in_modified": mh.thread,
					"address": fmt.Sprintf("0x%X", v.span.base+uintptr(mh.stomp[0].rva)),
					"mitre":    []string{"T1055", "T1027"},
					"evidence": "镜像代码页与磁盘文件大段不一致（模块覆盖 / Module Stomping）",
				}))
		}
		// 仅小范围改动、无挂钩/无覆盖：IME/热补丁噪声极大，要求改动量足够且非 user32 一类常被垫片触碰的模块
		if len(mh.stomp) == 0 && len(mh.hooks) == 0 && len(mh.minor) >= 4 && mh.bytes >= 24 &&
			integrityCriticalDLLs[mod] && mod != "user32.dll" && mod != "imm32.dll" {
			out = append(out, integrityFinding("image_code_modified", "medium", pid, name,
				fmt.Sprintf("系统模块代码被修改：%s pid=%d %s 共 %d 处小范围改动", name, pid, mod, len(mh.minor)),
				map[string]any{
					"module": mod, "module_path": v.span.path, "locations": loc(v, mh.minor),
					"mitre": []string{"T1562.001"}, "evidence": "系统 DLL 代码页与磁盘文件存在少量差异",
				}))
		}
	}
	return out
}

func eatHooks(h windows.Handle, pid uint32, name string, views []*moduleView, mods []modSpan, jit bool) []map[string]any {
	var out []map[string]any
	for _, v := range views {
		if !integrityCriticalDLLs[v.name] || len(v.disk.eat) == 0 || v.disk.eatRVA == 0 {
			continue
		}
		if !v.versionOK(h) {
			continue
		}
		mem, ok := readProcMem(h, v.span.base+uintptr(v.disk.eatRVA), len(v.disk.eat)*4)
		if !ok {
			continue
		}
		var locs []string
		for i, want := range v.disk.eat {
			got := binary.LittleEndian.Uint32(mem[i*4:])
			if got == want {
				continue
			}
			target := v.span.base + uintptr(got)
			imgEnd := v.span.base + uintptr(v.disk.sizeOfImage)
			// 同模块内重排 / 指向其它已加载镜像：多为安全软件或系统垫片，不告警
			if target >= v.span.base && target < imgEnd {
				continue
			}
			if inModuleSpans(mods, target) && addrMemType(h, target) == memTypeImage {
				continue
			}
			fn := v.disk.exportName[want]
			if fn == "" {
				fn = fmt.Sprintf("#%d", i)
			}
			if len(locs) < 5 {
				locs = append(locs, fmt.Sprintf("%s → 0x%X", fn, target))
			}
		}
		if len(locs) == 0 {
			continue
		}
		sev := "high"
		if jit {
			sev = "medium"
		}
		out = append(out, integrityFinding("eat_hook", sev, pid, name,
			fmt.Sprintf("导出表被篡改：%s pid=%d %s %s", name, pid, v.name, strings.Join(locs, "；")),
			map[string]any{
				"module": v.name, "module_path": v.span.path, "locations": locs, "points_outside_image": true,
				"mitre": []string{"T1574", "T1562.001"}, "evidence": "导出地址被改写到非镜像/私有内存",
			}))
	}
	return out
}

func iatHooks(h windows.Handle, pid uint32, name string, views []*moduleView, mods []modSpan, jit bool) []map[string]any {
	var out []map[string]any
	reportedMods := 0
	for _, v := range views {
		if reportedMods >= 3 {
			break
		}
		d := v.disk
		if d.iatRVA == 0 || d.iatSize == 0 || d.iatSize > 64<<10 {
			continue
		}
		if !v.versionOK(h) {
			continue
		}
		mem, ok := readProcMem(h, v.span.base+uintptr(d.iatRVA), int(d.iatSize))
		if !ok {
			continue
		}
		width := 4
		if d.is64 {
			width = 8
		}
		var locs []string
		for off := 0; off+width <= len(mem); off += width {
			var ptr uintptr
			if width == 8 {
				ptr = uintptr(binary.LittleEndian.Uint64(mem[off:]))
			} else {
				ptr = uintptr(binary.LittleEndian.Uint32(mem[off:]))
			}
			if ptr == 0 || inModuleSpans(mods, ptr) {
				continue
			}
			t := addrMemType(h, ptr)
			if t == 0 || t == memTypeImage {
				continue
			}
			if len(locs) < 5 {
				locs = append(locs, fmt.Sprintf("IAT+0x%X → 0x%X[%s]", off, ptr, memTypeLabel(t)))
			}
		}
		if len(locs) == 0 {
			continue
		}
		reportedMods++
		sev := "high"
		if jit {
			sev = "medium"
		}
		out = append(out, integrityFinding("iat_hook", sev, pid, name,
			fmt.Sprintf("导入表被挂钩：%s pid=%d %s %s", name, pid, v.name, strings.Join(locs, "；")),
			map[string]any{
				"module": v.name, "module_path": v.span.path, "locations": locs,
				"mitre": []string{"T1574", "T1056.004"}, "evidence": "导入地址表项指向非镜像内存",
			}))
	}
	return out
}
