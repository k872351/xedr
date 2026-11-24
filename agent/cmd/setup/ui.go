//go:build windows

package main

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	gdi32                = windows.NewLazySystemDLL("gdi32.dll")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procLoadCursorW      = user32.NewProc("LoadCursorW")
	procGetWindowTextW   = user32.NewProc("GetWindowTextW")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procCreateFontW      = gdi32.NewProc("CreateFontW")
)

const (
	wsChild         = 0x40000000
	wsVisible       = 0x10000000
	wsTabstop       = 0x00010000
	wsBorder        = 0x00800000
	wsVScroll       = 0x00200000
	wsCaption       = 0x00C00000
	wsSysMenu       = 0x00080000
	wsMinimizeBox   = 0x00020000
	wsESMultiline   = 0x0004
	wsESAutoVScroll = 0x0040
	wsESAutoHScroll = 0x0080
	wsESReadOnly    = 0x0800
	wsBSAutoCheck   = 0x00000003

	swShow       = 5
	idcArrow     = 32512
	wmDestroy    = 0x0002
	wmCommand    = 0x0111
	wmSetFont    = 0x0030
	bmGetCheck   = 0x00F0
	bstChecked   = 1
	emReplaceSel = 0x00C2
	emSetSel     = 0x00B1
	colorBtnFace = 15
	smCXScreen   = 0
	smCYScreen   = 1
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type point struct{ X, Y int32 }
type msg struct {
	Hwnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type uiState struct {
	root      string
	hwnd      windows.Handle
	editURL   windows.Handle
	chkDriver windows.Handle
	editLog   windows.Handle
	btnOK     windows.Handle
	busy      bool
}

var gUI *uiState

func runInstallerUI(root, serverURL string) int {
	runtime.LockOSThread()
	gUI = &uiState{root: root}

	hInst, _, _ := procGetModuleHandleW.Call(0)
	className, _ := windows.UTF16PtrFromString("ForensicAgentSetupWnd")
	cursor, _, _ := procLoadCursorW.Call(0, uintptr(idcArrow))

	wc := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:    windows.NewCallback(mainWndProc),
		Instance:   windows.Handle(hInst),
		Cursor:     windows.Handle(cursor),
		Background: windows.Handle(colorBtnFace + 1),
		ClassName:  className,
	}
	atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		msgBox("注册窗口失败: "+err.Error(), "ForensicAgent 安装", true)
		return 1
	}

	title, _ := windows.UTF16PtrFromString("ForensicAgent 安装")
	style := uintptr(wsCaption | wsSysMenu | wsMinimizeBox | wsVisible)
	hwnd, _, err2 := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		style,
		uintptr(centerX(580)), uintptr(centerY(500)),
		580, 500,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		msgBox("创建窗口失败: "+err2.Error(), "ForensicAgent 安装", true)
		return 1
	}
	gUI.hwnd = windows.Handle(hwnd)
	createControls(windows.Handle(hwnd), windows.Handle(hInst), serverURL)
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)

	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	return 0
}

func centerX(w int32) int32 {
	r, _, _ := procGetSystemMetrics.Call(smCXScreen)
	return (int32(r) - w) / 2
}
func centerY(h int32) int32 {
	r, _, _ := procGetSystemMetrics.Call(smCYScreen)
	return (int32(r) - h) / 2
}

func createControls(parent, hInst windows.Handle, serverURL string) {
	font := createUIFont()
	mk := func(class, text string, style uintptr, x, y, w, h, id int) windows.Handle {
		cn, _ := windows.UTF16PtrFromString(class)
		tx, _ := windows.UTF16PtrFromString(text)
		hwnd, _, _ := procCreateWindowExW.Call(
			0, uintptr(unsafe.Pointer(cn)), uintptr(unsafe.Pointer(tx)),
			style|wsChild|wsVisible,
			uintptr(x), uintptr(y), uintptr(w), uintptr(h),
			uintptr(parent), uintptr(id), uintptr(hInst), 0,
		)
		hh := windows.Handle(hwnd)
		if font != 0 {
			procSendMessageW.Call(uintptr(hh), wmSetFont, font, 1)
		}
		return hh
	}

	mk("STATIC", "ForensicAgent", 0, 24, 18, 400, 28, 10)
	mk("STATIC", "安装为 Windows 服务并自动启动（默认用户态采集）", 0, 24, 50, 520, 22, 11)
	mk("STATIC", "平台地址 (server_url)", 0, 24, 90, 280, 20, 12)
	gUI.editURL = mk("EDIT", serverURL, wsTabstop|wsBorder|wsESAutoHScroll, 24, 112, 520, 26, 101)
	gUI.chkDriver = mk("BUTTON", "同时安装 DataProtector 内核驱动（可选；当前为测试签名，需开启测试模式）",
		wsTabstop|wsBSAutoCheck, 24, 150, 520, 24, 102)
	mk("STATIC", "安装日志", 0, 24, 186, 200, 20, 13)
	gUI.editLog = mk("EDIT", "", wsBorder|wsVScroll|wsESMultiline|wsESAutoVScroll|wsESReadOnly,
		24, 208, 520, 180, 103)
	gUI.btnOK = mk("BUTTON", "安装并启动服务", wsTabstop, 300, 408, 150, 32, 1)
	mk("BUTTON", "关闭", wsTabstop, 460, 408, 84, 32, 2)

	appendLog("安装包目录: " + gUI.root)
	appendLog("准备就绪：填写平台地址后点击「安装并启动服务」。")
}

func createUIFont() uintptr {
	face, _ := windows.UTF16PtrFromString("Segoe UI")
	r, _, _ := procCreateFontW.Call(
		16, 0, 0, 0, 400, 0, 0, 0,
		1, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(face)),
	)
	return r
}

func mainWndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	case wmCommand:
		id := int(wParam & 0xFFFF)
		if id == 2 {
			procDestroyWindow.Call(uintptr(hwnd))
			return 0
		}
		if id == 1 {
			onInstallClicked()
			return 0
		}
	}
	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func onInstallClicked() {
	if gUI == nil || gUI.busy {
		return
	}
	url := getText(gUI.editURL)
	if url == "" {
		msgBox("请填写平台地址", "ForensicAgent 安装", true)
		return
	}
	wantDriver := getCheck(gUI.chkDriver)
	gUI.busy = true
	procEnableWindow.Call(uintptr(gUI.btnOK), 0)
	appendLog("开始安装…")

	go func() {
		err := doInstall(gUI.root, url, wantDriver, appendLog)
		if err != nil {
			appendLog("失败: " + err.Error())
			msgBox("安装失败:\n"+err.Error(), "ForensicAgent 安装", true)
		} else {
			msgBox("安装完成，服务已尝试启动。", "ForensicAgent 安装", false)
		}
		gUI.busy = false
		procEnableWindow.Call(uintptr(gUI.btnOK), 1)
	}()
}

func getText(hwnd windows.Handle) string {
	buf := make([]uint16, 1024)
	n, _, _ := procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf[:n])
}

func getCheck(hwnd windows.Handle) bool {
	r, _, _ := procSendMessageW.Call(uintptr(hwnd), bmGetCheck, 0, 0)
	return r == bstChecked
}

func appendLog(s string) {
	if gUI == nil || gUI.editLog == 0 {
		return
	}
	line, _ := windows.UTF16PtrFromString(s + "\r\n")
	procSendMessageW.Call(uintptr(gUI.editLog), emSetSel, ^uintptr(0), ^uintptr(0))
	procSendMessageW.Call(uintptr(gUI.editLog), emReplaceSel, 0, uintptr(unsafe.Pointer(line)))
}
