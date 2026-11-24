//go:build windows

// ForensicAgent-Setup.exe — 双击安装：图形界面 + 提权 + 安装并启动服务。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// 静默安装日志（windowsgui 无控制台时写文件）
// 优先写到 %ProgramData%\ForensicAgent\setup-silent.log，便于排查 MSI「Configuring」卡住。
func silentLog(root string) func(string) {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramData"), "ForensicAgent", "setup-silent.log"),
		filepath.Join(root, "setup-silent.log"),
	}
	var f *os.File
	for _, logPath := range candidates {
		_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
		ff, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			f = ff
			_, _ = fmt.Fprintf(f, "---- setup %s root=%s ----\n", time.Now().Format(time.RFC3339), root)
			break
		}
	}
	if f == nil {
		return func(string) {}
	}
	return func(s string) {
		_, _ = fmt.Fprintln(f, s)
	}
}

func main() {
	silent, urlFlag, driverFlag := parseSetupArgs(os.Args[1:])
	for _, a := range os.Args[1:] {
		if al := strings.ToLower(a); al == "/u" || al == "--uninstall" {
			root := "."
			if exe, e := os.Executable(); e == nil {
				root = filepath.Dir(exe)
			}
			_ = doUninstall(silentLog(root))
			os.Exit(0)
		}
	}
	if err := ensureAdmin(); err != nil {
		if silent {
			fmt.Fprintln(os.Stderr, "need admin:", err)
			os.Exit(1)
		}
		msgBox("需要管理员权限才能安装 ForensicAgent。\n\n"+err.Error(), "ForensicAgent 安装", true)
		os.Exit(1)
	}
	root := "."
	if exe, e := os.Executable(); e == nil {
		root = filepath.Dir(exe)
	}
	cfgPath := filepath.Join(root, "agent.json")
	serverURL := urlFlag
	if serverURL == "" {
		serverURL = readServerURL(cfgPath)
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8100"
	}
	if silent {
		logFn := silentLog(root)
		err := doInstall(root, serverURL, driverFlag, logFn)
		if err != nil {
			logFn("ERROR: " + err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(runInstallerUI(root, serverURL))
}

// setupTestSigning: /TESTSIGNING=1 turns on Windows test-signing mode (needed for the
// test-signed driver; takes effect after reboot; impossible while Secure Boot is on).
var setupTestSigning bool

func parseSetupArgs(args []string) (silent bool, url string, driver bool) {
	for _, a := range args {
		if strings.EqualFold(strings.TrimSpace(a), "/testsigning=1") {
			setupTestSigning = true
		}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		al := strings.ToLower(strings.TrimSpace(a))
		switch {
		case al == "/s" || al == "-s" || al == "--silent" || al == "/quiet":
			silent = true
		case strings.HasPrefix(al, "/url="):
			url = strings.TrimSpace(a[5:])
		case strings.HasPrefix(al, "--url="):
			url = strings.TrimSpace(a[6:])
		case al == "/url" || al == "--url":
			if i+1 < len(args) {
				i++
				url = strings.TrimSpace(args[i])
			}
		case al == "/driver" || al == "--driver" || al == "/driver=1" || al == "--driver=1":
			driver = true
		case al == "/driver=0" || al == "--driver=0":
			driver = false
		}
	}
	return
}

func readServerURL(cfgPath string) string {
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	s, _ := m["server_url"].(string)
	return strings.TrimRight(strings.TrimSpace(s), "/")
}

func ensureAdmin() error {
	if isAdmin() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	err = windows.ShellExecute(0, verb, file, nil, dir, 1)
	if err != nil {
		return fmt.Errorf("提权失败: %w", err)
	}
	os.Exit(0)
	return nil
}

func isAdmin() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func msgBox(text, title string, isErr bool) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(title)
	flag := uint32(windows.MB_OK)
	if isErr {
		flag |= windows.MB_ICONERROR
	} else {
		flag |= windows.MB_ICONINFORMATION
	}
	windows.MessageBox(0, t, c, flag)
}
