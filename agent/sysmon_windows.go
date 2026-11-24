//go:build windows

package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// 内置配置为仓库 Sysmon/sysmonconfig-export.xml 的副本；终端/安装包/平台若有同名文件则优先用外部文件。
//
//go:embed data/sysmonconfig-export.xml
var sysmonConfigFS embed.FS

const (
	sysmonManagedFlag = "xedr.managed"
	sysmonConfigName  = "sysmonconfig-export.xml"
	sysmonMutexName   = `Global\XEDRSysmonEnsure`
)

var (
	// sysmonMu 串行化进程内的安装/更新；状态读取走 sysmonStatMu，避免心跳被长时间安装阻塞
	sysmonMu       sync.Mutex
	sysmonStatMu   sync.Mutex
	sysmonLastStat map[string]any
	sysmonLastAt   time.Time
)

func sysmonExeName() string {
	switch runtime.GOARCH {
	case "arm64":
		return "Sysmon64a.exe"
	case "386":
		return "Sysmon.exe"
	default:
		return "Sysmon64.exe"
	}
}

func sysmonInstallDir() string {
	base := globalCfg.StateDir
	if base == "" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			base = filepath.Join(pd, "ForensicAgent")
		} else {
			base = filepath.Join(`C:\ProgramData`, "ForensicAgent")
		}
	}
	return filepath.Join(base, "sysmon")
}

var (
	appliedPolicyMu sync.RWMutex
	appliedPolicy   map[string]any
)

func setAppliedPolicy(pol map[string]any) {
	appliedPolicyMu.Lock()
	defer appliedPolicyMu.Unlock()
	if pol == nil {
		appliedPolicy = nil
		return
	}
	cp := make(map[string]any, len(pol))
	for k, v := range pol {
		cp[k] = v
	}
	appliedPolicy = cp
}

func sysmonManagedEnabled() bool {
	appliedPolicyMu.RLock()
	pol := appliedPolicy
	appliedPolicyMu.RUnlock()
	if pol == nil {
		return true
	}
	if v, ok := pol["sysmon_managed"].(bool); ok {
		return v
	}
	return true
}

func setSysmonStat(st map[string]any) map[string]any {
	sysmonStatMu.Lock()
	sysmonLastStat, sysmonLastAt = st, time.Now()
	sysmonStatMu.Unlock()
	writeSysmonStatusFile(st)
	return st
}

// writeSysmonStatusFile 给安装/运维一眼能看到 Sysmon 结果（虚拟机上别只盯 install 那两行服务日志）。
func writeSysmonStatusFile(st map[string]any) {
	dir := sysmonInstallDir()
	_ = os.MkdirAll(dir, 0o755)
	base := globalCfg.StateDir
	if base == "" {
		base = filepath.Dir(dir)
	}
	lines := []string{
		"checked_at=" + time.Now().Format("2006-01-02T15:04:05"),
		fmt.Sprintf("action=%v", st["action"]),
		fmt.Sprintf("present=%v", st["present"]),
		fmt.Sprintf("installed=%v", st["installed"]),
		fmt.Sprintf("managed=%v", st["managed"]),
		fmt.Sprintf("error=%v", st["error"]),
		fmt.Sprintf("exe=%v", st["exe"]),
		fmt.Sprintf("config_source=%v", st["config_source"]),
		fmt.Sprintf("config_sha256=%v", st["config_sha256"]),
	}
	body := strings.Join(lines, "\n") + "\n"
	_ = os.WriteFile(filepath.Join(dir, "last-ensure.txt"), []byte(body), 0o644)
	_ = os.WriteFile(filepath.Join(base, "sysmon-status.txt"), []byte(body), 0o644)
	act, _ := st["action"].(string)
	errS, _ := st["error"].(string)
	switch act {
	case "installed":
		log.Printf("sysmon: 安装成功 present=%v", st["present"])
	case "already_ok":
		log.Printf("sysmon: 已就绪（无需重装） present=%v", st["present"])
	case "config_updated":
		log.Printf("sysmon: 配置已更新 present=%v", st["present"])
	case "need_binary":
		log.Printf("sysmon: 缺少 Sysmon64.exe — %s", errS)
	case "busy":
		log.Printf("sysmon: 其它进程正在安装，本次跳过")
	case "install_failed", "update_failed":
		log.Printf("sysmon: 失败 action=%s err=%s", act, errS)
	case "disabled_by_policy":
		log.Printf("sysmon: 策略已关闭托管安装")
	default:
		if errS != "" {
			log.Printf("sysmon: action=%s err=%s", act, errS)
		}
	}
}

// acquireSysmonMutex 跨进程互斥：安装脚本的 ensure-sysmon 与服务内首次 ensure 可能同时跑。
func acquireSysmonMutex(wait time.Duration) (release func(), ok bool) {
	name, err := windows.UTF16PtrFromString(sysmonMutexName)
	if err != nil {
		return func() {}, true
	}
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil && h == 0 {
		return func() {}, true
	}
	ev, _ := windows.WaitForSingleObject(h, uint32(wait/time.Millisecond))
	if ev != windows.WAIT_OBJECT_0 && ev != windows.WAIT_ABANDONED {
		windows.CloseHandle(h)
		return func() {}, false
	}
	return func() {
		_ = windows.ReleaseMutex(h)
		windows.CloseHandle(h)
	}, true
}

func ensureSysmonManaged(api *APIClient) map[string]any {
	sysmonMu.Lock()
	defer sysmonMu.Unlock()
	st := map[string]any{
		"managed": false, "present": probeSysmonLogQuick(), "installed": false,
		"action": "skip", "error": "",
	}
	if !sysmonManagedEnabled() {
		st["action"] = "disabled_by_policy"
		return setSysmonStat(st)
	}
	st["managed"] = true

	// 安装器与服务可能并发；互斥等待不宜过长，否则 MSI CustomAction 会表现为「Configuring」假死
	release, ok := acquireSysmonMutex(45 * time.Second)
	if !ok {
		st["action"] = "busy"
		st["error"] = "另一个进程正在安装 Sysmon"
		return setSysmonStat(st)
	}
	defer release()

	dir := sysmonInstallDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		st["error"] = "mkdir: " + err.Error()
		return setSysmonStat(st)
	}

	cfgPath, cfgHash, cfgSrc, err := materializeSysmonConfig(dir, api)
	if err != nil {
		st["error"] = "config: " + err.Error()
		return setSysmonStat(st)
	}
	st["config_sha256"] = cfgHash
	st["config_source"] = cfgSrc

	exePath, err := locateOrFetchSysmonExe(dir, api)
	if err != nil {
		st["error"] = err.Error()
		st["action"] = "need_binary"
		log.Printf("sysmon: %v", err)
		return setSysmonStat(st)
	}
	st["exe"] = exePath

	installed := sysmonServiceInstalledFast()
	st["installed"] = installed
	hashPath := filepath.Join(dir, "config.sha256")
	prev, _ := os.ReadFile(hashPath)
	markManaged := func() {
		_ = os.WriteFile(filepath.Join(dir, sysmonManagedFlag), []byte("1\n"), 0o644)
		_ = os.WriteFile(hashPath, []byte(cfgHash), 0o644)
	}

	if !installed {
		out, err := runSysmonCmd(3*time.Minute, exePath, "-accepteula", "-i", cfgPath)
		if err != nil && !sysmonServiceInstalledFast() {
			st["error"] = fmt.Sprintf("install: %v (%s)", err, truncate(strings.TrimSpace(out), 240))
			st["action"] = "install_failed"
			log.Printf("sysmon install failed: %v", st["error"])
			return setSysmonStat(st)
		}
		markManaged()
		ensureSysmonServiceRunning()
		st["action"] = "installed"
		st["installed"] = true
		st["present"] = probeSysmonLogQuick()
		log.Printf("sysmon: 已自动安装 (%s, config=%s)", filepath.Base(exePath), cfgSrc)
		return setSysmonStat(st)
	}

	if strings.TrimSpace(string(prev)) != cfgHash || !fileExists(filepath.Join(dir, sysmonManagedFlag)) {
		out, err := runSysmonCmd(2*time.Minute, exePath, "-accepteula", "-c", cfgPath)
		if err != nil {
			st["error"] = fmt.Sprintf("update: %v (%s)", err, truncate(strings.TrimSpace(out), 240))
			st["action"] = "update_failed"
			log.Printf("sysmon config update failed: %v", st["error"])
			ensureSysmonServiceRunning()
			return setSysmonStat(st)
		}
		markManaged()
		st["action"] = "config_updated"
		log.Printf("sysmon: 配置已更新 sha256=%s source=%s", cfgHash[:12], cfgSrc)
	} else {
		st["action"] = "already_ok"
	}
	if ensureSysmonServiceRunning() {
		st["restarted"] = true
	}
	st["present"] = probeSysmonLogQuick()
	return setSysmonStat(st)
}

// materializeSysmonConfig 选择配置：本地 sysmonconfig-export.xml → 平台下载 → 内置副本。
func materializeSysmonConfig(dir string, api *APIClient) (path, hash, source string, err error) {
	path = filepath.Join(dir, sysmonConfigName)
	var raw []byte
	for _, p := range []string{
		filepath.Join(exeDir(), "sysmon", sysmonConfigName),
		filepath.Join(exeDir(), sysmonConfigName),
		path,
	} {
		if b, e := os.ReadFile(p); e == nil && len(b) > 64 && strings.Contains(string(b), "<Sysmon") {
			raw, source = b, p
			break
		}
	}
	if raw == nil && api != nil {
		tmp := path + ".dl"
		if e := api.DownloadArtifact("/api/agent/artifacts/sysmon/"+sysmonConfigName, tmp); e == nil {
			if b, e2 := os.ReadFile(tmp); e2 == nil && strings.Contains(string(b), "<Sysmon") {
				raw, source = b, "platform"
			}
		}
		_ = os.Remove(tmp)
	}
	if raw == nil {
		b, e := sysmonConfigFS.ReadFile("data/" + sysmonConfigName)
		if e != nil {
			return "", "", "", e
		}
		raw, source = b, "embedded"
	}
	sum := sha256.Sum256(raw)
	hash = hex.EncodeToString(sum[:])
	if cur, e := os.ReadFile(path); e == nil {
		s2 := sha256.Sum256(cur)
		if hex.EncodeToString(s2[:]) == hash {
			return path, hash, source, nil
		}
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return "", "", "", err
	}
	return path, hash, source, nil
}

func locateOrFetchSysmonExe(dir string, api *APIClient) (string, error) {
	name := sysmonExeName()
	dst := filepath.Join(dir, name)
	cands := []string{
		dst,
		filepath.Join(exeDir(), "sysmon", name),
		filepath.Join(exeDir(), name),
		filepath.Join(exeDir(), "pkg", "sysmon", name),
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		cands = append(cands,
			filepath.Join(pd, "ForensicAgent", "sysmon", name),
			filepath.Join(pd, "ForensicAgent", "pkg", "sysmon", name),
		)
	}
	for _, p := range cands {
		if fi, err := os.Stat(p); err == nil && fi.Size() > 100_000 {
			if filepath.Clean(p) != filepath.Clean(dst) {
				if err := copyFileSimple(p, dst); err != nil {
					return p, nil
				}
			}
			return dst, nil
		}
	}
	if api == nil {
		return "", fmt.Errorf("未找到 %s，且无平台客户端可下载（请把 Sysmon/%s 打进安装包，或重启平台后再试下载）", name, name)
	}
	if err := api.DownloadArtifact("/api/agent/artifacts/sysmon/"+name, dst); err != nil {
		return "", fmt.Errorf("本地无 %s，平台下载失败: %w（常见原因：平台未重启导致接口 404，或安装包未带 sysmon 目录）", name, err)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Size() < 100_000 {
		_ = os.Remove(dst)
		return "", fmt.Errorf("下载的 %s 无效", name)
	}
	log.Printf("sysmon: 已从平台下载 %s", name)
	return dst, nil
}

func copyFileSimple(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err = out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

func runSysmonCmd(timeout time.Duration, exe string, args ...string) (string, error) {
	return runCmd(timeout, exe, args...)
}

func sysmonServiceNames() []string { return []string{"Sysmon64", "Sysmon64a", "Sysmon"} }

// ensureSysmonServiceRunning 服务存在但停止时拉起；返回是否执行了启动。
func ensureSysmonServiceRunning() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	for _, name := range sysmonServiceNames() {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		st, e := s.Query()
		started := false
		if e == nil && st.State == svc.Stopped {
			if err := s.Start(); err == nil {
				started = true
				log.Printf("sysmon: 服务 %s 已重新启动", name)
			}
		}
		s.Close()
		return started
	}
	return false
}

func probeSysmonLogQuick() bool {
	if sysmonServiceInstalledFast() {
		return true
	}
	return winevtChannelOK("Microsoft-Windows-Sysmon/Operational")
}

func sysmonServiceInstalledFast() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	for _, name := range sysmonServiceNames() {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		s.Close()
		return true
	}
	return false
}

// sysmonSubscribedEIDs 与 winevtChannelDefs 中 sysmon XPath 保持一致。
func sysmonSubscribedEIDs() []int {
	return []int{1, 3, 5, 7, 8, 10, 11, 13, 15, 17, 22, 23, 25, 26}
}

func sysmonStatusSnapshot() map[string]any {
	sysmonStatMu.Lock()
	last, at := sysmonLastStat, sysmonLastAt
	sysmonStatMu.Unlock()
	out := map[string]any{}
	if last != nil {
		for k, v := range last {
			out[k] = v
		}
		out["checked_at"] = at.Format("2006-01-02T15:04:05")
	} else {
		out["managed"] = sysmonManagedEnabled()
		out["action"] = "pending"
	}
	out["present"] = probeSysmonLogQuick()
	out["installed"] = sysmonServiceInstalledFast()
	out["subscribed_eids"] = sysmonSubscribedEIDs()
	if h, _ := out["config_sha256"].(string); len(h) >= 12 {
		out["config_version"] = h[:12]
	}
	tele := telemetryMetricsSnapshot()
	if n, ok := tele["events_sysmon"]; ok {
		out["events_collected"] = n
	}
	return out
}

// uninstallManagedSysmon 仅当存在 managed 标记时卸载，避免动用户自装的 Sysmon。
func uninstallManagedSysmon() {
	dir := sysmonInstallDir()
	if !fileExists(filepath.Join(dir, sysmonManagedFlag)) {
		return
	}
	exe := filepath.Join(dir, sysmonExeName())
	if !fileExists(exe) {
		exe = filepath.Join(exeDir(), "sysmon", sysmonExeName())
	}
	if !fileExists(exe) {
		return
	}
	out, err := runSysmonCmd(2*time.Minute, exe, "-u", "force")
	if err != nil {
		log.Printf("sysmon uninstall: %v (%s)", err, truncate(strings.TrimSpace(out), 200))
		return
	}
	_ = os.Remove(filepath.Join(dir, sysmonManagedFlag))
	log.Printf("sysmon: 已卸载 XEDR 托管实例")
}
