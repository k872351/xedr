//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func doInstall(root, serverURL string, wantDriver bool, logFn func(string)) error {
	logFn = coalesceLog(logFn)
	agentSrc := filepath.Join(root, "forensic-agent.exe")
	cfgSrc := filepath.Join(root, "agent.json")
	if _, err := os.Stat(agentSrc); err != nil {
		return fmt.Errorf("同目录缺少 forensic-agent.exe")
	}
	dest := filepath.Join(os.Getenv("ProgramData"), "ForensicAgent")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	logFn("安装目录: " + dest)

	agentDst := filepath.Join(dest, "forensic-agent.exe")
	cfgDst := filepath.Join(dest, "agent.json")
	// Validate the target before stopping or replacing the existing installation.
	if err := validateExistingConfig(cfgDst, serverURL); err != nil {
		return err
	}
	// 覆盖安装：先停掉旧服务，否则运行中的 exe 被占用无法覆盖
	if _, err := os.Stat(agentDst); err == nil {
		logFn("停止旧版服务…")
		_ = runLogged(logFn, agentDst, "uninstall")
	}
	if err := copyFile(agentSrc, agentDst); err != nil {
		return fmt.Errorf("复制 agent 失败: %w", err)
	}
	logFn("已复制 forensic-agent.exe")

	if err := writeServerURL(cfgDst, cfgSrc, serverURL); err != nil {
		return err
	}
	logFn("已写入 server_url: " + strings.TrimRight(strings.TrimSpace(serverURL), "/"))
	copySysmonBundle(root, dest, logFn)

	logFn("卸载旧服务（如有）…")
	_ = runLogged(logFn, agentDst, "uninstall")

	logFn("安装并启动 ForensicAgent 服务…")
	if err := runLogged(logFn, agentDst, "install", "-config", cfgDst); err != nil {
		return fmt.Errorf("install 失败: %w", err)
	}
	_ = exec.Command("sc.exe", "config", "ForensicAgent", "start=", "auto").Run()
	_ = exec.Command("sc.exe", "failure", "ForensicAgent", "reset=", "86400",
		"actions=", "restart/15000/restart/15000/restart/30000").Run()
	_ = exec.Command("sc.exe", "start", "ForensicAgent").Run()
	time.Sleep(800 * time.Millisecond)
	out, _ := exec.Command("sc.exe", "query", "ForensicAgent").CombinedOutput()
	if strings.Contains(string(out), "RUNNING") {
		logFn("服务 ForensicAgent 已在运行")
	} else {
		logFn("服务已安装；若未 RUNNING，请稍后在「服务」中确认")
	}
	// 切勿在安装阶段同步 ensure-sysmon（会与服务抢锁，MSI 假死在 Configuring）。
	// 也不要立刻再起一个后台 ensure：会与服务启动时的 ensure 撞 busy。
	// Sysmon 只由 ForensicAgent 服务托管；这里轮询结果写进安装日志，方便虚拟机排查。
	logFn("Sysmon 由服务自动托管安装（不阻塞 MSI）；正在等待结果…")
	sysmonOK := waitSysmonReady(45*time.Second, logFn)
	if !sysmonOK {
		logFn("提示: 暂未检测到 Sysmon 服务。请在虚拟机查看：")
		logFn("  - C:\\ProgramData\\ForensicAgent\\agent.log （搜 sysmon）")
		logFn("  - C:\\ProgramData\\ForensicAgent\\sysmon-status.txt")
		logFn("  - sc query Sysmon64")
		logFn("可手动执行: forensic-agent.exe ensure-sysmon")
	}

	if setupTestSigning {
		out, err := exec.Command("bcdedit.exe", "/set", "testsigning", "on").CombinedOutput()
		if err != nil {
			logFn("开启测试签名失败（Secure Boot 开启时无法开启）: " + strings.TrimSpace(string(out)))
		} else {
			logFn("已开启测试签名模式，重启后驱动才能加载")
		}
	}
	if wantDriver {
		if err := installDataProtector(root, logFn); err != nil {
			// Agent 已装好；驱动失败不回滚 Agent，只提示
			logFn("驱动未加载: " + err.Error())
		}
	}
	logFn("安装完成。")
	return nil
}

const dpService = "DataProtector"

// installDataProtector registers the DataProtector minifilter directly (the vendored
// INF references a catalog we do not produce) and loads it. Demand start: it is loaded
// here and by the agent's service start, never at boot, so a faulty build cannot boot-loop.
func installDataProtector(root string, logFn func(string)) error {
	sysSrc := filepath.Join(root, "driver", "DataProtector.sys")
	if _, err := os.Stat(sysSrc); err != nil {
		return fmt.Errorf("安装包内没有 driver\\DataProtector.sys")
	}
	// 重新安装即重新授权 Agent 自动加载（清除崩溃保护的停用标记）
	agentDir := filepath.Join(os.Getenv("ProgramData"), "ForensicAgent")
	_ = os.Remove(filepath.Join(agentDir, "dp_load_pending"))
	_ = os.Remove(filepath.Join(agentDir, "dp_load_disabled"))
	if cer := filepath.Join(root, "driver", "XEDRDriverTest.cer"); fileExists(cer) {
		// 测试签名证书：仅在 bcdedit testsigning on 的机器上起作用
		_ = exec.Command("certutil.exe", "-f", "-addstore", "Root", cer).Run()
		_ = exec.Command("certutil.exe", "-f", "-addstore", "TrustedPublisher", cer).Run()
	}
	_ = exec.Command("fltmc.exe", "unload", dpService).Run()
	sysDst := filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "DataProtector.sys")
	if err := copyFile(sysSrc, sysDst); err != nil {
		return fmt.Errorf("复制驱动失败: %w", err)
	}
	_ = exec.Command("sc.exe", "delete", dpService).Run()
	out, err := exec.Command("sc.exe", "create", dpService, "type=", "filesys", "start=", "demand",
		"error=", "normal", "binPath=", `System32\drivers\DataProtector.sys`,
		"group=", "FSFilter Encryption", "depend=", "FltMgr", "DisplayName=", "XEDR DataProtector").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create: %s", strings.TrimSpace(string(out)))
	}
	base := `HKLM\SYSTEM\CurrentControlSet\Services\` + dpService
	for _, args := range [][]string{
		{"add", base, "/v", "SupportedFeatures", "/t", "REG_DWORD", "/d", "3", "/f"},
		{"add", base + `\Instances`, "/v", "DefaultInstance", "/t", "REG_SZ", "/d", "DataProtector Instance", "/f"},
		{"add", base + `\Instances\DataProtector Instance`, "/v", "Altitude", "/t", "REG_SZ", "/d", "141000", "/f"},
		{"add", base + `\Instances\DataProtector Instance`, "/v", "Flags", "/t", "REG_DWORD", "/d", "0", "/f"},
	} {
		if o, err := exec.Command("reg.exe", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("reg %v: %s", args[1], strings.TrimSpace(string(o)))
		}
	}
	logFn("加载 DataProtector 驱动（默认只告警，不拦截）…")
	// 同 Agent 的崩溃保护：加载前写标记，稳定运行一段时间后再删；若期间蓝屏，重启后 Agent 停用自动加载
	pending := filepath.Join(agentDir, "dp_load_pending")
	_ = os.WriteFile(pending, []byte(time.Now().Format(time.RFC3339)), 0o644)
	out, err = exec.Command("fltmc.exe", "load", dpService).CombinedOutput()
	if err == nil {
		logFn("驱动已加载，观察运行稳定性（20 秒）…")
		time.Sleep(20 * time.Second)
	}
	_ = os.Remove(pending)
	if err != nil {
		// 已注册：测试模式生效（重启）后由 Agent 服务自动加载
		return fmt.Errorf("暂未加载: %s（测试签名需 bcdedit /set testsigning on 并重启，重启后 Agent 会自动加载；生产需 EV+微软签名）",
			strings.TrimSpace(string(out)))
	}
	logFn("DataProtector 驱动已加载")
	return nil
}

func uninstallDataProtector(logFn func(string)) {
	_ = exec.Command("fltmc.exe", "unload", dpService).Run()
	_ = exec.Command("sc.exe", "delete", dpService).Run()
	_ = os.Remove(filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "DataProtector.sys"))
	logFn("已卸载 DataProtector 驱动")
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func copySysmonBundle(root, dest string, logFn func(string)) {
	src := filepath.Join(root, "sysmon")
	if _, err := os.Stat(src); err != nil {
		// 兼容安装包旁的上级 Sysmon 目录（开发机）
		alt := filepath.Join(filepath.Dir(root), "Sysmon")
		if _, e2 := os.Stat(alt); e2 == nil {
			src = alt
		} else if st, e3 := os.Stat(filepath.Join(root, "Sysmon")); e3 == nil && st.IsDir() {
			src = filepath.Join(root, "Sysmon")
		} else {
			logFn("警告: 安装包内没有 sysmon\\ 目录（将依赖平台下载 Sysmon64.exe）: " + src)
			return
		}
	}
	dst := filepath.Join(dest, "sysmon")
	_ = os.MkdirAll(dst, 0o755)
	ents, err := os.ReadDir(src)
	if err != nil {
		return
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		low := strings.ToLower(name)
		if !(strings.HasSuffix(low, ".exe") || low == "eula.txt" || strings.HasSuffix(low, ".xml")) {
			continue
		}
		if err := copyFile(filepath.Join(src, name), filepath.Join(dst, name)); err == nil {
			n++
		}
	}
	if n > 0 {
		logFn(fmt.Sprintf("已复制 Sysmon 组件 %d 个文件 → %s", n, dst))
	}
}

func doUninstall(logFn func(string)) error {
	logFn = coalesceLog(logFn)
	dest := filepath.Join(os.Getenv("ProgramData"), "ForensicAgent")
	agentDst := filepath.Join(dest, "forensic-agent.exe")
	if _, err := os.Stat(agentDst); err == nil {
		_ = runLogged(logFn, agentDst, "uninstall")
	}
	_ = exec.Command("sc.exe", "stop", "ForensicAgent").Run()
	_ = exec.Command("sc.exe", "delete", "ForensicAgent").Run()
	_ = exec.Command("sc.exe", "stop", "FaKmon").Run()
	_ = exec.Command("sc.exe", "delete", "FaKmon").Run()
	uninstallDataProtector(logFn)
	logFn("已卸载 ForensicAgent 服务")
	return nil
}

func coalesceLog(fn func(string)) func(string) {
	if fn == nil {
		return func(string) {}
	}
	return fn
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o644)
}

func writeServerURL(cfgDst, cfgSrc, serverURL string) error {
	if err := validateExistingConfig(cfgDst, serverURL); err != nil {
		return err
	}
	if _, err := os.Stat(cfgDst); err == nil {
		return nil
	}
	serverURL = strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if serverURL == "" {
		return fmt.Errorf("平台地址不能为空")
	}
	var m map[string]any
	raw, err := os.ReadFile(cfgDst)
	if err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	if m == nil {
		raw2, err2 := os.ReadFile(cfgSrc)
		if err2 == nil {
			_ = json.Unmarshal(raw2, &m)
		}
	}
	if m == nil {
		m = map[string]any{}
	}
	m["server_url"] = serverURL
	if _, ok := m["token"]; !ok || strings.TrimSpace(fmt.Sprint(m["token"])) == "" {
		// 保留原 token；若两边都没有，install 会失败并提示
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfgDst, b, 0o644)
}

func validateExistingConfig(path, serverURL string) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var config struct {
		ServerURL string `json:"server_url"`
	}
	if json.Unmarshal(raw, &config) != nil || strings.TrimSpace(config.ServerURL) == "" {
		return fmt.Errorf("existing agent configuration is invalid; repair it before installing")
	}
	if strings.TrimRight(strings.TrimSpace(config.ServerURL), "/") != strings.TrimRight(strings.TrimSpace(serverURL), "/") {
		return fmt.Errorf("existing agent uses a different server; explicit migration required")
	}
	return nil
}

func runLogged(logFn func(string), exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if s != "" {
		for _, line := range strings.Split(s, "\n") {
			logFn(strings.TrimSpace(line))
		}
	}
	if err != nil {
		return fmt.Errorf("%v (exit)", err)
	}
	return nil
}

func waitSysmonReady(timeout time.Duration, logFn func(string)) bool {
	deadline := time.Now().Add(timeout)
	names := []string{"Sysmon64", "Sysmon64a", "Sysmon"}
	for time.Now().Before(deadline) {
		for _, name := range names {
			out, _ := exec.Command("sc.exe", "query", name).CombinedOutput()
			s := string(out)
			if strings.Contains(s, "RUNNING") || strings.Contains(s, "STOPPED") {
				// STOPPED 也算已安装（服务存在）；再尝试拉起
				if strings.Contains(s, "STOPPED") {
					_ = exec.Command("sc.exe", "start", name).Run()
					time.Sleep(500 * time.Millisecond)
					out2, _ := exec.Command("sc.exe", "query", name).CombinedOutput()
					s = string(out2)
				}
				stPath := filepath.Join(os.Getenv("ProgramData"), "ForensicAgent", "sysmon-status.txt")
				if b, err := os.ReadFile(stPath); err == nil && len(b) > 0 {
					logFn("sysmon-status.txt:\n" + strings.TrimSpace(string(b)))
				}
				if strings.Contains(s, "RUNNING") {
					logFn("Sysmon 服务已运行: " + name)
					return true
				}
				if strings.Contains(s, "STOPPED") || strings.Contains(s, "SERVICE_NAME") {
					logFn("Sysmon 服务已安装但未运行: " + name)
					return true
				}
			}
		}
		// 服务尚未写出状态时，读 agent 侧状态文件
		stPath := filepath.Join(os.Getenv("ProgramData"), "ForensicAgent", "sysmon-status.txt")
		if b, err := os.ReadFile(stPath); err == nil {
			low := strings.ToLower(string(b))
			if strings.Contains(low, "action=installed") || strings.Contains(low, "action=already_ok") ||
				strings.Contains(low, "action=config_updated") {
				logFn("sysmon-status.txt:\n" + strings.TrimSpace(string(b)))
				return true
			}
			if strings.Contains(low, "action=need_binary") || strings.Contains(low, "action=install_failed") {
				logFn("sysmon-status.txt:\n" + strings.TrimSpace(string(b)))
				return false
			}
		}
		time.Sleep(2 * time.Second)
	}
	return false
}
