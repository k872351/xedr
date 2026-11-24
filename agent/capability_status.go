package main

import (
	"runtime"
	"strings"
	"time"
)

// 能力运行态（管理端精细识别，避免「在线=全能」）
const (
	capRunning       = "running"
	capBuiltDisabled = "built_disabled"
	capInitFailed    = "init_failed"
	capOSUnsupported = "os_unsupported"
	capPolicyDenied  = "policy_denied"
)

func capabilityStatusReport() []map[string]any {
	caps := agentCapabilities()
	out := make([]map[string]any, 0, len(caps))
	for _, id := range caps {
		st, msg := resolveCapabilityStatus(id)
		out = append(out, map[string]any{
			"id": id, "status": st, "message": msg,
		})
	}
	return out
}

func resolveCapabilityStatus(id string) (string, string) {
	id = strings.TrimSpace(id)
	switch {
	case id == "sensor.linux.journal.v1":
		if runtime.GOOS != "linux" {
			return capOSUnsupported, "仅 Linux"
		}
		if !integrationEnabled("linux_journal") {
			return capPolicyDenied, "策略未启用 Journald"
		}
		state, message, observed := latestComponentObservation("linux_journal", time.Now())
		if observed && state == cStateHealthy {
			return capRunning, message
		}
		if observed && (state == cStateDegraded || state == cStateFailed) {
			return capInitFailed, message
		}
		return capBuiltDisabled, "等待日志采集运行证据"
	case strings.HasPrefix(id, "sensor.etw"), id == "http.etw.v1":
		if runtime.GOOS != "windows" {
			return capOSUnsupported, "仅 Windows"
		}
		if !integrationEnabled("etw") {
			return capPolicyDenied, "策略未启用 ETW"
		}
		return capRunning, ""
	case id == "sensor.wevt":
		if runtime.GOOS != "windows" {
			return capOSUnsupported, "仅 Windows"
		}
		if !integrationEnabled("winevent") {
			return capPolicyDenied, "策略未启用 Windows 事件"
		}
		return capRunning, ""
	case id == "fim.v1":
		if !integrationEnabled("fim") {
			return capPolicyDenied, "策略未启用 FIM"
		}
		return capRunning, ""
	case id == "fim.polling.v1":
		if runtime.GOOS != "linux" {
			return capOSUnsupported, "仅 Linux"
		}
		if !integrationEnabled("fim") {
			return capPolicyDenied, "策略未启用 FIM"
		}
		return capRunning, ""
	case id == "memory.integrity.v1", strings.Contains(id, "memory.scan"):
		if !yaraCompiled && strings.Contains(id, "yara") {
			return capBuiltDisabled, "当前构建未编译 YARA"
		}
		if !integrationEnabled("memory_scan") {
			return capPolicyDenied, "策略未启用内存扫描"
		}
		if !yaraCompiled {
			return capBuiltDisabled, "YARA 可选能力未编入本构建"
		}
		return capRunning, ""
	case id == "registry.realtime":
		if runtime.GOOS != "windows" {
			return capOSUnsupported, "仅 Windows"
		}
		if !integrationEnabled("registry") {
			return capPolicyDenied, "策略未启用注册表监控"
		}
		return capRunning, ""
	case id == "upgrade.ed25519", id == "upgrade.replace", id == "upgrade.watchdog",
		id == "upgrade.signed_atomic.linux.v1":
		if len(pinnedUpgradePubKeys(globalCfg)) == 0 {
			return capBuiltDisabled, "未钉扎升级公钥"
		}
		return capRunning, ""
	case id == "policy.sign.v1":
		if len(pinnedPolicyPubKeys(globalCfg)) == 0 {
			return capBuiltDisabled, "未钉扎策略公钥（兼容无签名策略）"
		}
		return capRunning, ""
	case strings.Contains(id, "linux") && runtime.GOOS != "linux":
		return capOSUnsupported, "仅 Linux"
	case (strings.HasPrefix(id, "process.identity") || id == "process.entity.v1") && runtime.GOOS != "windows":
		return capOSUnsupported, "当前实现面向 Windows"
	default:
		return capRunning, ""
	}
}
