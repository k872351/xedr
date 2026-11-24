package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// 以下三项由 scripts/build_agent.py 通过 -ldflags -X 注入；本地 go build 时为默认值。
var (
	buildID   = "dev"
	buildTime = ""
	sourceRev = ""
)

// 本 Agent 支持的协议范围。服务端按双方交集协商，旧服务端只认 v1。
const (
	protocolMin = 1
	protocolMax = 2
)

// agentCapabilities 只列出已真正实现的能力，供服务端按能力启用新功能。
func agentCapabilities() []string {
	base := []string{
		"snapshot.v1",
		"timeline.v1",
		"command.ack.v1",
		"ingest.v2",
		"health.v1",
		"inventory.delta",
		"inventory.parts.v1",
		"policy.lkg",
		"fleet.checkin.v1",
		"diagnostics.v2",
		"composable.host.v1",
		"event.schema.v1",
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		base = append(base, "inventory.software.extended.v1", "inventory.software.paged.v1", "inventory.assets.paged.v1", "inventory.user.paged.v1")
	}
	if runtime.GOOS == "windows" {
		return append(base,
			"process.identity.v1", "sensor.etw", "sensor.wevt",
			"upgrade.replace", "upgrade.ed25519", "upgrade.watchdog",
			"auth.agent_secret", "command.lease", "process.entity.v1",
			"registry.realtime", "dns.aggregate", "fim.v1",
			"memory.integrity.v1", "file.meta.v1", "http.etw.v1",
			"beacon.watch.v1", "response.persist.v1", "policy.sign.v1",
			"self.protect.watch.v1",
		)
	}
	if runtime.GOOS == "linux" {
		return append(base,
			"dns.aggregate", "fim.polling.v1", "inventory.kernel_module.v1",
			"inventory.process.procfs.v1", "inventory.network.procfs.v1",
			"inventory.services.systemd_units.linux.v1",
			"inventory.tasks.cron_systemd.linux.v1", "inventory.startup.linux.v1",
			"rules.linux.process_snapshot.v1",
			"inventory.software.linux.v1", "inventory.package_updates.linux.v1",
			"rootcheck.linux.v1", "sca.linux.v1",
			"response.kill_process.linux.v1", "response.quarantine_file.linux.v1",
			"sensor.linux.journal.v1",
		)
	}
	return base
}
func buildInfoMap() map[string]any {
	return map[string]any{
		"version":            agentVersion,
		"build_id":           buildID,
		"build_time":         buildTime,
		"source_rev":         sourceRev,
		"protocol_min":       protocolMin,
		"protocol_max":       protocolMax,
		"capabilities":       agentCapabilities(),
		"capability_status":  capabilityStatusReport(),
		"go_version":         runtime.Version(),
		"goos":               runtime.GOOS,
		"goarch":             runtime.GOARCH,
		"yara_compiled":      yaraCompiled,
		"yara_optional_note": "YARA 为可选构建；yara_compiled=false 时内存扫描能力为 built_disabled",
	}
}

// printBuildInfo 将构建信息写到文件（windowsgui 无控制台，故支持落盘）；path 为空则输出到 stdout。
func printBuildInfo(path string) error {
	b, err := json.MarshalIndent(buildInfoMap(), "", "  ")
	if err != nil {
		return err
	}
	if path == "" {
		fmt.Println(string(b))
		return nil
	}
	return os.WriteFile(path, b, 0644)
}

// registerExtras 注册/心跳附带的构建与协议信息。
func registerExtras() map[string]any {
	return map[string]any{
		"build_id":          buildID,
		"build_time":        buildTime,
		"source_rev":        sourceRev,
		"protocol_min":      protocolMin,
		"protocol_max":      protocolMax,
		"capabilities":      agentCapabilities(),
		"capability_status": capabilityStatusReport(),
		"yara_compiled":     yaraCompiled,
		"host":              hostMetadata(),
	}
}
