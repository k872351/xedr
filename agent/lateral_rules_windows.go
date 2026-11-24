//go:build windows

package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

// 横向移动用户态规则：对标 DataProtector LateralDefense 的「工具链可见性」，
// 但不使用内核 minifilter——只从进程创建 / 命令行识别远程 schtasks/sc/wmic/WinRM 等。

var (
	reLatSchtasks   = regexp.MustCompile(`(?i)(^|[\\/])schtasks(\.exe)?\b`)
	reLatSC         = regexp.MustCompile(`(?i)(^|[\\/])sc(\.exe)?\b`)
	reLatWMIC       = regexp.MustCompile(`(?i)(^|[\\/])wmic(\.exe)?\b`)
	reLatWinRS      = regexp.MustCompile(`(?i)(^|[\\/])winrs(\.exe)?\b`)
	reLatPsExec     = regexp.MustCompile(`(?i)(^|[\\/])(psexec|psexec64|paexec|csexec)(\.exe)?\b`)
	reLatAt         = regexp.MustCompile(`(?i)(^|[\\/])at(\.exe)?\b`)
	reLatPSRemote   = regexp.MustCompile(`(?i)\b(invoke-command|enter-pssession|new-pssession|icm)\b`)
	reLatRemoteHost = regexp.MustCompile(`(?i)(\\\\[^\\\s]+|/s\s+[^\s]+|/node\s*:\s*[^\s]+|-ComputerName\s+[^\s]+|-cn\s+[^\s]+|\\\\[^\s]+\\(admin\$|c\$|ipc\$))`)
)

type lateralHit struct {
	Technique string
	Label     string
	Severity  string
}

func detectLateralFromCmd(image, cmd string) *lateralHit {
	img := strings.TrimSpace(image)
	c := strings.TrimSpace(cmd)
	if c == "" && img == "" {
		return nil
	}
	blob := strings.ToLower(img + " " + c)
	base := strings.ToLower(filepath.Base(img))
	remote := reLatRemoteHost.MatchString(c) || reLatRemoteHost.MatchString(img)

	switch {
	case reLatPsExec.MatchString(blob) || strings.HasPrefix(base, "psexec"):
		return &lateralHit{Technique: "T1569.002", Label: "PsExec/远程执行工具", Severity: "high"}
	case reLatSchtasks.MatchString(blob) && (remote || strings.Contains(blob, "/create") || strings.Contains(blob, "/run")):
		sev := "medium"
		if remote {
			sev = "high"
		}
		return &lateralHit{Technique: "T1053.005", Label: "远程/计划任务 schtasks", Severity: sev}
	case reLatSC.MatchString(blob) && (remote || strings.Contains(blob, " create") || strings.Contains(blob, " config") || strings.Contains(blob, " start")):
		sev := "medium"
		if remote || strings.Contains(blob, `\\`) {
			sev = "high"
		}
		return &lateralHit{Technique: "T1543.003", Label: "远程/服务控制 sc", Severity: sev}
	case reLatWMIC.MatchString(blob) && (remote || strings.Contains(blob, "process call create") || strings.Contains(blob, "/node")):
		return &lateralHit{Technique: "T1047", Label: "远程 WMI/wmic", Severity: "high"}
	case reLatWinRS.MatchString(blob) || (reLatPSRemote.MatchString(blob) && (remote || strings.Contains(blob, "-computername") || strings.Contains(blob, "new-pssession"))):
		return &lateralHit{Technique: "T1021.006", Label: "WinRM/PowerShell Remoting", Severity: "high"}
	case reLatAt.MatchString(blob) && remote:
		return &lateralHit{Technique: "T1053.002", Label: "远程 at 计划任务", Severity: "high"}
	case strings.Contains(blob, `\admin$`) || strings.Contains(blob, `\c$`) || strings.Contains(blob, `\ipc$`):
		if strings.Contains(blob, "copy ") || strings.Contains(blob, "xcopy") || strings.Contains(blob, "robocopy") ||
			strings.Contains(blob, "move ") || strings.Contains(blob, "copy\t") {
			return &lateralHit{Technique: "T1021.002", Label: "SMB 管理共享投递", Severity: "high"}
		}
	}
	return nil
}

// enrichLateralEvents：对进程创建类事件打上横向移动标签；命中时追加一条专用信号便于狩猎。
func enrichLateralEvents(events []map[string]any) []map[string]any {
	if len(events) == 0 {
		return events
	}
	out := make([]map[string]any, 0, len(events)+4)
	for _, ev := range events {
		out = append(out, ev)
		et := strings.ToLower(asString(ev["etype"]))
		if et != "process_create" && et != "process_create_etw" && et != "process_create_kernel" &&
			et != "win_proc_create" && !strings.Contains(et, "process_create") {
			continue
		}
		d, _ := ev["detail"].(map[string]any)
		if d == nil {
			continue
		}
		img := firstNonEmpty(asString(d["path"]), asString(d["image"]), asString(d["process_path"]))
		cmd := firstNonEmpty(asString(d["command_line"]), asString(d["cmdline"]), asString(d["CommandLine"]))
		hit := detectLateralFromCmd(img, cmd)
		if hit == nil {
			continue
		}
		d["lateral"] = true
		d["technique"] = hit.Technique
		d["lateral_label"] = hit.Label
		if sevRank(asString(ev["severity"])) < sevRank(hit.Severity) {
			ev["severity"] = hit.Severity
		}
		sum := asString(ev["summary"])
		if sum != "" && !strings.Contains(sum, hit.Label) {
			ev["summary"] = sum + " · " + hit.Label
		}
		ts := asString(ev["ts"])
		pid := d["pid"]
		out = append(out, map[string]any{
			"etype":    "lateral_tool",
			"summary":  "横向移动工具: " + hit.Label + " · " + filepath.Base(img),
			"severity": hit.Severity,
			"ts":       ts,
			"detail": map[string]any{
				"source": "cmdline_rule", "technique": hit.Technique, "label": hit.Label,
				"path": img, "command_line": cmd, "pid": pid,
				"process_name": filepath.Base(img), "matched": hit.Label,
			},
		})
	}
	return out
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
