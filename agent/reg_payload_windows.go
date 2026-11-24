//go:build windows

package main

import (
	"regexp"
	"strings"

	"golang.org/x/sys/windows/registry"
)

var clsidRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// resolveCLSIDServer 把 CLSID 解析到其 InprocServer32 / LocalServer32；用户级注册优先。
func resolveCLSIDServer(sid, clsid string) string {
	type loc struct {
		root registry.Key
		path string
	}
	var locs []loc
	if sid != "" {
		locs = append(locs, loc{registry.USERS, sid + `\Software\Classes\CLSID\` + clsid})
	}
	locs = append(locs,
		loc{registry.LOCAL_MACHINE, `SOFTWARE\Classes\CLSID\` + clsid},
		loc{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Classes\CLSID\` + clsid},
	)
	for _, l := range locs {
		for _, sub := range []string{"InprocServer32", "LocalServer32"} {
			k, err := registry.OpenKey(l.root, l.path+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			v, _, err := k.GetStringValue("")
			k.Close()
			if err == nil && strings.TrimSpace(v) != "" {
				return v
			}
		}
	}
	return ""
}

func expandRegPath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	if strings.Contains(p, "%") {
		if e, err := registry.ExpandString(p); err == nil {
			p = e
		}
	}
	return p
}

// regPayloadPath 从注册表值里找出最终会被加载/执行的文件。
func regPayloadPath(spec regSpec, key, name, data string) string {
	d := strings.TrimSpace(data)
	candidate := ""
	switch {
	case clsidRe.MatchString(d):
		candidate = resolveCLSIDServer(spec.SID, d)
	case clsidRe.MatchString(name) && !strings.ContainsAny(d, `\/`):
		// ShellExecuteHooks 等：值名是 CLSID，数据只是描述
		candidate = resolveCLSIDServer(spec.SID, name)
	case name == "(key)":
		if clsidRe.MatchString(d) {
			candidate = resolveCLSIDServer(spec.SID, d)
		}
	default:
		candidate = d
	}
	if candidate == "" {
		return ""
	}
	whole := expandRegPath(candidate)
	if fileExists(whole) {
		return whole
	}
	// LocalServer32 / 命令行形式：取可执行部分
	if exe := expandRegPath(extractExe(candidate)); exe != "" {
		return exe
	}
	return whole
}

// regPayloadSeverity 按落地文件重新定级：有效签名 → low；不存在或可疑路径未签名 → 保持/提为 high；其余 medium。
func regPayloadSeverity(payload, sev string, detail map[string]any) string {
	detail["payload_path"] = payload
	if !fileExists(payload) {
		detail["payload_missing"] = true
		return sev
	}
	valid, status := peSignedValid(payload)
	if status != "" {
		detail["payload_signed"] = status
	}
	if valid {
		return "low"
	}
	if pathLooksSuspicious(payload) {
		return "high"
	}
	return "medium"
}
