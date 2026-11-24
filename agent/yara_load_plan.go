package main

// YARA 规则加载计划：与 //go:build yara 解耦的纯逻辑，便于在默认构建下单测。
// 借鉴 DataProtector YaraScanEngine.cs:381 的「逐文件验证 → 合并进单一对象 + 唯一 namespace」。
// 本文件不 import go-yara，因此 !yara 构建同样可用。

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// 兼容历史：早期实现扫描不到规则时会尝试这几个默认文件名。
var defaultYaraRuleNames = []string{
	"reflective_loader.yar", "cobalt_strike.yar", "mimikatz.yar", "amsi_bypass.yar",
}

type yaraRuleEntry struct {
	path      string
	namespace string
}

type yaraLoadPlan struct {
	dir     string
	entries []yaraRuleEntry
}

var yaraNamespaceInvalid = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// yaraNamespaceFor 生成稳定、唯一、合法的 namespace。
// 用「清洗后的文件名 + 序号」避免标识符冲突，也便于告警里回溯来源文件。
func yaraNamespaceFor(name string, index int) string {
	base := strings.TrimSuffix(strings.ToLower(name), ".yara")
	base = strings.TrimSuffix(base, ".yar")
	clean := strings.Trim(yaraNamespaceInvalid.ReplaceAllString(base, "_"), "_")
	if clean == "" {
		clean = "rule"
	}
	if len(clean) > 48 {
		clean = clean[:48]
	}
	// namespace 以字母开头，避免某些 YARA 版本对数字开头的限制
	if clean[0] >= '0' && clean[0] <= '9' {
		clean = "ns_" + clean
	}
	return "f" + itoa(index) + "_" + clean
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// scanYaraRuleFiles 列出目录下所有 .yar/.yara 规则文件（不递归），按文件名排序保证稳定。
func scanYaraRuleFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		low := strings.ToLower(e.Name())
		if strings.HasSuffix(low, ".yar") || strings.HasSuffix(low, ".yara") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// buildYaraLoadPlan 生成加载计划；目录不存在或为空时返回空计划（不报错）。
func buildYaraLoadPlan(dir string) *yaraLoadPlan {
	plan := &yaraLoadPlan{dir: dir}
	names, err := scanYaraRuleFiles(dir)
	if err != nil {
		return plan
	}
	if len(names) == 0 {
		// 兼容：目录里只有非标准后缀但存在历史默认文件名时仍纳入
		for _, n := range defaultYaraRuleNames {
			if _, e := os.Stat(filepath.Join(dir, n)); e == nil {
				names = append(names, n)
			}
		}
		sort.Strings(names)
	}
	for i, n := range names {
		plan.entries = append(plan.entries, yaraRuleEntry{
			path:      filepath.Join(dir, n),
			namespace: yaraNamespaceFor(n, i),
		})
	}
	return plan
}

// namespaces 返回本计划的 namespace 集合（供测试/诊断）。
func (p *yaraLoadPlan) namespaces() []string {
	out := make([]string, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, e.namespace)
	}
	return out
}
