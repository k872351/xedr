//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// 处置补齐：禁用服务 / 删计划任务 / 注册表回滚 / 持久化清除 / 复查。

func execPersistResponse(cfg Config, action string, params map[string]any) (map[string]any, error) {
	switch strings.ToLower(action) {
	case "disable_service":
		return disableWindowsService(params)
	case "enable_service":
		return enableWindowsService(params)
	case "stop_service":
		return stopWindowsService(params)
	case "delete_task", "delete_scheduled_task":
		return deleteScheduledTask(params)
	case "disable_task", "disable_scheduled_task":
		return disableScheduledTask(params)
	case "enable_task", "enable_scheduled_task":
		return enableScheduledTask(params)
	case "reg_delete_value":
		return regDeleteValueAction(cfg, params)
	case "reg_set_value":
		return regSetValueAction(cfg, params)
	case "reg_rollback":
		return regRollbackAction(cfg, params)
	case "clear_persistence":
		return clearPersistenceAction(cfg, params)
	case "recheck_persistence", "verify_response":
		return recheckPersistenceAction(params)
	default:
		return nil, fmt.Errorf("未知持久化处置: %s", action)
	}
}

func guardedServiceName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("缺少 service")
	}
	low := strings.ToLower(name)
	if low == strings.ToLower(serviceName) || low == "forensic-agent" {
		return fmt.Errorf("拒绝操作 Agent 自身服务")
	}
	critical := []string{
		"eventlog", "rpcss", "lsass", "windefend", "mpssvc", "wuauserv",
		"schedule", "cryptsvc", "dcomlaunch", "plugplay", "power",
	}
	for _, c := range critical {
		if low == c {
			return fmt.Errorf("拒绝操作关键系统服务: %s", name)
		}
	}
	return nil
}

func disableWindowsService(params map[string]any) (map[string]any, error) {
	name := strings.TrimSpace(fmt.Sprint(params["service"]))
	if name == "" {
		name = strings.TrimSpace(fmt.Sprint(params["name"]))
	}
	if err := guardedServiceName(name); err != nil {
		return nil, err
	}
	out1, err1 := runCmd(30*time.Second, "sc", "stop", name)
	out2, err2 := runCmd(30*time.Second, "sc", "config", name, "start=", "disabled")
	ok := err2 == nil
	return map[string]any{
		"ok": ok, "service": name, "stop_output": out1, "config_output": out2,
		"stop_err": errString(err1), "config_err": errString(err2),
	}, err2
}

func enableWindowsService(params map[string]any) (map[string]any, error) {
	name := strings.TrimSpace(fmt.Sprint(params["service"]))
	if name == "" {
		name = strings.TrimSpace(fmt.Sprint(params["name"]))
	}
	if err := guardedServiceName(name); err != nil {
		return nil, err
	}
	start := strings.TrimSpace(fmt.Sprint(params["start"]))
	if start == "" {
		start = "demand"
	}
	out, err := runCmd(30*time.Second, "sc", "config", name, "start=", start)
	return map[string]any{"ok": err == nil, "service": name, "start": start, "output": out}, err
}

func stopWindowsService(params map[string]any) (map[string]any, error) {
	name := strings.TrimSpace(fmt.Sprint(params["service"]))
	if name == "" {
		name = strings.TrimSpace(fmt.Sprint(params["name"]))
	}
	if err := guardedServiceName(name); err != nil {
		return nil, err
	}
	out, err := runCmd(30*time.Second, "sc", "stop", name)
	return map[string]any{"ok": err == nil, "service": name, "output": out}, err
}

func deleteScheduledTask(params map[string]any) (map[string]any, error) {
	task := strings.TrimSpace(fmt.Sprint(params["task"]))
	if task == "" {
		task = strings.TrimSpace(fmt.Sprint(params["name"]))
	}
	if task == "" {
		return nil, fmt.Errorf("缺少 task")
	}
	if strings.HasPrefix(strings.ToLower(task), `\microsoft\windows\`) &&
		!strings.Contains(strings.ToLower(fmt.Sprint(params["force"])), "true") &&
		fmt.Sprint(params["force"]) != "1" {
		return nil, fmt.Errorf("拒绝删除系统计划任务（需 force=true）: %s", task)
	}
	out, err := runCmd(45*time.Second, "schtasks", "/Delete", "/TN", task, "/F")
	return map[string]any{"ok": err == nil, "task": task, "output": out}, err
}

func disableScheduledTask(params map[string]any) (map[string]any, error) {
	task := strings.TrimSpace(fmt.Sprint(params["task"]))
	if task == "" {
		task = strings.TrimSpace(fmt.Sprint(params["name"]))
	}
	if task == "" {
		return nil, fmt.Errorf("缺少 task")
	}
	out, err := runCmd(45*time.Second, "schtasks", "/Change", "/TN", task, "/DISABLE")
	return map[string]any{"ok": err == nil, "task": task, "output": out}, err
}

func enableScheduledTask(params map[string]any) (map[string]any, error) {
	task := strings.TrimSpace(fmt.Sprint(params["task"]))
	if task == "" {
		task = strings.TrimSpace(fmt.Sprint(params["name"]))
	}
	if task == "" {
		return nil, fmt.Errorf("缺少 task")
	}
	out, err := runCmd(45*time.Second, "schtasks", "/Change", "/TN", task, "/ENABLE")
	return map[string]any{"ok": err == nil, "task": task, "output": out}, err
}

type regBackupEntry struct {
	ID        string `json:"id"`
	Hive      string `json:"hive"`
	Path      string `json:"path"`
	Name      string `json:"name"`
	Existed   bool   `json:"existed"`
	Type      string `json:"type"`
	Data      any    `json:"data"`
	DeletedAt string `json:"deleted_at"`
	Action    string `json:"action"`
}

func regBackupDir(cfg Config) string {
	d := filepath.Join(cfg.StateDir, "reg_rollback")
	_ = os.MkdirAll(d, 0700)
	return d
}

func parseRegTarget(params map[string]any) (registry.Key, string, string, string, error) {
	hive := strings.ToUpper(strings.TrimSpace(fmt.Sprint(params["hive"])))
	path := strings.TrimSpace(fmt.Sprint(params["path"]))
	name := strings.TrimSpace(fmt.Sprint(params["name"]))
	if name == "" {
		name = strings.TrimSpace(fmt.Sprint(params["value"]))
	}
	full := strings.TrimSpace(fmt.Sprint(params["key"]))
	if full != "" && path == "" {
		full = strings.ReplaceAll(full, "/", `\`)
		parts := strings.SplitN(full, `\`, 2)
		if len(parts) == 2 {
			hive, path = strings.ToUpper(parts[0]), parts[1]
		}
	}
	var root registry.Key
	switch hive {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root, hive = registry.LOCAL_MACHINE, "HKLM"
	case "HKCU", "HKEY_CURRENT_USER":
		root, hive = registry.CURRENT_USER, "HKCU"
	case "HKU", "HKEY_USERS":
		root, hive = registry.USERS, "HKU"
	case "HKCR", "HKEY_CLASSES_ROOT":
		root, hive = registry.CLASSES_ROOT, "HKCR"
	default:
		return 0, "", "", "", fmt.Errorf("不支持的 hive: %s", hive)
	}
	if path == "" || name == "" {
		return 0, "", "", "", fmt.Errorf("缺少 path/name")
	}
	low := strings.ToLower(path)
	if strings.Contains(low, `currentcontrolset\services\`+strings.ToLower(serviceName)) {
		return 0, "", "", "", fmt.Errorf("拒绝修改 Agent 服务键")
	}
	return root, hive, path, name, nil
}

func readRegValueAny(root registry.Key, path, name string) (typ string, data any, ok bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", nil, false
	}
	defer k.Close()
	_, valType, err := k.GetValue(name, nil)
	if err != nil {
		return "", nil, false
	}
	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, e := k.GetStringValue(name)
		if e != nil {
			return "", nil, false
		}
		if valType == registry.EXPAND_SZ {
			return "EXPAND_SZ", s, true
		}
		return "SZ", s, true
	case registry.DWORD:
		n, _, e := k.GetIntegerValue(name)
		if e != nil {
			return "", nil, false
		}
		return "DWORD", n, true
	case registry.QWORD:
		n, _, e := k.GetIntegerValue(name)
		if e != nil {
			return "", nil, false
		}
		return "QWORD", n, true
	case registry.MULTI_SZ:
		s, _, e := k.GetStringsValue(name)
		if e != nil {
			return "", nil, false
		}
		return "MULTI_SZ", s, true
	case registry.BINARY:
		b, _, e := k.GetBinaryValue(name)
		if e != nil {
			return "", nil, false
		}
		return "BINARY", b, true
	default:
		return fmt.Sprintf("TYPE_%d", valType), nil, false
	}
}

func saveRegBackup(cfg Config, e regBackupEntry) (string, error) {
	if e.ID == "" {
		e.ID = fmt.Sprintf("%d_%s", time.Now().UnixNano(), sanitizeFileToken(e.Name))
	}
	if e.DeletedAt == "" {
		e.DeletedAt = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(regBackupDir(cfg), e.ID+".json")
	return p, os.WriteFile(p, b, 0600)
}

func sanitizeFileToken(s string) string {
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, s)
	if len(s) > 40 {
		s = s[:40]
	}
	if s == "" {
		return "val"
	}
	return s
}

func regDeleteValueAction(cfg Config, params map[string]any) (map[string]any, error) {
	root, hive, path, name, err := parseRegTarget(params)
	if err != nil {
		return nil, err
	}
	typ, data, existed := readRegValueAny(root, path, name)
	bak := regBackupEntry{
		Hive: hive, Path: path, Name: name, Existed: existed, Type: typ, Data: data, Action: "delete",
	}
	bakPath, berr := saveRegBackup(cfg, bak)
	if berr != nil {
		return nil, berr
	}
	k, err := registry.OpenKey(root, path, registry.SET_VALUE)
	if err != nil {
		return map[string]any{"ok": false, "backup": bakPath}, err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil {
		return map[string]any{"ok": false, "backup": bakPath, "existed": existed}, err
	}
	return map[string]any{
		"ok": true, "hive": hive, "path": path, "name": name,
		"backup_id": strings.TrimSuffix(filepath.Base(bakPath), ".json"), "backup": bakPath, "existed": existed,
	}, nil
}

func regSetValueAction(cfg Config, params map[string]any) (map[string]any, error) {
	root, hive, path, name, err := parseRegTarget(params)
	if err != nil {
		return nil, err
	}
	typ, data, existed := readRegValueAny(root, path, name)
	bak := regBackupEntry{
		Hive: hive, Path: path, Name: name, Existed: existed, Type: typ, Data: data, Action: "set",
	}
	bakPath, berr := saveRegBackup(cfg, bak)
	if berr != nil {
		return nil, berr
	}
	wantType := strings.ToUpper(strings.TrimSpace(fmt.Sprint(params["type"])))
	if wantType == "" {
		wantType = "SZ"
	}
	k, err := registry.OpenKey(root, path, registry.SET_VALUE)
	if err != nil {
		var k2 registry.Key
		k2, _, err = registry.CreateKey(root, path, registry.SET_VALUE)
		if err != nil {
			return map[string]any{"ok": false, "backup": bakPath}, err
		}
		k = k2
	}
	defer k.Close()
	switch wantType {
	case "SZ":
		err = k.SetStringValue(name, fmt.Sprint(params["data"]))
	case "EXPAND_SZ":
		err = k.SetExpandStringValue(name, fmt.Sprint(params["data"]))
	case "DWORD":
		var n uint64
		fmt.Sscan(fmt.Sprint(params["data"]), &n)
		err = k.SetDWordValue(name, uint32(n))
	case "QWORD":
		var n uint64
		fmt.Sscan(fmt.Sprint(params["data"]), &n)
		err = k.SetQWordValue(name, n)
	default:
		return nil, fmt.Errorf("不支持的注册表类型: %s", wantType)
	}
	if err != nil {
		return map[string]any{"ok": false, "backup": bakPath}, err
	}
	return map[string]any{
		"ok": true, "hive": hive, "path": path, "name": name, "type": wantType,
		"backup_id": strings.TrimSuffix(filepath.Base(bakPath), ".json"), "backup": bakPath,
	}, nil
}

func regRollbackAction(cfg Config, params map[string]any) (map[string]any, error) {
	id := strings.TrimSpace(fmt.Sprint(params["backup_id"]))
	if id == "" {
		id = strings.TrimSpace(fmt.Sprint(params["id"]))
	}
	path := strings.TrimSpace(fmt.Sprint(params["backup"]))
	if path == "" && id != "" {
		path = filepath.Join(regBackupDir(cfg), id+".json")
	}
	if path == "" {
		return nil, fmt.Errorf("缺少 backup_id")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e regBackupEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	root, _, _, _, err := parseRegTarget(map[string]any{"hive": e.Hive, "path": e.Path, "name": e.Name})
	if err != nil {
		return nil, err
	}
	if !e.Existed {
		k, err := registry.OpenKey(root, e.Path, registry.SET_VALUE)
		if err != nil {
			return map[string]any{"ok": true, "restored": "absent", "note": "原值本不存在且键不可写"}, nil
		}
		defer k.Close()
		_ = k.DeleteValue(e.Name)
		return map[string]any{"ok": true, "restored": "deleted", "hive": e.Hive, "path": e.Path, "name": e.Name}, nil
	}
	k, err := registry.OpenKey(root, e.Path, registry.SET_VALUE)
	if err != nil {
		var k2 registry.Key
		k2, _, err = registry.CreateKey(root, e.Path, registry.SET_VALUE)
		if err != nil {
			return nil, err
		}
		k = k2
	}
	defer k.Close()
	switch strings.ToUpper(e.Type) {
	case "SZ":
		err = k.SetStringValue(e.Name, fmt.Sprint(e.Data))
	case "EXPAND_SZ":
		err = k.SetExpandStringValue(e.Name, fmt.Sprint(e.Data))
	case "DWORD":
		var n uint64
		fmt.Sscan(fmt.Sprint(e.Data), &n)
		err = k.SetDWordValue(e.Name, uint32(n))
	case "QWORD":
		var n uint64
		fmt.Sscan(fmt.Sprint(e.Data), &n)
		err = k.SetQWordValue(e.Name, n)
	case "MULTI_SZ":
		var arr []string
		switch v := e.Data.(type) {
		case []any:
			for _, x := range v {
				arr = append(arr, fmt.Sprint(x))
			}
		case []string:
			arr = v
		}
		err = k.SetStringsValue(e.Name, arr)
	default:
		return nil, fmt.Errorf("无法回滚类型 %s", e.Type)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "restored": e.Type, "hive": e.Hive, "path": e.Path, "name": e.Name, "backup": path}, nil
}

func clearPersistenceAction(cfg Config, params map[string]any) (map[string]any, error) {
	kind := strings.ToLower(strings.TrimSpace(fmt.Sprint(params["kind"])))
	name := strings.TrimSpace(fmt.Sprint(params["name"]))
	if name == "" {
		return nil, fmt.Errorf("缺少 name")
	}
	switch kind {
	case "", "run", "runonce":
		hive := strings.ToUpper(strings.TrimSpace(fmt.Sprint(params["hive"])))
		if hive == "" {
			hive = "HKCU"
		}
		sub := `Software\Microsoft\Windows\CurrentVersion\Run`
		if kind == "runonce" {
			sub = `Software\Microsoft\Windows\CurrentVersion\RunOnce`
		}
		return regDeleteValueAction(cfg, map[string]any{"hive": hive, "path": sub, "name": name})
	case "task":
		return deleteScheduledTask(map[string]any{"task": name, "force": params["force"]})
	case "service":
		return disableWindowsService(map[string]any{"service": name})
	default:
		return nil, fmt.Errorf("不支持的持久化类型: %s", kind)
	}
}

func recheckPersistenceAction(params map[string]any) (map[string]any, error) {
	kind := strings.ToLower(strings.TrimSpace(fmt.Sprint(params["kind"])))
	name := strings.TrimSpace(fmt.Sprint(params["name"]))
	out := map[string]any{"ok": true, "kind": kind, "name": name}
	switch kind {
	case "run", "runonce", "":
		hive := strings.ToUpper(strings.TrimSpace(fmt.Sprint(params["hive"])))
		if hive == "" {
			hive = "HKCU"
		}
		sub := `Software\Microsoft\Windows\CurrentVersion\Run`
		if kind == "runonce" {
			sub = `Software\Microsoft\Windows\CurrentVersion\RunOnce`
		}
		root, _, _, _, err := parseRegTarget(map[string]any{"hive": hive, "path": sub, "name": name})
		if err != nil {
			return nil, err
		}
		_, _, exists := readRegValueAny(root, sub, name)
		out["present"] = exists
		out["cleared"] = !exists
	case "task":
		o, err := runCmd(30*time.Second, "schtasks", "/Query", "/TN", name, "/FO", "LIST")
		out["present"] = err == nil && !strings.Contains(strings.ToLower(o), "error")
		out["cleared"] = !out["present"].(bool)
		out["output"] = o
	case "service":
		o, err := runCmd(20*time.Second, "sc", "qc", name)
		out["output"] = o
		out["present"] = err == nil
		low := strings.ToLower(o)
		out["disabled"] = strings.Contains(low, "disabled")
		out["cleared"] = out["disabled"]
	default:
		return nil, fmt.Errorf("不支持复查类型: %s", kind)
	}
	return out, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
