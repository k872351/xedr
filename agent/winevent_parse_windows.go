//go:build windows

package main

import (
	"encoding/xml"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type winevtXML struct {
	System struct {
		// System 通道常见 <EventID Qualifiers="…">7036</EventID>；不能直接解到 int
		EventID struct {
			Qualifiers string `xml:"Qualifiers,attr"`
			Value      string `xml:",chardata"`
		} `xml:"EventID"`
		Channel     string `xml:"Channel"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name string `xml:"Name,attr"`
			Text string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func winevtParseEventID(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return n
}

func winevtParseXML(xmlText string, logChannel string) map[string]any {
	var doc winevtXML
	if err := xml.Unmarshal([]byte(xmlText), &doc); err != nil {
		return nil
	}
	data := map[string]string{}
	unnamed := 0
	for _, d := range doc.EventData.Data {
		v := strings.TrimSpace(d.Text)
		if d.Name != "" {
			data[d.Name] = v
			continue
		}
		// System 7036/7040 等无名 Data：按顺序记为 param1、param2…
		unnamed++
		data["param"+strconv.Itoa(unnamed)] = v
	}
	eid := winevtParseEventID(doc.System.EventID.Value)
	chanName := doc.System.Channel
	if chanName == "" {
		chanName = logChannel
	}
	ts := winevtFormatTime(doc.System.TimeCreated.SystemTime)
	return winevtMapEvent(eid, ts, chanName, data)
}

func winevtFormatTime(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Now().Format("2006-01-02T15:04:05")
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.Local().Format("2006-01-02T15:04:05")
	}
	if t, err := time.Parse("2006-01-02T15:04:05.9999999Z", raw); err == nil {
		return t.Local().Format("2006-01-02T15:04:05")
	}
	return raw
}

func winevtMapEvent(eid int, ts, chanName string, data map[string]string) map[string]any {
	withChan := func(d map[string]any) map[string]any {
		d["channel"] = chanName
		return d
	}
	lowChan := strings.ToLower(chanName)
	// 按通道优先：BITS/SMB 的 EventID 与 Sysmon/其它通道重叠，不能只靠 ID。
	if strings.Contains(lowChan, "bits") {
		return winevtBITSEvent(eid, ts, chanName, data)
	}
	if strings.Contains(lowChan, "smb") {
		return winevtSMBEvent(eid, ts, chanName, data)
	}
	switch eid {
	case 5140, 5142, 5143, 5145:
		return winevtSMBServerEvent(eid, ts, chanName, data)
	case 4624:
		logonType := data["LogonType"]
		if logonType == "0" || logonType == "5" || logonType == "11" {
			return nil
		}
		user := data["TargetUserName"]
		if user == "ANONYMOUS LOGON" || user == "SYSTEM" || user == "LOCAL SERVICE" || user == "NETWORK SERVICE" {
			return nil
		}
		if winevtUserNoise(user) {
			return nil
		}
		ip := data["IpAddress"]
		if logonType == "3" && (ip == "127.0.0.1" || ip == "::1" || ip == "-" || ip == "") {
			return nil
		}
		return map[string]any{
			"etype": "win_logon", "summary": "登录成功: " + user + " type=" + logonType,
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "user": user, "domain": data["TargetDomainName"],
				"logon_type": logonType, "ip": ip, "process": data["ProcessName"],
			}),
		}
	case 4625:
		u := data["TargetUserName"]
		if strings.HasSuffix(u, "$") || u == "SYSTEM" || u == "LOCAL SERVICE" || u == "NETWORK SERVICE" || u == "-" || u == "" {
			return nil
		}
		return map[string]any{
			"etype": "win_logon_fail", "summary": "登录失败: " + u,
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "user": u, "ip": data["IpAddress"],
				"status": data["Status"], "substatus": data["SubStatus"],
			}),
		}
	case 4648:
		proc := data["ProcessName"]
		if winevtPathEnds(proc, `\svchost.exe`, `\taskhostw.exe`, `\trustedinstaller.exe`, `\lsass.exe`, `\services.exe`, `\winlogon.exe`, `\consent.exe`) {
			return nil
		}
		user := data["TargetUserName"]
		return map[string]any{
			"etype": "win_explicit_logon", "summary": "显式凭据登录: " + user,
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "user": user, "process": proc, "target": data["TargetServerName"],
			}),
		}
	case 4720:
		u := data["TargetUserName"]
		return map[string]any{
			"etype": "win_account_create", "summary": "账号创建: " + u, "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid, "user": u, "by": data["SubjectUserName"]}),
		}
	case 4722:
		u := data["TargetUserName"]
		return map[string]any{
			"etype": "win_account_enable", "summary": "账号启用: " + u, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid, "user": u}),
		}
	case 4724:
		u := data["TargetUserName"]
		return map[string]any{
			"etype": "win_password_reset", "summary": "密码重置: " + u, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid, "user": u}),
		}
	case 4728, 4732, 4756:
		member, group := data["MemberName"], data["TargetUserName"]
		sum := "加入组: " + member + " → " + group
		if eid == 4732 {
			sum = "加入本地组: " + member + " → " + group
		}
		if eid == 4756 {
			sum = "加入通用组: " + member + " → " + group
		}
		return map[string]any{
			"etype": "win_group_add", "summary": sum, "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid, "member": member, "group": group}),
		}
	case 4697:
		sp := data["ServiceFileName"]
		if winevtWinDirPath(sp) {
			return nil
		}
		ev := map[string]any{
			"etype": "win_service_install", "summary": "服务安装: " + data["ServiceName"], "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "name": data["ServiceName"], "service_name": data["ServiceName"],
				"path": sp, "account": data["ServiceAccount"],
			}),
		}
		enrichServiceInstallEvent(ev)
		return ev
	case 4698:
		tn := data["TaskName"]
		if winevtTaskMicrosoft(tn) {
			return nil
		}
		ev := map[string]any{
			"etype": "win_task_create", "summary": "计划任务创建: " + tn, "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "task": tn, "task_name": tn,
				"content": data["TaskContent"],
			}),
		}
		enrichWinTaskEvent(ev, tn, data["TaskContent"])
		return ev
	case 4702:
		tn := data["TaskName"]
		if winevtTaskMicrosoft(tn) {
			return nil
		}
		ev := map[string]any{
			"etype": "win_task_update", "summary": "计划任务更新: " + tn, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "task": tn, "task_name": tn,
				"content": data["TaskContent"],
			}),
		}
		if strings.TrimSpace(data["TaskContent"]) != "" {
			enrichWinTaskEvent(ev, tn, data["TaskContent"])
		}
		return ev
	case 1102:
		return map[string]any{
			"etype": "win_audit_clear", "summary": "安全日志被清空", "severity": "critical", "ts": ts,
			"detail": withChan(map[string]any{"source": "security", "event_id": eid}),
		}
	case 4672:
		su := data["SubjectUserName"]
		if su == "SYSTEM" || su == "LOCAL SERVICE" || su == "NETWORK SERVICE" || strings.HasSuffix(su, "$") || winevtUserNoise(su) {
			return nil
		}
		priv := data["PrivilegeList"]
		if priv == "" || !winevtPrivInteresting(priv) {
			return nil
		}
		return map[string]any{
			"etype": "win_special_priv", "summary": "特殊权限分配: " + su, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security", "event_id": eid, "user": su, "domain": data["SubjectDomainName"], "privileges": priv,
			}),
		}
	case 7045:
		ip := data["ImagePath"]
		if winevtWinDirPath(ip) {
			return nil
		}
		ev := map[string]any{
			"etype": "win_service_install", "summary": "服务安装: " + data["ServiceName"], "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "system", "event_id": eid, "name": data["ServiceName"], "service_name": data["ServiceName"],
				"path": ip, "account": data["AccountName"], "start_type": data["StartType"],
			}),
		}
		enrichServiceInstallEvent(ev)
		return ev
	case 7036:
		return map[string]any{
			"etype": "win_service_state", "summary": "服务状态: " + data["param1"] + " → " + data["param2"],
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "system", "event_id": eid, "name": data["param1"], "state": data["param2"]}),
		}
	case 7040:
		disp := data["param1"]
		short := data["param4"]
		if short == "" {
			short = disp
		}
		if winevtServiceNoise(short) {
			return nil
		}
		to := data["param3"]
		if !strings.Contains(strings.ToLower(to), "disabled") && !strings.Contains(to, "禁用") {
			return nil
		}
		return map[string]any{
			"etype": "win_service_config", "summary": "服务被禁用: " + disp, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "system", "event_id": eid, "name": disp, "service": short, "from": data["param2"], "to": to,
			}),
		}
	case 4103:
		payload := data["Payload"]
		if payload == "" {
			payload = data["MessageNumber"]
		}
		snip := winevtSnip(payload, 180)
		return map[string]any{
			"etype": "win_ps_module", "summary": "PowerShell 模块日志: " + snip, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "powershell", "event_id": eid, "payload": payload, "context": data["ContextInfo"]}),
		}
	case 4104:
		script := data["ScriptBlockText"]
		if script == "" {
			return nil
		}
		sev, sum := "info", "PowerShell 脚本块"
		if winevtSuspiciousPS(script) {
			sev, sum = "high", "可疑 PowerShell 脚本块"
		}
		det := withChan(map[string]any{
			"source": "powershell", "event_id": eid, "script_block": script,
			"script_block_id": data["ScriptBlockId"], "path": data["Path"],
			"host_application_id": data["HostApplicationId"], "host_id": data["HostId"],
		})
		winevtEnrichScriptBlock(det, ts)
		return map[string]any{
			"etype": "win_ps_scriptblock", "summary": sum + ": " + winevtSnip(script, 160),
			"severity": sev, "ts": ts,
			"detail": det,
		}
	case 8:
		src := data["SourceImage"]
		if winevtSysmonSrcNoise(src) {
			return nil
		}
		tgt := data["TargetImage"]
		if winevtBrowserPair(src, tgt) {
			return nil
		}
		return map[string]any{
			"etype": "remote_thread", "summary": "远程线程(Sysmon): " + filepath.Base(src) + " → " + filepath.Base(tgt),
			"severity": "high", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": src, "target_path": tgt,
				"pid": winevtInt(data["SourceProcessId"]), "target_pid": winevtInt(data["TargetProcessId"]),
				"start_address": data["StartAddress"],
			}),
		}
	case 10:
		am := data["GrantedAccess"]
		if am == "" {
			return nil
		}
		mask, ok := winevtParseHex64(am)
		if !ok {
			return nil
		}
		want := uint64(0x20 | 0x2 | 0x8)
		if (mask&want) == 0 && mask != 0x1FFFFF && mask != 0x1F0FFF {
			return nil
		}
		src := data["SourceImage"]
		if winevtSysmonAccessNoise(src) {
			return nil
		}
		tgt := data["TargetImage"]
		sev := "medium"
		etype := "process_access"
		sum := "进程打开(Sysmon): " + filepath.Base(src) + " → " + filepath.Base(tgt)
		detail := withChan(map[string]any{
			"source": "sysmon", "event_id": eid, "path": src, "target_path": tgt,
			"pid": winevtInt(data["SourceProcessId"]), "target_pid": winevtInt(data["TargetProcessId"]),
			"access": am, "call_trace": data["CallTrace"],
		})
		// 凭据访问：打开 LSASS 升级为 credential_access，并与内存扫描触发绑定
		if winevtPathEnds(tgt, `\lsass.exe`) {
			sev = "high"
			etype = "credential_access"
			sum = "凭据访问(Sysmon): " + filepath.Base(src) + " → lsass.exe"
			detail["technique"] = "T1003.001"
			detail["target_name"] = "lsass.exe"
			detail["credential_access"] = true
		}
		return map[string]any{
			"etype": etype, "summary": sum, "severity": sev, "ts": ts, "detail": detail,
		}
	case 12: // RegistryEvent CreateKey / DeleteKey
		if !winevtIsSysmon(chanName) {
			return winevtGenericEvent(eid, ts, chanName, data)
		}
		to := data["TargetObject"]
		if !winevtRegASEP(to) {
			return nil
		}
		evType := data["EventType"]
		etype, sum := "registry_create", "注册表创建(Sysmon): "+to
		if strings.Contains(strings.ToLower(evType), "delete") {
			etype, sum = "registry_delete", "注册表删除(Sysmon): "+to
		}
		return map[string]any{
			"etype": etype, "summary": sum, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": to, "operation": evType,
				"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
				"process_path": data["Image"], "topic": winevtPersistTopic(to),
			}),
		}
	case 13:
		to := data["TargetObject"]
		if !winevtRegASEP(to) {
			return nil
		}
		return map[string]any{
			"etype": "registry_write", "summary": "注册表写入(Sysmon): " + to, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": to, "value": data["Details"],
				"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
				"process_path": data["Image"], "topic": winevtPersistTopic(to),
			}),
		}
	case 14: // RegistryEvent RenameKey / RenameValue
		if !winevtIsSysmon(chanName) {
			return winevtGenericEvent(eid, ts, chanName, data)
		}
		to := data["TargetObject"]
		if !winevtRegASEP(to) {
			return nil
		}
		return map[string]any{
			"etype": "registry_rename", "summary": "注册表重命名(Sysmon): " + to, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": to, "new_name": data["NewName"],
				"operation": data["EventType"],
				"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
				"process_path": data["Image"], "topic": winevtPersistTopic(to),
			}),
		}
	case 6: // DriverLoad
		if !winevtIsSysmon(chanName) {
			return winevtGenericEvent(eid, ts, chanName, data)
		}
		img := data["ImageLoaded"]
		if img == "" {
			img = data["Image"]
		}
		if img == "" {
			return nil
		}
		sigSt := data["SignatureStatus"]
		sev := "info"
		if winevtUnsignedStatus(sigSt) {
			sev = "high"
		}
		return map[string]any{
			"etype": "driver_load_sysmon", "summary": "驱动加载(Sysmon): " + filepath.Base(img),
			"severity": sev, "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": img, "name": filepath.Base(img),
				"signed": sigSt, "signer": data["Signature"], "hash": data["Hashes"],
			}),
		}
	case 19, 20: // WmiEventFilter / Consumer（21 与 RDP 会话共用，见下方）
		if !winevtIsSysmon(chanName) {
			return winevtGenericEvent(eid, ts, chanName, data)
		}
		et, sum, det := winevtSysmonWmiParts(eid, data)
		return map[string]any{"etype": et, "summary": sum, "severity": "high", "ts": ts, "detail": withChan(det)}
	case 22:
		if strings.Contains(strings.ToLower(chanName), "terminalservices") {
			user := data["User"]
			if user == "" {
				user = data["Account"]
			}
			return map[string]any{
				"etype": "win_rdp_session", "summary": "终端会话: " + user, "severity": "info", "ts": ts,
				"detail": withChan(map[string]any{"source": "terminalservices", "event_id": eid, "user": user, "ip": data["Address"]}),
			}
		}
		qname := data["QueryName"]
		if qname == "" || strings.HasSuffix(strings.ToLower(qname), ".arpa") || strings.HasSuffix(strings.ToLower(qname), ".local") {
			return nil
		}
		return map[string]any{
			"etype": "dns_query", "summary": "DNS(Sysmon): " + qname, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "query": qname, "type": data["QueryType"],
				"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
			}),
		}
	case 4688:
		img := data["NewProcessName"]
		cmd := data["CommandLine"]
		name := filepath.Base(img)
		return map[string]any{
			"etype": "process_create_etw", "summary": "进程创建(4688): " + name, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "security_4688", "event_id": eid, "pid": winevtInt(data["NewProcessId"]),
				"ppid": winevtInt(data["ProcessId"]), "name": name, "path": img, "command_line": cmd,
				"user": data["SubjectUserName"],
			}),
		}
	case 1:
		img := data["Image"]
		if winevtSysmonSrcNoise(img) {
			return nil
		}
		parentImg := data["ParentImage"]
		detail := withChan(map[string]any{
			"source": "sysmon", "event_id": eid, "pid": winevtInt(data["ProcessId"]),
			"ppid": winevtInt(data["ParentProcessId"]), "name": filepath.Base(img), "path": img,
			"command_line": data["CommandLine"], "user": data["User"],
			"hash": data["Hashes"], "hashes": data["Hashes"],
			"parent_path": parentImg, "parent_name": filepath.Base(parentImg),
			"parent_command_line": data["ParentCommandLine"],
			"company": data["Company"], "product": data["Product"], "description": data["Description"],
			"file_version": data["FileVersion"], "integrity": data["IntegrityLevel"],
			"original_file_name": data["OriginalFileName"],
			"logon_guid": data["LogonGuid"], "process_guid": data["ProcessGuid"],
			"parent_process_guid": data["ParentProcessGuid"],
		})
		winevtApplyHashes(detail, data["Hashes"])
		winevtAttachSysmonExtras(detail, data)
		// Sysmon 未带公司/签名时补读 PE；Temp 安装器落地后常秒删，需同步补一次
		winevtEnrichProcessImage(detail, img)
		return map[string]any{
			"etype": "process_create_sysmon", "summary": "进程创建(Sysmon): " + filepath.Base(img), "severity": "info", "ts": ts,
			"detail": detail,
		}
	case 3:
		detail := withChan(map[string]any{
			"source": "sysmon", "event_id": eid, "remote_ip": data["DestinationIp"], "remote_port": data["DestinationPort"],
			"remote": data["DestinationIp"] + ":" + data["DestinationPort"],
			"local": data["SourceIp"], "local_port": data["SourcePort"], "proto": data["Protocol"],
			"pid": winevtInt(data["ProcessId"]),
			"process_name": filepath.Base(data["Image"]), "path": data["Image"],
			"user": data["User"], "initiated": data["Initiated"],
		})
		winevtAttachSysmonExtras(detail, data)
		return map[string]any{
			"etype": "network_connect", "summary": "网络(Sysmon): " + data["DestinationIp"] + ":" + data["DestinationPort"],
			"severity": "info", "ts": ts, "detail": detail,
		}
	case 11:
		target := data["TargetFilename"]
		if target == "" {
			return nil
		}
		detail := withChan(map[string]any{
			"source": "sysmon", "event_id": eid, "path": target, "pid": winevtInt(data["ProcessId"]),
			"process_name": filepath.Base(data["Image"]), "process_path": data["Image"],
			"topic": winevtFileTopic(target),
			"hash": data["Hashes"], "hashes": data["Hashes"],
		})
		winevtApplyHashes(detail, data["Hashes"])
		winevtAttachSysmonExtras(detail, data)
		attachFileMetaCached(detail, target)
		winevtEnrichProcessImage(detail, target)
		sev := bumpSeverityForFileMeta("info", detail)
		return map[string]any{
			"etype": "file_create", "summary": "文件创建(Sysmon): " + filepath.Base(target), "severity": sev, "ts": ts,
			"detail": detail,
		}
	case 5: // ProcessTerminate
		if !winevtIsSysmon(chanName) {
			return winevtGenericEvent(eid, ts, chanName, data)
		}
		img := data["Image"]
		return map[string]any{
			"etype": "process_exit_sysmon", "summary": "进程退出(Sysmon): " + filepath.Base(img),
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "pid": winevtInt(data["ProcessId"]),
				"name": filepath.Base(img), "path": img, "exit_code": data["ExitCode"],
			}),
		}
	case 7: // ImageLoad
		if !winevtIsSysmon(chanName) {
			return winevtGenericEvent(eid, ts, chanName, data)
		}
		img := data["ImageLoaded"]
		if img == "" {
			img = data["Image"]
		}
		host := data["Image"]
		sigSt := data["SignatureStatus"]
		signed := sigSt
		if winevtUnsignedStatus(sigSt) {
			signed = "NotSigned"
		} else if strings.EqualFold(strings.TrimSpace(sigSt), "Valid") {
			signed = "Valid"
		}
		detail := withChan(map[string]any{
			"source": "sysmon", "event_id": eid, "path": img, "module": filepath.Base(img),
			"module_name": filepath.Base(img), "pid": winevtInt(data["ProcessId"]),
			"host_process": filepath.Base(host), "process_path": host,
			"signed": signed, "signer": data["Signature"], "signature_status": sigSt,
			"hash": data["Hashes"],
		})
		sev := "info"
		if winevtUnsignedStatus(sigSt) {
			sev = "medium"
		}
		return map[string]any{
			"etype": "image_load_sysmon", "summary": "DLL 加载(Sysmon): " + filepath.Base(img),
			"severity": sev, "ts": ts, "detail": detail,
		}
	case 15: // FileCreateStreamHash (ADS / MotW)
		if !winevtIsSysmon(chanName) {
			return winevtGenericEvent(eid, ts, chanName, data)
		}
		target := data["TargetFilename"]
		if target == "" {
			return nil
		}
		return map[string]any{
			"etype": "file_stream_create", "summary": "ADS/流创建(Sysmon): " + filepath.Base(target),
			"severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": target,
				"hash": data["Hash"], "contents": data["Contents"],
				"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
			}),
		}
	case 17: // PipeCreated
		if !winevtIsSysmon(chanName) {
			return winevtGenericEvent(eid, ts, chanName, data)
		}
		pipe := data["PipeName"]
		if pipe == "" {
			return nil
		}
		return map[string]any{
			"etype": "pipe_created", "summary": "命名管道(Sysmon): " + pipe,
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "pipe": pipe, "path": pipe,
				"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
			}),
		}
	case 26: // FileDeleteDetected
		if !winevtIsSysmon(chanName) {
			return winevtGenericEvent(eid, ts, chanName, data)
		}
		target := data["TargetFilename"]
		if target == "" {
			return nil
		}
		return map[string]any{
			"etype": "file_delete_detected", "summary": "文件删除检测(Sysmon): " + filepath.Base(target),
			"severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "sysmon", "event_id": eid, "path": target,
				"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
				"hash": data["Hashes"],
			}),
		}
	case 1116, 1117:
		threat := data["Threat Name"]
		if threat == "" {
			threat = data["Threat_Name"]
		}
		sev := "high"
		if eid == 1117 {
			sev = "info"
		}
		return map[string]any{
			"etype": "defender_detection", "summary": "Defender: " + threat, "severity": sev, "ts": ts,
			"detail": withChan(map[string]any{
				"source": "defender", "event_id": eid, "threat": threat, "path": data["Path"],
				"action": data["Action"], "user": data["User"],
			}),
		}
	case 1150, 5001:
		return map[string]any{
			"etype": "defender_status", "summary": "Defender 状态变更", "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "defender", "event_id": eid, "detail": data["Product Name"]}),
		}
	case 106, 140, 141, 200, 201:
		task := data["TaskName"]
		if task == "" {
			task = data["Path"]
		}
		ev := map[string]any{
			"etype": "win_task_ops", "summary": "任务计划(Sysmon/TS): " + task, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{
				"source": "winevent", "event_id": eid, "task": task, "task_name": task, "channel": chanName,
			}),
		}
		enrichWinTaskOpsFromCache(ev, task)
		return ev
	case 23: // Sysmon FileDelete 或 TerminalServices 会话
		if winevtIsSysmon(chanName) {
			target := data["TargetFilename"]
			if target == "" {
				return nil
			}
			return map[string]any{
				"etype": "file_delete", "summary": "文件删除(Sysmon): " + filepath.Base(target),
				"severity": "info", "ts": ts,
				"detail": withChan(map[string]any{
					"source": "sysmon", "event_id": eid, "path": target,
					"pid": winevtInt(data["ProcessId"]), "process_name": filepath.Base(data["Image"]),
					"hash": data["Hashes"], "is_executable": data["IsExecutable"],
				}),
			}
		}
		if !strings.Contains(strings.ToLower(chanName), "terminalservices") {
			return nil
		}
		user := data["User"]
		if user == "" {
			user = data["Account"]
		}
		return map[string]any{
			"etype": "win_rdp_session", "summary": "终端会话: " + user, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "terminalservices", "event_id": eid, "user": user, "ip": data["Address"]}),
		}
	case 25: // Sysmon ProcessTampering 或 TerminalServices
		if winevtIsSysmon(chanName) {
			img := data["Image"]
			typ := data["Type"]
			if typ == "" {
				typ = "Tampering"
			}
			return map[string]any{
				"etype": "process_tampering", "summary": "进程篡改(Sysmon): " + filepath.Base(img) + " · " + typ,
				"severity": "high", "ts": ts,
				"detail": withChan(map[string]any{
					"source": "sysmon", "event_id": eid, "path": img, "name": filepath.Base(img),
					"pid": winevtInt(data["ProcessId"]), "tamper_type": typ,
				}),
			}
		}
		if !strings.Contains(strings.ToLower(chanName), "terminalservices") {
			return nil
		}
		user := data["User"]
		if user == "" {
			user = data["Account"]
		}
		return map[string]any{
			"etype": "win_rdp_session", "summary": "终端会话: " + user, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "terminalservices", "event_id": eid, "user": user, "ip": data["Address"]}),
		}
	case 21: // Sysmon WmiEventConsumerToFilter 或 TerminalServices 会话
		if winevtIsSysmon(chanName) {
			et, sum, det := winevtSysmonWmiParts(eid, data)
			return map[string]any{"etype": et, "summary": sum, "severity": "high", "ts": ts, "detail": withChan(det)}
		}
		if !strings.Contains(strings.ToLower(chanName), "terminalservices") {
			return nil
		}
		user := data["User"]
		if user == "" {
			user = data["Account"]
		}
		return map[string]any{
			"etype": "win_rdp_session", "summary": "终端会话: " + user, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "terminalservices", "event_id": eid, "user": user, "ip": data["Address"]}),
		}
	case 24:
		if !strings.Contains(strings.ToLower(chanName), "terminalservices") {
			return nil
		}
		user := data["User"]
		if user == "" {
			user = data["Account"]
		}
		return map[string]any{
			"etype": "win_rdp_session", "summary": "终端会话: " + user, "severity": "info", "ts": ts,
			"detail": withChan(map[string]any{"source": "terminalservices", "event_id": eid, "user": user, "ip": data["Address"]}),
		}
	case 2004, 2005, 2006, 2010, 2011:
		rule := data["RuleName"]
		if rule == "" {
			rule = data["Rule Id"]
		}
		return map[string]any{
			"etype": "win_firewall", "summary": "防火墙: " + rule, "severity": "medium", "ts": ts,
			"detail": withChan(map[string]any{"source": "firewall", "event_id": eid, "rule": rule, "app": data["Application"]}),
		}
	case 8001, 8002, 8003, 8004:
		app := data["AppName"]
		if app == "" {
			app = data["FilePath"]
		}
		sev := "medium"
		if eid == 8004 {
			sev = "info"
		}
		return map[string]any{
			"etype": "win_applocker", "summary": "AppLocker: " + filepath.Base(app), "severity": sev, "ts": ts,
			"detail": withChan(map[string]any{"source": "applocker", "event_id": eid, "path": app, "user": data["User"]}),
		}
	case 3033, 3063, 3076, 3077:
		return map[string]any{
			"etype": "win_code_integrity", "summary": "代码完整性事件", "severity": "high", "ts": ts,
			"detail": withChan(map[string]any{"source": "codeintegrity", "event_id": eid, "file": data["FileName"], "detail": data["Status"]}),
		}
	}
	if ev := winevtGenericEvent(eid, ts, chanName, data); ev != nil {
		return ev
	}
	return nil
}

func winevtIsSysmon(chanName string) bool {
	return strings.Contains(strings.ToLower(chanName), "sysmon")
}

// winevtApplyHashes 把 Sysmon Hashes（MD5=..,SHA256=..,IMPHASH=..）拆成独立字段，方便管理端展示。
func winevtApplyHashes(detail map[string]any, raw string) {
	raw = strings.TrimSpace(raw)
	if detail == nil || raw == "" {
		return
	}
	detail["hash"] = raw
	detail["hashes"] = raw
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		i := strings.IndexByte(part, '=')
		if i <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(part[:i]))
		v := strings.TrimSpace(part[i+1:])
		if v == "" {
			continue
		}
		switch k {
		case "md5":
			detail["md5"] = v
		case "sha1":
			detail["sha1"] = v
		case "sha256":
			detail["sha256"] = v
		case "imphash":
			if asString(detail["imphash"]) == "" {
				detail["imphash"] = v
			}
		}
	}
}

// winevtEnrichProcessImage：非系统路径补签名/厂商/哈希（Temp 落地文件尤其需要同步）。
func winevtEnrichProcessImage(detail map[string]any, img string) {
	if detail == nil || img == "" || !peExtHot(img) {
		return
	}
	needHash := asString(detail["sha256"]) == ""
	needCorp := asString(detail["company"]) == "" && asString(detail["file_version"]) == ""
	needSig := asString(detail["signed"]) == ""
	if !needHash && !needCorp && !needSig {
		attachFileMetaCached(detail, img)
		return
	}
	// 用户目录 / Temp：文件可能秒删，同步补齐；系统目录只走缓存预热
	low := strings.ToLower(img)
	urgent := strings.Contains(low, `\temp\`) || strings.Contains(low, `\appdata\`) ||
		strings.Contains(low, `\downloads\`) || strings.Contains(low, `\users\`) ||
		!winevtWinDirPath(img)
	if urgent {
		pm := peMetaOf(img)
		if needCorp {
			if pm.Company != "" {
				detail["company"] = pm.Company
			}
			if pm.FileVersion != "" {
				detail["file_version"] = pm.FileVersion
			}
		}
		if needSig && pm.Signed != "" {
			detail["signed"] = pm.Signed
			if pm.Signer != "" {
				detail["signer"] = pm.Signer
			}
		}
		if needHash && pm.SHA256 != "" {
			detail["sha256"] = pm.SHA256
		}
		attachFileMeta(detail, img)
		return
	}
	peMetaWarmAsync(img)
	attachFileMetaCached(detail, img)
}

// winevtAttachSysmonExtras 把未单独建模的 Sysmon EventData 灌进 detail，供日志调查全字段研判。
func winevtAttachSysmonExtras(detail map[string]any, data map[string]string) {
	if detail == nil || data == nil {
		return
	}
	skip := map[string]bool{
		"Image": true, "CommandLine": true, "ProcessId": true, "ParentProcessId": true,
		"User": true, "Hashes": true, "ParentImage": true, "ParentCommandLine": true,
		"DestinationIp": true, "DestinationPort": true, "SourceIp": true, "SourcePort": true,
		"Protocol": true, "QueryName": true, "QueryType": true, "TargetFilename": true,
		"SourceImage": true, "TargetImage": true, "GrantedAccess": true, "CallTrace": true,
		"TargetObject": true, "Details": true, "PipeName": true, "ImageLoaded": true,
		"RuleName": true,
	}
	n := 0
	for k, v := range data {
		v = strings.TrimSpace(v)
		if v == "" || skip[k] {
			continue
		}
		lk := strings.ToLower(k)
		if _, exists := detail[lk]; exists {
			continue
		}
		if _, exists := detail[k]; exists {
			continue
		}
		// 扁平写入，日志调查/详情可直接展示
		detail[lk] = v
		n++
		if n >= 24 {
			break
		}
	}
}

func winevtUnsignedStatus(st string) bool {
	s := strings.ToLower(strings.TrimSpace(st))
	if s == "" {
		return false
	}
	return strings.Contains(s, "notsigned") || strings.Contains(s, "unavailable") ||
		strings.Contains(s, "hashmismatch") || strings.Contains(s, "expired") ||
		s == "unsigned" || strings.Contains(s, "未签名")
}

func winevtGenericEvent(eid int, ts, chanName string, data map[string]string) map[string]any {
	if eid <= 0 {
		return nil
	}
	low := strings.ToLower(chanName)
	// BITS / SMB 已有专用 mapper；未命中时不要再兜底，避免重复语义
	if strings.Contains(low, "bits") || strings.Contains(low, "smb") {
		return nil
	}
	// XPath 已筛过的事件：兜底带 EventID 进时间线，供日志规则匹配
	sum := chanName + " E" + strconv.Itoa(eid)
	src := "winevent"
	if winevtIsSysmon(chanName) {
		src = "sysmon"
	}
	d := map[string]any{"source": src, "event_id": eid, "channel": chanName}
	for _, k := range []string{"TaskName", "Path", "UserContext", "ResultCode", "ImagePath", "ServiceName", "param1", "param2",
		"Image", "CommandLine", "User", "TargetFilename", "ProcessId", "ParentImage"} {
		if v := data[k]; v != "" {
			lk := strings.ToLower(k)
			if k == "Image" {
				d["path"] = v
				d["name"] = filepath.Base(v)
			} else if k == "CommandLine" {
				d["command_line"] = v
			} else if k == "ProcessId" {
				d["pid"] = winevtInt(v)
			} else if k == "ParentImage" {
				d["parent_path"] = v
				d["parent_name"] = filepath.Base(v)
			} else if k == "TargetFilename" {
				d["path"] = v
			} else {
				d[lk] = v
			}
		}
	}
	if winevtIsSysmon(chanName) {
		winevtAttachSysmonExtras(d, data)
	}
	return map[string]any{
		"etype": "winevent_generic", "summary": sum, "severity": "info", "ts": ts, "detail": d,
	}
}

func winevtPick(data map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(data[k]); v != "" {
			return v
		}
	}
	// 大小写不敏感兜底
	lowWant := map[string]bool{}
	for _, k := range keys {
		lowWant[strings.ToLower(k)] = true
	}
	for k, v := range data {
		if lowWant[strings.ToLower(k)] && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func winevtBITSEvent(eid int, ts, chanName string, data map[string]string) map[string]any {
	job := winevtPick(data, "jobTitle", "JobTitle", "name", "Name", "TransferId", "jobId", "JobId")
	url := winevtPick(data, "url", "Url", "RemoteName", "remoteName", "RemoteUrl")
	local := winevtPick(data, "localName", "LocalName", "fileName", "FileName", "Path")
	owner := winevtPick(data, "jobOwner", "JobOwner", "User", "Owner")
	sev := "info"
	sum := "BITS: " + firstNonEmpty(job, url, local, "job")
	if url != "" || local != "" {
		sev = "medium"
		if taskSuspiciousExecute(local) || strings.Contains(strings.ToLower(url), "http") {
			sev = "high"
		}
	}
	return map[string]any{
		"etype": "win_bits", "summary": sum, "severity": sev, "ts": ts,
		"detail": map[string]any{
			"source": "bits", "event_id": eid, "channel": chanName,
			"job_name": job, "remote_url": url, "local_path": local, "owner": owner,
			"payload_path": firstNonEmpty(local, url), "matched": firstNonEmpty(url, local, job),
		},
	}
}

func winevtSMBEvent(eid int, ts, chanName string, data map[string]string) map[string]any {
	share := winevtPick(data, "ShareName", "shareName", "ObjectName", "ServerName", "serverName")
	user := winevtPick(data, "SubjectUserName", "UserName", "AccountName", "user")
	status := winevtPick(data, "Status", "status", "ErrorCode")
	path := winevtPick(data, "ObjectName", "ShareName", "Path", "FileName")
	sum := "SMB: " + firstNonEmpty(share, path, "access")
	sev := "medium"
	if eid == 31001 || eid == 31010 {
		sev = "info"
	}
	return map[string]any{
		"etype": "win_smb", "summary": sum, "severity": sev, "ts": ts,
		"detail": map[string]any{
			"source": "smbclient", "event_id": eid, "channel": chanName,
			"share": share, "path": path, "user": user, "status": status,
			"matched": firstNonEmpty(share, path), "direction": "client",
		},
	}
}

// winevtSMBServerEvent：本机作为 SMB 服务端被访问（横向移动落点常见）。
func winevtSMBServerEvent(eid int, ts, chanName string, data map[string]string) map[string]any {
	share := winevtPick(data, "ShareName", "shareName", "ObjectName")
	user := winevtPick(data, "SubjectUserName", "AccountName", "IpAddress")
	ip := winevtPick(data, "IpAddress", "SourceAddress", "ClientAddress")
	path := winevtPick(data, "RelativeTargetName", "ObjectName", "ShareName", "Path")
	access := winevtPick(data, "AccessMask", "AccessList", "Accesses")
	sum := "SMB共享访问: " + firstNonEmpty(share, path, "share")
	if ip != "" && ip != "-" {
		sum += " ← " + ip
	}
	sev := "medium"
	lowShare := strings.ToLower(share)
	if strings.Contains(lowShare, "admin$") || strings.Contains(lowShare, "c$") || strings.Contains(lowShare, "ipc$") {
		sev = "high"
		sum = "SMB高危共享: " + firstNonEmpty(share, path)
		if ip != "" && ip != "-" {
			sum += " ← " + ip
		}
	}
	if eid == 5145 {
		sev = "high"
	}
	return map[string]any{
		"etype": "win_smb", "summary": sum, "severity": sev, "ts": ts,
		"detail": map[string]any{
			"source": "smbserver", "event_id": eid, "channel": chanName,
			"share": share, "path": path, "user": user, "remote_ip": ip,
			"access": access, "matched": firstNonEmpty(share, path, ip),
			"direction": "server",
		},
	}
}

func enrichWinTaskOpsFromCache(ev map[string]any, taskName string) {
	if ev == nil {
		return
	}
	key := taskKeyFromTaskName(taskName)
	p, ok := lookupTaskDefinition(key)
	if !ok || len(p.Actions) == 0 {
		return
	}
	d, _ := ev["detail"].(map[string]any)
	if d == nil {
		d = map[string]any{}
		ev["detail"] = d
	}
	defPath := scheduledTaskFilePath(taskName)
	applyScheduledTaskFields(d, defPath, p, filepath.Base(defPath))
	if exe := firstTaskExecute(p); exe != "" {
		ev["summary"] = "任务计划: " + filepath.Base(exe) + " · " + strings.TrimSpace(taskName)
		if taskSuspiciousExecute(exe) {
			ev["severity"] = "high"
		}
	}
}

var (
	winevtDWM   = regexp.MustCompile(`(?i)^(DWM-|UMFD-)`)
	winevtSvcRe = regexp.MustCompile(`(?i)^(BITS|wuauserv|UsoSvc|DoSvc|TrustedInstaller|WaaSMedicSvc|wlidsvc|DiagTrack|WpnService|SystemEventsBroker|WinDefend|WdNisSvc|Sense|edgeupdate|edgeupdatem|gupdate|gupdatem|gpsvc|Schedule|WSearch|SysMain|ClickToRunSvc|MapsBroker|lfsvc|InstallService|AppXSvc|ClipSVC|StorSvc|TokenBroker|CDPSvc|CDPUserSvc.*|OneSyncSvc.*|PimIndexMaintenanceSvc.*|UnistoreSvc.*|UserDataSvc.*|WpnUserService.*)$`)
	winevtWinRe = regexp.MustCompile(`(?i)\\windows\\(system32|syswow64|winsxs)\\`)
	winevtPSRe  = regexp.MustCompile(`(?i)(-enc|frombase64string|iex\s|invoke-expression|downloadstring|system\.reflection\.assembly)`)
	winevtPriv  = regexp.MustCompile(`(?i)SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege`)
	winevtASEP  = regexp.MustCompile(`(?i)\\(CurrentVersion\\Run|RunOnce|Winlogon|Image File Execution Options|AppInit_DLLs|Services\\[^\\]+\\(ImagePath|ServiceDll)|Windows Defender\\Exclusions|Policies\\Microsoft\\Windows Defender|Lsa\\|WDigest)`)
)

func winevtUserNoise(user string) bool {
	return winevtDWM.MatchString(user) || strings.HasSuffix(user, "$")
}

func winevtPathEnds(path string, suffixes ...string) bool {
	low := strings.ToLower(path)
	for _, s := range suffixes {
		if strings.HasSuffix(low, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func winevtWinDirPath(p string) bool { return winevtWinRe.MatchString(p) }

func winevtTaskMicrosoft(tn string) bool {
	return strings.HasPrefix(strings.ToLower(tn), `\microsoft\`)
}

func winevtPrivInteresting(priv string) bool { return winevtPriv.MatchString(priv) }

func winevtServiceNoise(short string) bool { return winevtSvcRe.MatchString(short) }

func winevtSysmonWmiParts(eid int, data map[string]string) (etype, sum string, detail map[string]any) {
	name := data["Name"]
	if name == "" {
		name = data["Consumer"]
	}
	if name == "" {
		name = data["Filter"]
	}
	etype, sum = "wmi_persist_add", "WMI 永久订阅(Sysmon): "+name
	switch eid {
	case 19:
		sum = "WMI Filter(Sysmon): " + name
	case 20:
		sum = "WMI Consumer(Sysmon): " + name
	case 21:
		sum = "WMI Binding(Sysmon): " + name
	}
	op := strings.ToLower(data["Operation"])
	if strings.Contains(op, "delet") {
		etype = "wmi_persist_delete"
	} else if strings.Contains(op, "modif") {
		etype = "wmi_persist_modify"
	}
	detail = map[string]any{
		"source": "sysmon", "event_id": eid, "name": name, "operation": data["Operation"],
		"user": data["User"], "type": data["Type"], "destination": data["Destination"],
		"consumer": data["Consumer"], "filter": data["Filter"], "topic": "startup",
	}
	return etype, sum, detail
}

// winevtPersistTopic：注册表 ASEP → 调查页主题（启动项 / 服务）。
func winevtPersistTopic(regPath string) string {
	low := strings.ToLower(regPath)
	if strings.Contains(low, `\services\`) && (strings.Contains(low, `\imagepath`) || strings.Contains(low, `\servicedll`) || strings.HasSuffix(low, `\start`) || strings.Contains(low, `\servicemanifest`)) {
		return "service"
	}
	if strings.Contains(low, `currentversion\run`) || strings.Contains(low, `\runonce`) ||
		strings.Contains(low, `\winlogon`) || strings.Contains(low, `shell folders\startup`) ||
		strings.Contains(low, `\appinit_dlls`) || strings.Contains(low, `image file execution options`) {
		return "startup"
	}
	return ""
}

// winevtFileTopic：文件落地路径 → 调查页主题。
func winevtFileTopic(path string) string {
	low := strings.ToLower(path)
	if strings.Contains(low, `\startup\`) || strings.Contains(low, `\start menu\`) {
		return "startup"
	}
	if strings.Contains(low, `\windows\system32\tasks`) || strings.Contains(low, `\windows\syswow64\tasks`) ||
		strings.Contains(low, `\windows\tasks\`) {
		return "task"
	}
	return "file_create"
}

func winevtSnip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func winevtSuspiciousPS(s string) bool { return winevtPSRe.MatchString(s) }

func winevtSysmonSrcNoise(src string) bool {
	return winevtPathEnds(src, `\MsMpEng.exe`, `\NisSrv.exe`, `\csrss.exe`, `\wininit.exe`, `\services.exe`, `\lsass.exe`, `\svchost.exe`, `\smss.exe`, `\dwm.exe`, `\audiodg.exe`, `\MpDefenderCoreService.exe`, `\SecurityHealthService.exe`)
}

func winevtSysmonAccessNoise(src string) bool {
	return winevtPathEnds(src, `\MsMpEng.exe`, `\NisSrv.exe`, `\csrss.exe`, `\wininit.exe`, `\services.exe`, `\lsass.exe`, `\svchost.exe`, `\taskmgr.exe`, `\procexp.exe`, `\procexp64.exe`, `\vmtoolsd.exe`)
}

func winevtBrowserPair(src, tgt string) bool {
	browsers := []string{`\chrome.exe`, `\msedge.exe`, `\firefox.exe`, `\opera.exe`, `\brave.exe`}
	for _, b := range browsers {
		if strings.HasSuffix(strings.ToLower(src), b) && strings.HasSuffix(strings.ToLower(tgt), b) {
			return true
		}
	}
	return false
}

func winevtRegASEP(to string) bool { return winevtASEP.MatchString(to) }

func winevtParseHex64(s string) (uint64, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 64)
	return v, err == nil
}

func winevtInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		v, _ := strconv.ParseInt(s[2:], 16, 64)
		return int(v)
	}
	v, _ := strconv.Atoi(s)
	return v
}

// winevtEnrichScriptBlock 4104 绑定进程实体，便于 PTM/EVM 串链。
func winevtEnrichScriptBlock(det map[string]any, ts string) {
	if det == nil {
		return
	}
	at := parseLocalTS(ts)
	path := strings.TrimSpace(asString(det["path"]))
	if path != "" {
		det["process_path"] = path
		det["image"] = path
		det["process_name"] = filepath.Base(path)
	}
	// HostApplicationId 常为 PowerShell 实例 GUID；用 path + 时间窗匹配实体
	if ent := procEntities.bestRecentUserProcess(8 * time.Second); ent != nil {
		if path == "" || strings.EqualFold(ent.Image, path) || strings.Contains(strings.ToLower(path), strings.ToLower(ent.Name)) {
			det["entity_id"] = ent.ID
			det["pid"] = ent.PID
			det["ppid"] = ent.PPID
			if ent.CommandLine != "" {
				det["command_line"] = ent.CommandLine
			}
			det["correlation_id"] = "ps4104|" + ent.ID
			return
		}
	}
	if path != "" {
		procEntities.annotate(det, at)
		if eid := asString(det["entity_id"]); eid != "" {
			det["correlation_id"] = "ps4104|" + eid
		}
	}
}
