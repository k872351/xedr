# -*- coding: utf-8 -*-
"""Build compact, normalized alert details from timeline rule matches."""
from __future__ import annotations

from typing import Any, Dict, Optional

_TIMELINE_HIT_COPY_KEYS = (
    "command_line", "command", "name", "process_name", "path", "image", "parent_name",
    "pid", "ppid", "user", "key", "reg_key", "hive", "value", "value_name", "old_value",
    "label", "category", "change", "watch", "remote", "remote_ip", "domain", "local",
    "proto", "query", "entity_id", "parent_entity_id", "signed", "signer", "sha256",
    "ext", "size", "task_name", "task_execute", "payload_path", "script_block", "payload",
)


def _timeline_rule_hit_detail(
    ev: Dict[str, Any],
    *,
    rule_id: Any,
    rule_title: str,
    rule_source: str,
    building_block: bool = False,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """把时间线事件的进程/注册表/网络等关键字段带进 EVM/Elastic 告警 detail。"""
    det = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    et = str(ev.get("etype") or "")
    summary = str(ev.get("summary") or "")
    out: Dict[str, Any] = {
        "rule_id": rule_id,
        "rule_title": rule_title,
        "rule_source": rule_source,
        "etype": et,
        "summary": summary,
        "building_block": bool(building_block),
    }
    for k in _TIMELINE_HIT_COPY_KEYS:
        v = det.get(k)
        if v not in (None, "", [], {}):
            out[k] = v
    if not out.get("path") and det.get("image"):
        out["path"] = det.get("image")
    if not out.get("reg_key") and det.get("key"):
        out["reg_key"] = det.get("key")
    if not out.get("key") and out.get("reg_key"):
        # 值名挂在 key 末段时保留完整键；否则用 reg_key
        out["key"] = out.get("reg_key")
    cmd = str(out.get("command_line") or out.get("command") or "").strip()
    matched = str(det.get("matched") or "").strip()
    if not matched:
        if cmd:
            matched = cmd[:400]
        else:
            rk = str(out.get("key") or out.get("reg_key") or "")
            vn = str(out.get("value_name") or "")
            val = str(out.get("value") or "")
            if rk and (vn or val):
                matched = f"{rk} → {vn}={val}"[:500] if (vn or val) else rk[:500]
            elif rk:
                matched = rk[:500]
            elif summary:
                matched = summary[:500]
    out["matched"] = matched
    if isinstance(extra, dict):
        for k, v in extra.items():
            if v not in (None, "", [], {}):
                out[k] = v
    return out

_MODULE_PREFIXES = (
    (("registry_", "persist_"), "registry"),
    (("image_load", "driver_load"), "image"),
    (("remote_thread", "process_access", "protect_block", "credential_access", "process_tampering"), "inject"),
    (("process_",), "process"),
    (("file_", "fim_", "pipe_"), "file"),
    (("network_",), "network"),
    (("dns_",), "dns"),
    (("device_",), "file"),
    (("win_logon", "win_explicit_logon", "win_account", "win_password", "win_group", "win_special_priv"), "account"),
    (("win_service",), "service"),
    (("win_task",), "task"),
    (("win_ps_",), "script"),
    (("win_audit",), "audit"),
)


def alert_module_for(etype: str) -> str:
    """按事件语义归类告警模块（来源 etw/kernel/sysmon 保留在 detail.source）。"""
    et = str(etype or "").lower()
    for prefixes, mod in _MODULE_PREFIXES:
        if et.startswith(prefixes):
            return mod
    return "timeline"


def _timeline_rule_hit_module(ev: Dict[str, Any], detail: Dict[str, Any]) -> str:
    et = str((ev or {}).get("etype") or (detail or {}).get("etype") or "").lower()
    if et.startswith("persist") or et.startswith("registry") or _detail_looks_registry(detail or {}):
        return "registry"
    cmd = str((detail or {}).get("command_line") or (detail or {}).get("command") or "")
    if cmd and re.search(
        r"powershell|pwsh|wscript|cscript|mshta|scriptblock|\.ps1|\.vbs",
        cmd,
        re.I,
    ):
        return "script"
    if et.startswith("network") or et.startswith("dns"):
        return "network"
    if et.startswith("process"):
        return "process"
    return alert_module_for(et)


def _detail_looks_registry(detail: Dict[str, Any]) -> bool:
    if not isinstance(detail, dict):
        return False
    if str(detail.get("source_etype") or "").startswith("registry"):
        return True
    chain = detail.get("chain")
    if isinstance(chain, list):
        for c in chain:
            if isinstance(c, dict) and str(c.get("etype") or "").startswith("registry"):
                return True
            if isinstance(c, dict) and (c.get("reg_key") or c.get("key")):
                return True
    return bool(detail.get("reg_key") or detail.get("key"))


