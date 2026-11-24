# -*- coding: utf-8 -*-
"""Promotion of high-confidence sensor telemetry into platform alerts."""
from __future__ import annotations

from typing import Any, Dict, List

from . import agent_protocol
from .agent_alert_detail import _detail_looks_registry, alert_module_for

_ALERT_ETYPES = {
    "remote_thread_kernel", "protect_block_kernel", "remote_thread",
    "image_load_etw", "image_load_kernel", "image_load_sysmon", "driver_load_kernel",
    "persist_add", "persist_modify", "registry_set", "registry_delete", "registry_write",
    "fim_add", "fim_modify", "fim_rename",
    "dns_nx_burst", "win_audit_clear",
    "win_account_create", "win_group_add", "win_service_install", "win_task_create",
    "win_service_config",     "win_ps_scriptblock", "process_access", "credential_access",
    "process_tampering", "file_stream_create",
    "file_create", "priv_escalation", "memory_scan_hit",
    "device_mount", "api_amsi", "amsi_hit", "api_call", "api_hit",
    "evm_hit", "ptm_hit", "memory_rule", "memory_yara",
}
_SCRIPT_DROP_EXTS = {".ps1", ".vbs", ".js", ".jse", ".hta", ".bat", ".cmd", ".scr", ".wsf"}
_SIGNED_BAD = {"notsigned", "hashmismatch", "nottrusted", "incompatible"}
_SKIP_PROMOTE_ETYPES = {"sensor_status", "etw_status", "winevent_status"}
# 外联 / DNS：时间线照常入库，威胁事件只由 IOC 命中产出
_IOC_ONLY_ETYPES = {
    "network_connect", "network_connect_etw", "http_request_etw", "beacon_like",
    "dns_query", "dns_summary",
}

# Windows 更新常改启动类型的系统服务（7040），不当作威胁
_WIN_SVC_NOISE = {
    "background intelligent transfer service", "bits",
    "windows update", "wuauserv",
    "update orchestrator service", "usosvc",
    "delivery optimization", "dosvc",
    "windows modules installer", "trustedinstaller",
    "waasmedicSvc", "waasmedicsvc",
    "microsoft account sign-in assistant", "wlidsvc",
    "system events broker", "systemeventsbroker",
    "connected user experiences and telemetry", "diagtrack",
    "windows push notifications system service", "wpnservice",
}


def _is_noisy_service_config(detail: Dict[str, Any], summary: str = "") -> bool:
    name = str(detail.get("name") or detail.get("service") or "").strip().lower()
    blob = f"{name} {summary}".lower()
    if not blob.strip():
        return False
    for n in _WIN_SVC_NOISE:
        if n in blob:
            return True
    return False


def _ptm_detail_matched_hint(detail: Dict[str, Any]) -> str:
    if not isinstance(detail, dict):
        return ""
    if detail.get("matched"):
        return str(detail["matched"])[:500]
    chain = detail.get("chain")
    if not isinstance(chain, list):
        tr = detail.get("trigger")
        if isinstance(tr, dict):
            chain = [tr]
        else:
            return ""
    parts: List[str] = []
    for i, c in enumerate(chain[:6]):
        if not isinstance(c, dict):
            continue
        s = str(c.get("summary") or c.get("etype") or "").strip()
        rk = str(c.get("reg_key") or c.get("key") or c.get("path") or "").strip()
        if rk and rk not in s:
            s = f"{rk} {s}".strip()
        if s:
            parts.append(f"{i + 1}) {s}")
    return " | ".join(parts)[:500]


def _sensor_detail_matched_hint(detail: Dict[str, Any]) -> str:
    if not isinstance(detail, dict):
        return ""
    parts = [
        str(detail.get("source_summary") or "").strip(),
        str(detail.get("remote") or detail.get("remote_ip") or "").strip(),
        str(detail.get("domain") or "").strip(),
        str(detail.get("reg_key") or detail.get("key") or detail.get("path") or "").strip(),
        str(detail.get("command_line") or "").strip(),
    ]
    return " · ".join(p for p in parts if p)[:500]


def _promote_sensor_alerts(agent_id: str, host: str, events: List[Any]) -> int:
    n = 0
    for ev in events[:200]:
        if not isinstance(ev, dict):
            continue
        et = str(ev.get("etype") or "")
        sev = str(ev.get("severity") or "").lower()
        if et in _SKIP_PROMOTE_ETYPES or et in _IOC_ONLY_ETYPES:
            continue
        # 只晋升白名单 etype，且必须 medium+（不再把 info 抬成 medium）
        if et not in _ALERT_ETYPES:
            continue
        if sev not in ("medium", "high", "critical"):
            continue
        use_sev = sev
        detail_obj = {"etype": et}
        if isinstance(ev.get("detail"), dict):
            detail_obj.update(ev.get("detail") or {})
        title = str(ev.get("summary") or et)[:200]
        mod = alert_module_for(et)
        if et in ("evm_hit", "ptm_hit", "memory_rule", "memory_yara"):
            rt = str(detail_obj.get("rule_title") or detail_obj.get("title") or "").strip()
            if rt:
                prefix = "EVM" if et == "evm_hit" else "PTM" if et == "ptm_hit" else "内存规则"
                title = f"{prefix}：{rt}"[:200]
            detail_obj.setdefault("rule_title", rt or detail_obj.get("title"))
            if et == "evm_hit" and not detail_obj.get("matched"):
                detail_obj["matched"] = _sensor_detail_matched_hint(detail_obj)
            if et == "ptm_hit" and not detail_obj.get("matched"):
                detail_obj["matched"] = _ptm_detail_matched_hint(detail_obj)
            mod = "script" if et in ("evm_hit", "memory_rule", "memory_yara") else "process"
            if et == "ptm_hit" and _detail_looks_registry(detail_obj):
                mod = "registry"
            if et == "evm_hit" and str(detail_obj.get("source_etype") or "").startswith("network"):
                mod = "network"
        if ev.get("ts") and not detail_obj.get("event_ts"):
            detail_obj["event_ts"] = ev.get("ts")
        signed = str(detail_obj.get("signed") or "").strip().lower()
        # FIM：有签名字段时只认明确未签名/损坏；Valid 与未知均不晋升（hosts 等无签名字段的照常）
        if et.startswith("fim_") and signed and signed not in _SIGNED_BAD:
            continue
        # DLL / 内核模块：必须明确未签名
        if et in ("image_load_etw", "image_load_kernel", "image_load_sysmon") and signed not in _SIGNED_BAD:
            continue
        # 文件落地：仅投放区脚本类
        if et == "file_create":
            ext = str(detail_obj.get("ext") or "").lower()
            if ext not in _SCRIPT_DROP_EXTS:
                continue
        # BITS / Windows Update 等系统服务启动类型变更不晋升
        if et == "win_service_config" and _is_noisy_service_config(detail_obj, str(ev.get("summary") or "")):
            continue
        # 脚本块仅可疑特征（Agent 已标 high）
        if et == "win_ps_scriptblock" and sev != "high":
            continue
        # 规则管理里关闭的传感器不再晋升告警
        try:
            from . import agent_rules as _ar
            if not _ar.sensor_event_allowed(et, str(ev.get("summary") or ""), detail_obj):
                continue
        except Exception:
            pass
        try:
            from . import event_detail_enrich as _ede
            with agent_protocol._lock:
                conn = agent_protocol._connect()
                try:
                    detail_obj, _ = _ede.enrich_detail_from_timeline(
                        conn,
                        agent_id=agent_id,
                        title=title,
                        detail=detail_obj,
                        created_at=str(ev.get("ts") or ""),
                    )
                finally:
                    conn.close()
        except Exception:
            pass
        r = agent_protocol.report_event({
            "agent_id": agent_id,
            "hostname": host,
            "module": mod,
            "severity": use_sev,
            "title": title,
            "detail": detail_obj,
        })
        if r.get("ok") and not r.get("deduped") and not r.get("suppressed"):
            n += 1
        if n >= 120:
            break
    return n


