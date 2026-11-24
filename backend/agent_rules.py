# -*- coding: utf-8 -*-
"""Agent 专用实时规则（与主平台规则库分离，降低误报）。

文件：rules/agent-live-rules.json
管理台可增删改启用；快照上报时仅用本库匹配。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config
from .rule_metadata import is_elastic_rule, _enrich_rule_item

RULES_FILE = "agent-live-rules.json"
_LOCK = threading.RLock()
_CACHE: Dict[str, Any] = {"mtime": 0.0, "doc": None}

_MODULES = (
    "process", "service", "task", "startup", "network", "sysinfo", "file", "user",
    "software", "hotfix", "listen", "timeline",
)
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
# 仅用于时间线展示/过滤，不应进入端上 EVM（否则会「每条进程创建都 evm_hit」）
_SENSOR_EVM_SKIP_IDS = frozenset({
    "sensor-etw-proc",
    "sensor-etw-proc-exit",
    "sensor-dns",
    "sensor-dns-summary",
    "sensor-win-ps-script",
    "sensor-win-ps-module",
})
_FIELD_DEFAULT = {
    "process": ["name", "path", "command_line", "user"],
    "service": ["name", "display_name", "path", "account"],
    "task": ["task_name", "command", "path", "execute"],
    "startup": ["name", "command", "path", "location"],
    "network": ["local", "remote", "state", "proto"],
    "sysinfo": ["hostname", "caption"],
    "file": ["name", "path", "directory", "ext"],
    "user": ["name", "session", "state"],
}


def _path() -> Path:
    return Path(config.RULES_DIR) / RULES_FILE


def _merge_evm_rules_for_ui(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把 elastic_evm_import 中仅时间线执行的规则并入控制台列表（与快照规则区分）。"""
    try:
        from . import elastic_detection_import as _edi
    except Exception:
        return rules
    by_id = {str(r.get("id") or ""): r for r in rules if str(r.get("id") or "")}
    for er in _edi.load_evm_import_rules(enabled_only=False):
        if not isinstance(er, dict):
            continue
        eid = str(er.get("id") or "").strip()
        if not eid or eid in by_id:
            continue
        base = eid.replace(".evm", "").replace(".fim", "")
        snap = by_id.get(base)
        by_id[eid] = {
            "id": eid,
            "title": str(er.get("title") or (snap.get("title") if snap else "") or eid)[:120],
            "severity": str(er.get("severity") or (snap or {}).get("severity") or "medium"),
            "source": "elastic",
            "rule_channel": "evm",
            "platform": str(er.get("platform") or er.get("os") or (snap or {}).get("platform") or (snap or {}).get("os") or ""),
            "etype": str(er.get("etype") or ""),
            "patterns": list(er.get("patterns") or [])[:24],
            "match": str(er.get("match") or "substring"),
            "enabled": er.get("enabled") is not False,
            "building_block": bool(er.get("building_block")),
            "elastic_rule_id": str(er.get("elastic_rule_id") or (snap or {}).get("elastic_rule_id") or ""),
            "note": "Elastic EVM（时间线子串近似，非完整 EQL/KQL）",
            "modules": [],
            "builtin": False,
        }
    return list(by_id.values())




def _linux_snapshot_rules() -> List[Dict[str, Any]]:
    """Conservative Linux process rules for procfs snapshots on minimal hosts."""
    return [
        {
            "id": "agent-linux-temp-exec",
            "title": "Linux 可写临时目录执行程序",
            "severity": "medium",
            "modules": ["process"],
            "fields": ["path", "command_line"],
            "patterns": [r"/(tmp|var/tmp|dev/shm)/[^\s]+"],
            "match": "regex",
            "enabled": True,
            "note": "监控从 /tmp、/var/tmp、/dev/shm 执行的进程；请结合终端用途确认告警。",
        },
        {
            "id": "agent-linux-download-pipe-shell",
            "title": "Linux 下载内容直接交由 Shell 执行",
            "severity": "high",
            "modules": ["process"],
            "fields": ["command_line"],
            "patterns": [r"\b(curl|wget)\b[^\n|;]{0,240}\|\s*(sudo\s+)?(ba)?sh\b"],
            "match": "regex",
            "enabled": True,
            "note": "匹配常见的 curl/wget 管道执行形式。",
        },
        {
            "id": "agent-linux-reverse-shell",
            "title": "Linux 反向 Shell 命令特征",
            "severity": "high",
            "modules": ["process"],
            "fields": ["command_line"],
            "patterns": [r"/dev/tcp/|\bnc\b[^\n;]{0,180}\s-e\s*/bin/(ba)?sh|python[0-9.]*\s+-c[^\n]{0,240}socket"],
            "match": "regex",
            "enabled": True,
            "note": "检测常见的 /dev/tcp、netcat 与 Python socket Shell 特征。",
        },
        {
            "id": "agent-linux-miner-process",
            "title": "已知挖矿程序进程名",
            "severity": "high",
            "modules": ["process"],
            "fields": ["name", "path", "command_line"],
            "patterns": ["xmrig", "kdevtmpfsi", "kinsing", "watchbog"],
            "match": "substring",
            "enabled": True,
            "note": "基于进程名及路径的静态特征，误报时可在规则页禁用或调整。",
        },
        {
            "id": "agent-linux-persistence-shell",
            "title": "Linux 持久化任务调用临时载荷或反向 Shell",
            "severity": "high",
            "modules": ["task", "startup", "service"],
            "fields": ["command", "path", "execute"],
            "patterns": [r"(curl|wget)[^\n|;]{0,240}\|\s*(sudo\s+)?(ba)?sh|/dev/tcp/|/(tmp|var/tmp|dev/shm)/[^\s]+"],
            "match": "regex",
            "enabled": True,
            "note": "针对 cron、systemd unit 和启动项中的高风险命令特征。",
        },
    ]




def _default_doc() -> Dict[str, Any]:
    return {
        "meta": {
            "name": "Agent 实时规则",
            "version": "1.1",
            "description": "快照规则 + 传感器内置检出（可开关），与主平台规则库独立",
        },
        "rules": _default_rules() + _linux_snapshot_rules(),
        "sensor_overrides": {},
    }


def ensure_rules_file() -> Path:
    p = _path()
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(p, _default_doc())
    return p


def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def load_doc(*, force: bool = False) -> Dict[str, Any]:
    p = ensure_rules_file()
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return _default_doc()
    with _LOCK:
        if not force and _CACHE["doc"] is not None and abs(mtime - float(_CACHE["mtime"])) < 0.01:
            return _CACHE["doc"]  # type: ignore
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                doc = _default_doc()
            if not isinstance(doc.get("rules"), list):
                doc["rules"] = []
        except Exception:
            doc = _default_doc()
        meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
        if not meta.get("linux_snapshot_rules_v2"):
            existing_ids = {str(r.get("id") or "") for r in doc["rules"] if isinstance(r, dict)}
            doc["rules"].extend(r for r in _linux_snapshot_rules() if r["id"] not in existing_ids)
            meta["linux_snapshot_rules_v2"] = True
            doc["meta"] = meta
            _atomic_write(p, doc)
            try:
                mtime = p.stat().st_mtime
            except OSError:
                pass
        _CACHE["mtime"] = mtime
        _CACHE["doc"] = doc
        return doc


def save_doc(doc: Dict[str, Any]) -> None:
    with _LOCK:
        _atomic_write(_path(), doc)
        _CACHE["doc"] = doc
        try:
            _CACHE["mtime"] = _path().stat().st_mtime
        except OSError:
            _CACHE["mtime"] = time.time()
    try:
        from . import agent_protocol
        agent_protocol.bump_live("rules")
    except Exception:
        pass
    try:
        from . import agent_sync
        agent_sync.bump_sync("rules")
    except Exception:
        pass


def _merged_sensor_rules(doc: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    doc = doc if isinstance(doc, dict) else load_doc()
    overrides = doc.get("sensor_overrides") if isinstance(doc.get("sensor_overrides"), dict) else {}
    out: List[Dict[str, Any]] = []
    for base in _sensor_builtin_rules():
        r = dict(base)
        ov = overrides.get(str(r["id"])) if isinstance(overrides.get(str(r["id"])), dict) else {}
        if not isinstance(ov, dict):
            ov = {}
        if "enabled" in ov:
            r["enabled"] = bool(ov.get("enabled"))
        sev = str(ov.get("severity") or "").strip().lower()
        if sev in _SEVERITIES:
            r["severity"] = sev
        if "note" in ov and ov.get("note") is not None:
            r["note"] = str(ov.get("note") or "")[:300]
        if "title" in ov and str(ov.get("title") or "").strip():
            r["title"] = str(ov.get("title")).strip()[:120]
        if "etype" in ov and str(ov.get("etype") or "").strip():
            r["etype"] = str(ov.get("etype")).strip()[:64]
        if "summary_contains" in ov:
            r["summary_contains"] = str(ov.get("summary_contains") or "")[:200]
        if "match" in ov:
            m = str(ov.get("match") or "").strip().lower()
            if m in ("substring", "regex", "exact"):
                r["match"] = m
        if "patterns" in ov:
            pats = ov.get("patterns")
            if isinstance(pats, str):
                pats = [x.strip() for x in pats.replace(",", "\n").splitlines() if x.strip()]
            if isinstance(pats, list):
                r["patterns"] = [str(p) for p in pats if str(p).strip()][:20]
                # 人工改的特征同步为摘要关键字（取第一条非空）
                if r["patterns"] and "summary_contains" not in ov:
                    r["summary_contains"] = str(r["patterns"][0])[:200]
        for key in ("fields", "file_exts", "path_prefixes"):
            if key in ov and isinstance(ov.get(key), list):
                r[key] = [str(x) for x in ov.get(key) if str(x).strip()]
        if "signed_filter" in ov:
            signed_filter = str(ov.get("signed_filter") or "").strip().lower()
            if signed_filter in ("", "any", "unsigned", "signed"):
                r["signed_filter"] = signed_filter
        # 列表展示用：patterns 与 summary_contains 对齐
        sc = str(r.get("summary_contains") or "").strip()
        if sc and not r.get("patterns"):
            r["patterns"] = [sc]
        r["customized"] = bool(ov)
        out.append(r)
    return out


def list_rules(*, enabled_only: bool = False, include_sensor: bool = True) -> List[Dict[str, Any]]:
    doc = load_doc()
    custom = []
    for r in (doc.get("rules") or []):
        if not isinstance(r, dict):
            continue
        item = dict(r)
        item.setdefault("source", "custom")
        item.setdefault("builtin", False)
        # 防止旧文件里误塞了 sensor- 前缀的自定义规则覆盖内置
        if str(item.get("id") or "").startswith("sensor-"):
            continue
        custom.append(item)
    rules = (_merged_sensor_rules(doc) if include_sensor else []) + custom
    if enabled_only:
        rules = [r for r in rules if r.get("enabled", True)]
    return [_enrich_rule_item(dict(r)) for r in rules]


def get_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    rid = str(rule_id or "").strip()
    for r in list_rules():
        if str(r.get("id") or "") == rid:
            return dict(r)
    return None


def is_sensor_rule_id(rule_id: str) -> bool:
    return str(rule_id or "").startswith("sensor-")


def _sensor_text_match(hay: str, needle: str, how: str) -> bool:
    if not needle:
        return True
    how = (how or "substring").lower()
    if how == "exact":
        return hay == needle.lower()
    if how == "regex":
        try:
            return bool(re.search(needle, hay, re.I))
        except re.error:
            return needle.lower() in hay
    return needle.lower() in hay


def sensor_event_allowed(etype: str, summary: str, detail: Optional[Dict[str, Any]] = None) -> bool:
    """传感器事件是否允许入库。

    内置传感器与快照规则共用字段、扩展名、签名、路径和匹配方式。
    etype 仍是传感器的稳定入口，规则 ID 不允许被修改或删除。

    注意：若摘要/etype 已命中某条传感器规则，但被 signed_filter 等条件挡下，
    必须返回 False（禁止再「无匹配 → 默认放行」，否则 Valid 签名 FIM 会继续告警）。
    """
    et = str(etype or "").strip().lower()
    detail = detail if isinstance(detail, dict) else {}
    if not et and not str(summary or "").strip():
        return True
    matched: List[Dict[str, Any]] = []
    gated_out = False  # 命中规则主体但被签名/路径等过滤器挡下
    for r in _merged_sensor_rules():
        want_et = str(r.get("etype") or "").strip().lower()
        how = str(r.get("match") or "substring")
        needles = [str(r.get("summary_contains") or "").strip()]
        for p in (r.get("patterns") or []):
            if str(p).strip():
                needles.append(str(p).strip())
        needles = [n for n in needles if n]
        if want_et and et != want_et and not et.startswith(want_et):
            continue

        fields = [str(x).strip() for x in (r.get("fields") or []) if str(x).strip()]
        values: List[str] = []
        for field in fields:
            if field == "etype":
                values.append(et)
            elif field == "summary":
                values.append(str(summary or ""))
            elif detail.get(field) not in (None, ""):
                value = detail.get(field)
                values.append(json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value))
        if not values:
            values = [str(summary or "")]
        haystacks = [value.lower() for value in values]
        if needles and not any(
            _sensor_text_match(hay, needle, how)
            for hay in haystacks
            for needle in needles
        ):
            continue

        path = str(detail.get("path") or detail.get("image") or detail.get("target_path") or "")
        prefixes = [str(x).strip().lower() for x in (r.get("path_prefixes") or []) if str(x).strip()]
        if prefixes and (not path or not any(path.lower().startswith(prefix) for prefix in prefixes)):
            gated_out = True
            continue
        exts = {str(x).strip().lstrip(".").lower() for x in (r.get("file_exts") or []) if str(x).strip()}
        if exts:
            ext = Path(path).suffix.lstrip(".").lower()
            if not ext or ext not in exts:
                gated_out = True
                continue
        signed_filter = str(r.get("signed_filter") or "").lower()
        signed = str(detail.get("signed") or "").strip().lower()
        if signed_filter == "signed" and signed != "valid":
            gated_out = True
            continue
        # 与快照规则 _signed_allowed 对齐：未知/空不算未签名
        if signed_filter == "unsigned" and (
            signed == "valid" or not signed or signed in ("unknown", "undefined", "unknownerror", "n/a", "-")
        ):
            gated_out = True
            continue
        if not want_et and not needles:
            continue
        matched.append(r)
    if not matched:
        return False if gated_out else True
    matched.sort(
        key=lambda x: max((len(str(p)) for p in ([x.get("summary_contains")] + list(x.get("patterns") or [])) if p), default=0),
        reverse=True,
    )
    return bool(matched[0].get("enabled", True))


def _normalize_rule(payload: Dict[str, Any], *, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    base = dict(existing or {})
    title = str(payload.get("title") or base.get("title") or "").strip()
    if not title:
        raise ValueError("标题不能为空")
    rid = str(payload.get("id") or base.get("id") or "").strip()
    if not rid:
        rid = "agent-" + uuid.uuid4().hex[:10]
    sev = str(payload.get("severity") or base.get("severity") or "medium").strip().lower()
    if sev not in _SEVERITIES:
        sev = "medium"
    mods = payload.get("modules") if "modules" in payload else base.get("modules")
    if isinstance(mods, str):
        mods = [x.strip() for x in re.split(r"[,;\s]+", mods) if x.strip()]
    if not isinstance(mods, list) or not mods:
        mods = ["process"]
    mods = [m for m in mods if m in _MODULES] or ["process"]
    fields = payload.get("fields") if "fields" in payload else base.get("fields")
    if isinstance(fields, str):
        fields = [x.strip() for x in re.split(r"[,;\s]+", fields) if x.strip()]
    if not isinstance(fields, list) or not fields:
        fields = list(_FIELD_DEFAULT.get(mods[0], ["path", "name"]))
    pats = payload.get("patterns") if "patterns" in payload else base.get("patterns")
    if isinstance(pats, str):
        # 一行一个，或逗号分隔
        lines = [x.strip() for x in pats.replace(",", "\n").splitlines() if x.strip()]
        pats = lines
    if not isinstance(pats, list):
        pats = []
    pats = [str(p) for p in pats if str(p).strip()]
    match = str(payload.get("match") or base.get("match") or "substring").strip().lower()
    if match not in ("substring", "regex", "exact"):
        match = "substring"
    enabled = payload.get("enabled") if "enabled" in payload else base.get("enabled", True)
    note = str(payload.get("note") if "note" in payload else base.get("note") or "")[:300]
    # 文件类型：exe / dll / ps1 …（空表示不限）
    exts = payload.get("file_exts") if "file_exts" in payload else base.get("file_exts")
    if isinstance(exts, str):
        exts = [x.strip().lstrip(".").lower() for x in re.split(r"[,;\s]+", exts) if x.strip()]
    if not isinstance(exts, list):
        exts = []
    exts = [str(x).strip().lstrip(".").lower() for x in exts if str(x).strip()][:24]
    # 签名过滤：""/any=不限；unsigned=未签名或签名异常；signed=仅有效签名
    signed_filter = str(
        payload.get("signed_filter") if "signed_filter" in payload else base.get("signed_filter") or ""
    ).strip().lower()
    if signed_filter not in ("", "any", "unsigned", "signed"):
        signed_filter = ""
    # 路径前缀：限制命中路径必须以这些开头（如 C:\ 、C:\Users\）
    path_prefixes = payload.get("path_prefixes") if "path_prefixes" in payload else base.get("path_prefixes")
    if isinstance(path_prefixes, str):
        path_prefixes = [x.strip() for x in re.split(r"[,;\n]+", path_prefixes) if x.strip()]
    if not isinstance(path_prefixes, list):
        path_prefixes = []
    path_prefixes = [str(x).strip() for x in path_prefixes if str(x).strip()][:12]
    # 异常文件规则：强制 file 模块 + category=abfile
    category = str(payload.get("category") if "category" in payload else base.get("category") or "").strip().lower()
    if payload.get("abfile") is True or base.get("abfile") is True:
        category = "abfile"
    if category == "abfile":
        mods = ["file"]
        if not fields or fields == list(_FIELD_DEFAULT.get("process", [])):
            fields = ["path", "name"]
    # 匹配特征：异常文件规则可用「路径前缀 / 扩展名 / 未签名」单独约束，特征可填 *
    if not pats:
        if signed_filter == "unsigned" or (category == "abfile" and (path_prefixes or exts)):
            pats = ["*"]  # 占位：匹配阶段按范围/签名约束放行
        else:
            raise ValueError(
                "至少填写一条匹配特征（异常文件规则也可只填路径前缀/扩展名，或签名条件设为「未签名」）"
            )
    out = {
        "id": rid[:64],
        "title": title[:120],
        "severity": sev,
        "modules": mods,
        "fields": fields[:12],
        "patterns": pats[:40],
        "file_exts": exts,
        "signed_filter": signed_filter,
        "path_prefixes": path_prefixes,
        "match": match,
        "enabled": bool(enabled),
        "note": note,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    if category:
        out["category"] = category[:32]
        if category == "abfile":
            out["abfile"] = True
    for key in ("etype", "summary_contains", "parent_name_contains", "building_block"):
        if key in payload:
            val = payload.get(key)
            if key == "building_block":
                out[key] = bool(val)
            elif val is not None and str(val).strip() != "":
                out[key] = str(val).strip()[:200] if key != "etype" else str(val).strip()[:64]
        elif existing and key in existing:
            out[key] = existing[key]
    return out


def create_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    rule = _normalize_rule(payload or {})
    if is_sensor_rule_id(rule["id"]):
        raise ValueError("不能创建 sensor- 前缀的内置传感器规则 ID")
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        if any(str(r.get("id")) == rule["id"] for r in rules):
            raise ValueError(f"规则 ID 已存在: {rule['id']}")
        rule["source"] = "custom"
        rule["builtin"] = False
        rules.append(rule)
        doc["rules"] = rules
        save_doc(doc)
    return {"ok": True, "item": rule}


def upsert_imported_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Elastic 等批量导入：按 ID 覆盖，保留 source/building_block 等元数据。"""
    payload = payload or {}
    rid = str(payload.get("id") or "").strip()
    if not rid:
        raise ValueError("缺少 id")
    if is_sensor_rule_id(rid):
        raise ValueError("不能写入 sensor- 前缀规则")
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        idx = next((i for i, r in enumerate(rules) if str(r.get("id")) == rid), -1)
        existing = rules[idx] if idx >= 0 else None
        rule = _normalize_rule(payload, existing=existing or {})
        for k in ("source", "building_block", "elastic_rule_id", "technique", "tactic"):
            if k in payload:
                rule[k] = payload[k]
        src = str(rule.get("source") or payload.get("source") or "custom").strip().lower()
        rule["source"] = src if src in ("custom", "elastic") else "custom"
        rule["builtin"] = False
        created = idx < 0
        if idx >= 0:
            rules[idx] = rule
        else:
            rules.append(rule)
        doc["rules"] = rules
        save_doc(doc)
    return {"ok": True, "created": created, "item": rule}


def _update_sensor_override(rule_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """内置传感器规则：允许人工改标题/级别/关键字/事件类型/备注/开关，落在 sensor_overrides。"""
    rid = str(rule_id or "").strip()
    base = next((r for r in _sensor_builtin_rules() if r["id"] == rid), None)
    if not base:
        raise ValueError("内置传感器规则不存在")
    payload = payload or {}
    # 重置为出厂默认
    if payload.get("reset_default"):
        with _LOCK:
            doc = load_doc(force=True)
            ov_all = doc.get("sensor_overrides") if isinstance(doc.get("sensor_overrides"), dict) else {}
            ov_all.pop(rid, None)
            doc["sensor_overrides"] = ov_all
            save_doc(doc)
        return {"ok": True, "item": get_rule(rid) or dict(base)}

    with _LOCK:
        doc = load_doc(force=True)
        ov_all = doc.get("sensor_overrides") if isinstance(doc.get("sensor_overrides"), dict) else {}
        cur = dict(ov_all.get(rid) or {}) if isinstance(ov_all.get(rid), dict) else {}
        if "enabled" in payload:
            cur["enabled"] = bool(payload.get("enabled"))
        if "severity" in payload:
            sev = str(payload.get("severity") or "").strip().lower()
            if sev in _SEVERITIES:
                cur["severity"] = sev
        if "note" in payload:
            cur["note"] = str(payload.get("note") or "")[:300]
        if "title" in payload and str(payload.get("title") or "").strip():
            cur["title"] = str(payload.get("title")).strip()[:120]
        if "etype" in payload and str(payload.get("etype") or "").strip():
            cur["etype"] = str(payload.get("etype")).strip()[:64]
        # 摘要关键字：直接字段，或取 patterns 第一行
        if "summary_contains" in payload:
            cur["summary_contains"] = str(payload.get("summary_contains") or "")[:200]
        if "patterns" in payload:
            pats = payload.get("patterns")
            if isinstance(pats, str):
                pats = [x.strip() for x in pats.replace(",", "\n").splitlines() if x.strip()]
            if isinstance(pats, list):
                pats = [str(p) for p in pats if str(p).strip()][:20]
                cur["patterns"] = pats
                if pats and "summary_contains" not in payload:
                    cur["summary_contains"] = pats[0][:200]
        if "match" in payload:
            m = str(payload.get("match") or "").strip().lower()
            if m in ("substring", "regex", "exact"):
                cur["match"] = m
        if "fields" in payload:
            fields = payload.get("fields")
            if isinstance(fields, str):
                fields = [x.strip() for x in re.split(r"[,;\s]+", fields) if x.strip()]
            if isinstance(fields, list):
                cur["fields"] = [str(x).strip() for x in fields if str(x).strip()][:12]
        if "file_exts" in payload:
            exts = payload.get("file_exts")
            if isinstance(exts, str):
                exts = [x.strip() for x in re.split(r"[,;\s]+", exts) if x.strip()]
            if isinstance(exts, list):
                cur["file_exts"] = [str(x).strip().lstrip(".").lower() for x in exts if str(x).strip()][:24]
        if "path_prefixes" in payload:
            prefixes = payload.get("path_prefixes")
            if isinstance(prefixes, str):
                prefixes = [x.strip() for x in re.split(r"[,;\n]+", prefixes) if x.strip()]
            if isinstance(prefixes, list):
                cur["path_prefixes"] = [str(x).strip() for x in prefixes if str(x).strip()][:12]
        if "signed_filter" in payload:
            signed_filter = str(payload.get("signed_filter") or "").strip().lower()
            if signed_filter in ("", "any", "unsigned", "signed"):
                cur["signed_filter"] = signed_filter
        ov_all[rid] = cur
        doc["sensor_overrides"] = ov_all
        save_doc(doc)
    item = get_rule(rid) or dict(base)
    return {"ok": True, "item": item}


def update_rule(rule_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    rid = str(rule_id or "").strip()
    if is_sensor_rule_id(rid):
        return _update_sensor_override(rid, payload or {})
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        idx = next((i for i, r in enumerate(rules) if str(r.get("id")) == rid), -1)
        if idx < 0:
            raise ValueError("规则不存在")
        merged = dict(payload or {})
        merged["id"] = rid  # 不允许改 ID
        existing = rules[idx]
        rule = _normalize_rule(merged, existing=existing)
        prev_src = str(existing.get("source") or "").lower()
        if is_elastic_rule(existing) or prev_src == "elastic":
            rule["source"] = "elastic"
        else:
            rule["source"] = "custom"
        rule["builtin"] = False
        for k in ("elastic_rule_id", "building_block", "technique", "tactic", "rule_channel"):
            if k in existing and k not in merged:
                rule[k] = existing[k]
        rules[idx] = rule
        doc["rules"] = rules
        save_doc(doc)
    return {"ok": True, "item": rule}


def delete_rule(rule_id: str) -> Dict[str, Any]:
    rid = str(rule_id or "").strip()
    if is_sensor_rule_id(rid):
        raise ValueError("内置传感器规则不能删除，可关闭启用开关")
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        new_rules = [r for r in rules if str(r.get("id")) != rid]
        if len(new_rules) == len(rules):
            raise ValueError("规则不存在")
        doc["rules"] = new_rules
        save_doc(doc)
    return {"ok": True}


def set_rule_enabled(rule_id: str, enabled: bool) -> Dict[str, Any]:
    rid = str(rule_id or "").strip()
    if is_sensor_rule_id(rid):
        return _update_sensor_override(rid, {"enabled": bool(enabled)})
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        idx = next((i for i, r in enumerate(rules) if str(r.get("id")) == rid), -1)
        if idx < 0:
            raise ValueError("规则不存在")
        rules[idx]["enabled"] = bool(enabled)
        rules[idx]["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        doc["rules"] = rules
        save_doc(doc)
        item = dict(rules[idx])
    return {"ok": True, "item": item}


def bulk_set_rules_enabled(
    enabled: bool,
    *,
    rule_ids: Optional[List[str]] = None,
    source: str = "",
    scope: str = "filtered",
) -> Dict[str, Any]:
    """批量开关。source: elastic|custom|''；scope=filtered 时仅 rule_ids。"""
    want_ids = {str(x).strip() for x in (rule_ids or []) if str(x).strip()}
    src = str(source or "").strip().lower()
    changed: List[str] = []
    skipped: List[str] = []
    for r in list_rules(include_sensor=True):
        rid = str(r.get("id") or "")
        if not rid:
            continue
        if want_ids and rid not in want_ids:
            continue
        if src == "elastic" and not is_elastic_rule(r):
            continue
        if src == "custom" and (r.get("builtin") or r.get("source") == "sensor"):
            continue
        if src == "sensor" and not (r.get("builtin") or r.get("source") == "sensor"):
            continue
        try:
            set_rule_enabled(rid, enabled)
            changed.append(rid)
        except ValueError:
            skipped.append(rid)
    if changed:
        try:
            from . import agent_protocol, agent_sync
            agent_protocol.bump_live("rules")
            agent_sync.bump_sync("rules")
        except Exception:
            pass
    return {"ok": True, "enabled": bool(enabled), "changed": len(changed), "ids": changed[:500], "skipped": skipped[:50]}


def _item_blob(item: Dict[str, Any], fields: List[str]) -> str:
    parts = []
    for f in fields or []:
        v = item.get(f)
        if v not in (None, ""):
            parts.append(str(v))
    if not parts:
        for f in ("name", "display_name", "path", "command", "command_line", "task_name", "local", "remote"):
            v = item.get(f)
            if v:
                parts.append(str(v))
    return "\n".join(parts)


def _item_ext(item: Dict[str, Any]) -> str:
    ext = str(item.get("ext") or "").strip().lstrip(".").lower()
    if ext:
        return ext
    for k in ("name", "path", "command_line", "command", "execute", "image"):
        v = str(item.get(k) or "")
        if not v:
            continue
        m = re.search(r"\.([A-Za-z0-9]{1,10})(?:[\"'\s\\]|$)", v)
        if m:
            return m.group(1).lower()
    return ""


def _ext_allowed(item: Dict[str, Any], file_exts: List[str]) -> bool:
    if not file_exts:
        return True
    return _item_ext(item) in {str(x).lower().lstrip(".") for x in file_exts}


_UNSIGNED_STATUSES = frozenset({
    "notsigned", "not signed", "unsigned",
    "hashmismatch", "hash mismatch",
    "nottrusted", "untrusted", "invalid", "invalid signature",
})


def _signed_allowed(item: Dict[str, Any], signed_filter: str) -> bool:
    sf = (signed_filter or "").strip().lower()
    if not sf or sf == "any":
        return True
    signed = str(item.get("signed") or "").strip().lower()
    # 空 / Undefined = 未检测，不算「未签名」，避免网络/任务等无签名字段误报
    if not signed or signed in ("undefined", "unknown", "n/a", "-"):
        return False if sf in ("unsigned", "signed") else True
    valid = signed in ("valid", "valid signature", "signed")
    if sf == "signed":
        return valid
    if sf == "unsigned":
        compact = signed.replace(" ", "")
        return (not valid) and (
            signed in _UNSIGNED_STATUSES
            or compact in {x.replace(" ", "") for x in _UNSIGNED_STATUSES}
        )
    return True


def _path_fields_blob(item: Dict[str, Any]) -> str:
    """进程/文件规则：合并路径、命令行、父进程路径等，供 Temp/Public 片段匹配。"""
    parts: List[str] = []
    for k in (
        "path", "image", "command", "command_line", "execute", "directory",
        "parent_path", "parent_name", "target_path",
    ):
        v = item.get(k)
        if v not in (None, ""):
            parts.append(str(v))
    px = item.get("process_ext")
    if isinstance(px, dict):
        for k in ("path", "parent_path", "parent_name", "name"):
            if px.get(k):
                parts.append(str(px[k]))
        anc = px.get("ancestry")
        if isinstance(anc, list):
            for a in anc:
                if isinstance(a, dict):
                    if a.get("path"):
                        parts.append(str(a["path"]))
                    if a.get("name"):
                        parts.append(str(a["name"]))
    return "\n".join(parts).replace("/", "\\").lower()


def _path_root_only_match(path_line: str, base: str) -> bool:
    """base 为目录（末尾带 \\）：路径必须是 base + 文件名，且文件名中不再含 \\。"""
    line = (path_line or "").replace("/", "\\").lower()
    b = (base or "").replace("/", "\\").lower()
    if not line or not b:
        return False
    if not b.endswith("\\"):
        b = b + "\\"
    if not line.startswith(b):
        return False
    rest = line[len(b):]
    return bool(rest) and ("\\" not in rest)


def _path_scope_allowed(item: Dict[str, Any], prefixes: List[str]) -> bool:
    """路径范围：盘符前缀用 startswith；末尾多一个 \\（如 C:\\Users\\Public\\\\）表示仅该目录根，不含子目录。

    \\temp\\、\\public\\ 等片段在任意相关字段中出现即命中。
    """
    if not prefixes:
        return True
    blob = _path_fields_blob(item)
    if not blob.strip():
        return False
    for p in prefixes:
        pref = str(p or "").replace("/", "\\").strip().lower()
        if not pref:
            continue
        # 约定：路径以「双反斜杠」结尾 → 仅匹配该目录根一层（不含子目录）
        # 例：C:\Users\Public\\  命中 C:\Users\Public\a.exe，不命中 ...\Public\foo\a.exe
        root_only = pref.endswith("\\\\")
        if root_only:
            base = pref.rstrip("\\") + "\\"
            for line in blob.split("\n"):
                if _path_root_only_match(line, base):
                    return True
            continue
        if len(pref) >= 3 and pref[1] == ":" and pref[2] == "\\":
            for line in blob.split("\n"):
                if line.startswith(pref):
                    return True
            continue
        frag = pref
        if not frag.startswith("\\"):
            frag = "\\" + frag.strip("\\")
        if not frag.endswith("\\") and "\\" in frag:
            pass
        elif frag.endswith("\\") or "\\" in frag:
            if frag in blob:
                return True
        if pref in blob or frag in blob:
            return True
    return False


def _path_prefix_allowed(item: Dict[str, Any], prefixes: List[str]) -> bool:
    return _path_scope_allowed(item, prefixes)


def _match_text(text: str, patterns: List[str], how: str) -> Optional[str]:
    t = text or ""
    tl = t.lower()
    if not t:
        return None
    how = (how or "substring").lower()
    for p in patterns or []:
        raw = str(p or "")
        if not raw:
            continue
        # * = 任意内容（配合 path_prefixes / file_exts / signed_filter 做范围约束）
        if raw.strip() == "*":
            return "*"
        if how == "exact":
            if tl == raw.lower() or Path(t).name.lower() == raw.lower():
                return raw
        elif how == "regex":
            try:
                if re.search(raw, t, re.I):
                    return raw
            except re.error:
                continue
        else:
            if raw.lower() in tl:
                return raw
    return None


_EVIDENCE_KEYS = (
    "name", "display_name", "task_name", "path", "command", "command_line",
    "pid", "ppid", "parent_name", "parent_path", "user", "local", "remote",
    "remote_ip", "remote_port", "domain", "query", "status", "state", "author",
    "location", "proto", "signed", "signer", "sha256", "company", "file_version",
    "uptime", "process_name", "create_time", "execute", "arguments", "working_directory",
    "triggers", "start_type", "account", "image", "module", "module_name", "host_process",
    "process_path", "ext", "size", "key", "value", "value_name", "old_value", "etype",
)

_OFFICE_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "onenote.exe", "visio.exe", "mspub.exe",
    "acrord32.exe", "acrobat.exe", "wmplayer.exe",
}
_LOL_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "curl.exe", "wget.exe", "notepad.exe",
}


def _evidence_of(it: Dict[str, Any]) -> Dict[str, Any]:
    return {k: it.get(k) for k in _EVIDENCE_KEYS if it.get(k) not in (None, "")}


def _heuristic_process_hits(items: List[Any], *, max_hits: int, seen: set) -> List[Dict[str, Any]]:
    """注入/可疑父子等启发式（不依赖完整内核注入检测）。"""
    hits: List[Dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name") or "").lower()
        path = str(it.get("path") or it.get("command_line") or "").lower()
        parent = str(it.get("parent_name") or "").lower()
        signed = str(it.get("signed") or "").lower()
        pid = it.get("pid")

        def add(rid: str, title: str, sev: str, matched: str) -> bool:
            key = (rid, str(pid or name or path or matched))
            if key in seen:
                return False
            seen.add(key)
            hits.append({
                "rule_id": rid,
                "title": title,
                "severity": sev,
                "module": "process",
                "matched": matched,
                "rule_source": "agent",
                "evidence": _evidence_of(it),
            })
            return len(hits) >= max_hits

        # 办公/阅读器拉起 LOLBIN —— 常见宏/投放后行为
        if parent in _OFFICE_PARENTS and name in _LOL_CHILDREN:
            if add("agent-heur-office-child", "办公进程拉起脚本解释器", "high", f"{parent} → {name}"):
                return hits
        # 未签名落在系统目录 —— 伪装/替换启发式
        if signed in ("notsigned", "hashmismatch", "nottrusted") and (
            "\\windows\\system32\\" in path or "\\windows\\syswow64\\" in path
        ):
            if add("agent-heur-unsigned-system", "系统目录未签名进程", "high", signed or "NotSigned"):
                return hits
        # 未签名 + 临时目录
        if signed in ("notsigned", "hashmismatch") and any(
            x in path for x in ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\users\\public\\")
        ):
            if add("agent-heur-unsigned-temp", "临时目录未签名进程", "high", signed or "NotSigned"):
                return hits
        # 父进程丢失（ppid 指向不存在）且自身在临时目录 —— 注入/断链启发式弱信号
        ppid = it.get("ppid")
        if (
            ppid not in (None, 0, "0")
            and not parent
            and any(x in path for x in ("\\temp\\", "\\appdata\\", "\\users\\public\\"))
        ):
            # matched 带可读说明；evidence 仍含子进程完整字段，父名缺失表示链已断
            if add(
                "agent-heur-orphan-temp",
                "临时目录进程父链缺失",
                "medium",
                f"父进程不可见 ppid={ppid}（可能已退出或注入断链）",
            ):
                return hits
    return hits


def match_snapshot(module: str, items: List[Any], *, max_hits: int = 30) -> List[Dict[str, Any]]:
    mod = str(module or "").lower()
    rules = [
        r for r in list_rules(enabled_only=True)
        if mod in (r.get("modules") or []) and not is_elastic_rule(r)
    ]
    hits: List[Dict[str, Any]] = []
    seen = set()
    if rules and items:
        for it in items:
            if not isinstance(it, dict):
                continue
            for rule in rules:
                if not _ext_allowed(it, list(rule.get("file_exts") or [])):
                    continue
                if not _signed_allowed(it, str(rule.get("signed_filter") or "")):
                    continue
                if not _path_prefix_allowed(it, list(rule.get("path_prefixes") or [])):
                    continue
                blob = _item_blob(it, list(rule.get("fields") or []))
                pats = [p for p in list(rule.get("patterns") or []) if p and p != "*"]
                if str(rule.get("signed_filter") or "") == "unsigned" and not pats:
                    hit_pat = f"signed={it.get('signed') or 'empty'}"
                else:
                    hit_pat = _match_text(blob, pats or list(rule.get("patterns") or []), str(rule.get("match") or "substring"))
                if not hit_pat:
                    continue
                rid = str(rule.get("id") or "")
                key = (rid, str(it.get("name") or it.get("task_name") or it.get("pid") or it.get("path") or hit_pat))
                if key in seen:
                    continue
                seen.add(key)
                rsrc = str(rule.get("source") or "custom").lower()
                if rule.get("builtin"):
                    rsrc = "sensor"
                elif is_elastic_rule(rule):
                    rsrc = "elastic"
                hits.append({
                    "rule_id": rid,
                    "title": str(rule.get("title") or rid),
                    "rule_title": str(rule.get("title") or rid),
                    "severity": str(rule.get("severity") or "medium"),
                    "module": mod,
                    "matched": hit_pat,
                    "rule_source": rsrc if rsrc in ("elastic", "custom", "sensor") else "agent",
                    "evidence": _evidence_of(it),
                })
                if len(hits) >= max_hits:
                    return hits
    if mod == "process" and len(hits) < max_hits:
        hits.extend(_heuristic_process_hits(items or [], max_hits=max_hits - len(hits), seen=seen))
    if mod == "process" and len(hits) < max_hits:
        hits.extend(lolbin_hits(items or [], max_hits=max_hits - len(hits), seen=seen))
    return hits


def rule_fim_paths(max_paths: int = 20) -> List[str]:
    """文件类规则的路径前缀 → Agent FIM 监控目录（含扩展名），实现「目录下新建未签名文件」实时命中。"""
    out: List[str] = []
    seen = set()

    def add_drive_roots(exts: str) -> None:
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            spec = f"{letter}:\\"
            if exts:
                spec += "|" + exts
            spec += "|rule"
            if spec.lower() not in seen:
                seen.add(spec.lower())
                out.append(spec)

    for r in list_rules(enabled_only=True, include_sensor=False):
        pats = [str(p) for p in (r.get("patterns") or [])]
        rid = str(r.get("id") or "")
        if rid in ("agent-root-drop", "agent-progdata-temp-unsigned") or any(
            "^" in p and ":\\\\" in p and "[^\\\\]" in p for p in pats
        ):
            if rid == "agent-progdata-temp-unsigned":
                for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                    for sub in (r"ProgramData", r"Windows\Temp"):
                        spec = f"{letter}:\\{sub}|r|exe,dll,bat,cmd,ps1,scr,msi,js,vbs,hta|rule"
                        if spec.lower() not in seen:
                            seen.add(spec.lower())
                            out.append(spec)
                if len(out) >= max_paths:
                    return out
                continue
            exts = ",".join(
                sorted({str(e).strip().lstrip(".").lower() for e in (r.get("file_exts") or []) if str(e).strip()})
            ) or "exe,dll,bat,cmd,ps1,scr"
            add_drive_roots(exts)
            if len(out) >= max_paths:
                return out
    for r in list_rules(enabled_only=True, include_sensor=False):
        if "file" not in (r.get("modules") or []):
            continue
        prefixes = [str(p).strip() for p in (r.get("path_prefixes") or []) if str(p).strip()]
        if not prefixes:
            continue
        exts = ",".join(sorted({str(e).strip().lstrip(".").lower() for e in (r.get("file_exts") or []) if str(e).strip()}))
        for p in prefixes:
            p = p.replace("/", "\\")
            if not re.match(r"^[A-Za-z]:\\", p):
                continue
            root = p.rstrip("\\")
            spec = (root + "\\") if len(root) == 2 else (root + "|r")
            if exts:
                spec += "|" + exts
            spec += "|rule"
            if spec.lower() in seen:
                continue
            seen.add(spec.lower())
            out.append(spec)
            if len(out) >= max_paths:
                return out
    return out


def lolbin_hits(items: List[Any], *, max_hits: int = 30, seen: Optional[set] = None) -> List[Dict[str, Any]]:
    """LOLBin 内置检测（进程名 + 命令行 + 父进程）。"""
    from . import lolbin

    seen = seen if seen is not None else set()
    disabled = set((load_doc().get("lolbin_disabled") or []))
    out: List[Dict[str, Any]] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        for h in lolbin.match(it, disabled=disabled):
            key = (h["rule_id"], str(it.get("pid") or it.get("entity_id") or it.get("command_line") or ""))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "rule_id": h["rule_id"],
                "title": "LOLBin · " + h["title"],
                "severity": h["severity"],
                "module": "process",
                "matched": h["matched"],
                "rule_source": "lolbin",
                "technique": h["technique"],
                "tactic": h["tactic"],
                "evidence": _evidence_of(it),
            })
            if len(out) >= max_hits:
                return out
    return out


def report_rule_hits(agent_id: str, module: str, hits: List[Dict[str, Any]], hostname: str = "") -> Dict[str, Any]:
    from . import agent_protocol

    written = 0
    skipped = 0
    for h in hits:
        evd = h.get("evidence") or {}
        obj = str(evd.get("name") or evd.get("task_name") or evd.get("display_name") or "")
        if not obj:
            p = str(evd.get("path") or evd.get("command") or "")
            obj = p.replace("/", "\\").rsplit("\\", 1)[-1] if p else ""
        title = f"规则命中：{h.get('title')}"
        if obj:
            title = f"{title} · {obj}"
        detail = {
            "rule_id": h.get("rule_id"),
            "rule_title": h.get("rule_title") or h.get("title"),
            "rule_source": h.get("rule_source") or "agent",
            "matched": h.get("matched"),
            "evidence": evd,
            "module": h.get("module"),
        }
        for k in _EVIDENCE_KEYS:
            if k in evd and evd.get(k) not in (None, ""):
                detail.setdefault(k, evd[k])
        if h.get("technique"):
            detail["technique"] = h.get("technique")
            detail["tactic"] = h.get("tactic")
        use_mod = str(h.get("module") or module or "process").lower()
        nm = str(evd.get("name") or "").lower()
        if nm in (
            "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "cmd.exe",
        ):
            use_mod = "script"
        cmd_blob = str(evd.get("command_line") or evd.get("command") or h.get("matched") or "")
        if use_mod != "script" and cmd_blob and re.search(
            r"powershell|pwsh|wscript|cscript|mshta|scriptblock|frombase64string|-enc\b",
            cmd_blob,
            re.I,
        ):
            use_mod = "script"
        ev = agent_protocol.report_event({
            "agent_id": agent_id,
            "hostname": hostname,
            "module": use_mod,
            "severity": h.get("severity") or "medium",
            "title": title[:200],
            "detail": detail,
        })
        if ev.get("suppressed"):
            skipped += 1
        elif ev.get("ok") and not ev.get("deduped"):
            written += 1
    return {"ok": True, "hits": len(hits), "events": written, "skipped_whitelist": skipped, "ts": time.time()}


def apply_lolbin(agent_id: str, items: List[Any], hostname: str = "") -> Dict[str, Any]:
    return report_rule_hits(agent_id, "process", lolbin_hits(items), hostname)


def enrich_process_event_detail(
    agent_id: str,
    detail: Dict[str, Any],
    summary: str = "",
) -> Dict[str, Any]:
    """补全进程 detail：摘要解析进程名；命令行为空时从 agent_processes 表回填（ETW 创建过早常见）。"""
    d = dict(detail or {})
    if not d.get("name") and summary:
        m = re.search(r"[:：]\s*([^\s(]+)", str(summary), re.I)
        if m:
            nm = m.group(1).strip().strip('"')
            if nm:
                d.setdefault("name", nm)
    cmd = str(d.get("command_line") or d.get("command") or "").strip()
    if cmd or not agent_id or not d.get("pid"):
        return d
    try:
        from . import agent_edr

        agent_edr.ensure()
        pid = str(d.get("pid"))
        with agent_edr._lock:
            conn = agent_edr._connect()
            try:
                row = conn.execute(
                    """SELECT command_line, name, path FROM agent_processes
                       WHERE agent_id=? AND CAST(pid AS TEXT)=?
                       ORDER BY last_seen DESC LIMIT 1""",
                    (agent_id, pid),
                ).fetchone()
                if row:
                    if row[0]:
                        d["command_line"] = row[0]
                    if not d.get("name") and row[1]:
                        d["name"] = row[1]
                    if not d.get("path") and row[2]:
                        d["path"] = row[2]
            finally:
                conn.close()
    except Exception:
        pass
    return d


def apply_snapshot_rules(agent_id: str, module: str, items: List[Any], hostname: str = "") -> Dict[str, Any]:
    hits = match_snapshot(module, items)
    return report_rule_hits(agent_id, module, hits, hostname)


def _evm_match_blob(ev: Dict[str, Any]) -> str:
    et = str(ev.get("etype") or "").lower()
    summary = str(ev.get("summary") or "").lower()
    detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    path = str(detail.get("path") or detail.get("image") or "").lower()
    blob = summary + "\n" + path + "\n" + str(detail.get("command_line") or "").lower()
    px = detail.get("process_ext") if isinstance(detail.get("process_ext"), dict) else {}
    if px:
        blob += "\n" + str(px.get("parent_name") or "").lower()
        blob += "\n" + str(px.get("parent_path") or "").lower()
        blob += "\n" + str(px.get("grandparent_name") or "").lower()
    blob += "\n" + str(detail.get("parent_path") or "").lower()
    return blob


def _evm_rule_matches(r: Dict[str, Any], ev: Dict[str, Any]) -> bool:
    et = str(ev.get("etype") or "").lower()
    summary = str(ev.get("summary") or "").lower()
    detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    want_et = str(r.get("etype") or "").lower()
    if want_et and want_et != et:
        return False
    sc = str(r.get("summary_contains") or "").lower()
    if sc and sc not in summary:
        return False
    prefixes = [str(p).strip() for p in (r.get("path_prefixes") or []) if str(p).strip()]
    if prefixes and not _path_scope_allowed(detail, prefixes):
        return False
    if not _ext_allowed(detail, list(r.get("file_exts") or [])):
        return False
    if not _signed_allowed(detail, str(r.get("signed_filter") or "")):
        return False
    pn = str(r.get("parent_name_contains") or "").strip().lower()
    if pn:
        parent = str(detail.get("parent_name") or "").lower()
        if not parent and isinstance(detail.get("process_ext"), dict):
            parent = str(detail["process_ext"].get("parent_name") or "").lower()
        if pn not in parent:
            return False
    pats = [str(p).strip() for p in (r.get("patterns") or []) if str(p).strip() and str(p).strip() != "*"]
    if not pats:
        return True
    blob = _evm_match_blob(ev)
    how = str(r.get("match") or "substring").lower()
    for p in pats:
        if how == "regex":
            try:
                if re.search(p, blob, re.I):
                    return True
            except re.error:
                continue
        elif p.lower() in blob:
            return True
    return False


def match_live_evm_events(ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    """与 Agent evmEvaluate 对齐：对已上报时间线事件做 EVM 匹配（含 agent-live 自定义规则）。"""
    if not isinstance(ev, dict):
        return []
    try:
        rules = export_evm_document().get("rules") or []
    except Exception:
        return []
    hits: List[Dict[str, Any]] = []
    for r in rules:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        if _evm_rule_matches(r, ev):
            hits.append(r)
    return hits[:8]


def export_evm_document() -> Dict[str, Any]:
    """端上 EVM：时间线/传感器启用规则的轻量条件包。"""
    rules: List[Dict[str, Any]] = []
    for r in list_rules(enabled_only=True):
        mods = r.get("modules") or []
        if r.get("source") != "sensor" and "timeline" not in mods:
            if "file" in mods or "process" in mods:
                file_rule = {
                    "id": str(r.get("id") or ""),
                    "title": str(r.get("title") or ""),
                    "severity": str(r.get("severity") or "medium"),
                    "summary_contains": "",
                    "path_prefixes": [str(p) for p in (r.get("path_prefixes") or []) if str(p).strip()][:12],
                    "patterns": [str(p) for p in (r.get("patterns") or []) if str(p).strip()][:24],
                    "file_exts": [str(e).strip().lstrip(".").lower() for e in (r.get("file_exts") or []) if str(e).strip()][:24],
                    "match": str(r.get("match") or "substring"),
                    "signed_filter": str(r.get("signed_filter") or ""),
                    "building_block": bool(r.get("building_block")),
                }
                # FIM and ETW use different event names; cover file lifecycle changes.
                for etype in ("fim_add", "fim_modify", "fim_rename", "file_create", "file_write", "file_write_etw", "file_stream_create", "file_rename", "file_delete"):
                    item = dict(file_rule)
                    item["etype"] = etype
                    if etype != "fim_add":
                        item["id"] = f"{file_rule['id']}.{etype}"
                    rules.append(item)
            continue
        evm_item = {
            "id": str(r.get("id") or ""),
            "title": str(r.get("title") or ""),
            "severity": str(r.get("severity") or "medium"),
            "etype": str(r.get("etype") or "").strip(),
            "summary_contains": str(r.get("summary_contains") or "").strip(),
            "path_prefixes": [str(p) for p in (r.get("path_prefixes") or []) if str(p).strip()][:12],
            "patterns": [str(p) for p in (r.get("patterns") or []) if str(p).strip()][:24],
            "file_exts": [str(e).strip().lstrip(".").lower() for e in (r.get("file_exts") or []) if str(e).strip()][:24],
            "match": str(r.get("match") or "substring"),
            "signed_filter": str(r.get("signed_filter") or ""),
            "building_block": bool(r.get("building_block")),
        }
        pn = str(r.get("parent_name_contains") or "").strip()
        if pn:
            evm_item["parent_name_contains"] = pn[:64]
        rid = str(r.get("id") or "")
        if r.get("source") == "sensor" and rid in _SENSOR_EVM_SKIP_IDS:
            continue
        rules.append(evm_item)
    def _append_evm_rules(src_rules: List[Dict[str, Any]]) -> None:
        for r in src_rules:
            if not isinstance(r, dict):
                continue
            rules.append({
                "id": str(r.get("id") or ""),
                "title": str(r.get("title") or ""),
                "severity": str(r.get("severity") or "medium"),
                "etype": str(r.get("etype") or "").strip(),
                "summary_contains": str(r.get("summary_contains") or "").strip(),
                "path_prefixes": [str(p) for p in (r.get("path_prefixes") or []) if str(p).strip()][:12],
                "patterns": [str(p) for p in (r.get("patterns") or []) if str(p).strip()][:24],
                "match": str(r.get("match") or "substring"),
                "signed_filter": str(r.get("signed_filter") or ""),
                "building_block": bool(r.get("building_block")),
            })

    try:
        from . import elastic_detection_import as _edi

        _append_evm_rules(_edi.load_evm_import_rules(enabled_only=True))
    except Exception:
        pass
    try:
        from . import protections_import as _pi

        _append_evm_rules(_pi.load_evm_import_rules(enabled_only=True))
    except Exception:
        pass
    doc: Dict[str, Any] = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "rules": rules,
    }
    doc["rev"] = hashlib.sha256(json.dumps(doc, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]
    return doc


def rule_registry_fim_paths() -> List[str]:
    """注册表 FIM 扩展键（与 reg_watch 安全项互补，可按规则扩展）。"""
    out: List[str] = []
    seen = set()
    extras = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
    ]
    for p in extras:
        k = p.lower()
        if k not in seen:
            seen.add(k)
            out.append(p)
    for r in list_rules(enabled_only=True):
        if str(r.get("etype") or "").startswith("registry") or "registry" in str(r.get("title") or "").lower():
            for p in (r.get("path_prefixes") or []):
                ps = str(p).strip()
                if ps.upper().startswith("HK") and ps.lower() not in seen:
                    seen.add(ps.lower())
                    out.append(ps)
    return out[:32]


def _rule_compilable(rule: Dict[str, Any]) -> bool:
    """可编译：有可匹配的 pattern / 范围约束，且 match 模式合法。"""
    if not isinstance(rule, dict):
        return False
    how = str(rule.get("match") or "substring").strip().lower()
    if how not in ("substring", "regex", "exact"):
        return False
    pats = [str(p).strip() for p in (rule.get("patterns") or []) if str(p).strip()]
    if pats:
        if how == "regex":
            for p in pats:
                if p == "*":
                    continue
                try:
                    re.compile(p)
                except re.error:
                    return False
        return True
    # 异常文件等可用前缀/扩展名/未签名单独约束
    if rule.get("path_prefixes") or rule.get("file_exts") or str(rule.get("signed_filter") or "") == "unsigned":
        return True
    if rule.get("etype") or rule.get("summary_contains"):
        return True
    return False


def _rule_fields_complete(rule: Dict[str, Any]) -> bool:
    """字段齐全：标题、模块、匹配字段或 etype 约束齐备。"""
    if not isinstance(rule, dict):
        return False
    if not str(rule.get("title") or "").strip():
        return False
    mods = rule.get("modules") if isinstance(rule.get("modules"), list) else []
    fields = [str(x).strip() for x in (rule.get("fields") or []) if str(x).strip()]
    if mods and fields:
        return True
    # EVM / Elastic 导入规则可能用 note/channel 表达
    if str(rule.get("rule_channel") or "").strip() or str(rule.get("elastic_rule_id") or "").strip():
        return bool(str(rule.get("id") or "").strip())
    if rule.get("etype") or rule.get("summary_contains"):
        return True
    return False


def _production_hit_rule_ids(limit: int = 5000) -> set:
    """从 agent_events 粗提取生产命中过的 rule_id。"""
    ids: set = set()
    try:
        from . import agent_protocol
        agent_protocol.ensure_db()
        with agent_protocol._lock:
            conn = agent_protocol._connect()
            try:
                rows = conn.execute(
                    "SELECT detail FROM agent_events ORDER BY id DESC LIMIT ?",
                    (max(100, min(int(limit), 20000)),),
                ).fetchall()
            finally:
                conn.close()
        for r in rows:
            raw = r["detail"] if isinstance(r, dict) or hasattr(r, "keys") else ""
            try:
                detail = json.loads(raw or "{}") if not isinstance(raw, dict) else raw
            except Exception:
                continue
            if not isinstance(detail, dict):
                continue
            for key in ("rule_id", "id", "agent_rule_id"):
                rid = str(detail.get(key) or "").strip()
                if rid:
                    ids.add(rid)
            for nested in (detail.get("rule"), detail.get("matched_rule")):
                if isinstance(nested, dict):
                    rid = str(nested.get("id") or nested.get("rule_id") or "").strip()
                    if rid:
                        ids.add(rid)
    except Exception:
        pass
    return ids


def classify_rule_coverage(rule: Dict[str, Any], *, hit_ids: Optional[set] = None) -> Dict[str, Any]:
    """规则覆盖率五态：已导入 / 可编译 / 字段齐全 / 已回放 / 生产有命中。"""
    rid = str(rule.get("id") or "").strip()
    imported = bool(rid)
    compilable = imported and _rule_compilable(rule)
    fields_ok = imported and _rule_fields_complete(rule)
    replayed = bool(
        rule.get("replayed")
        or rule.get("replay_at")
        or rule.get("last_replay_at")
        or rule.get("validated")
        or rule.get("ai_draft_validated")
    )
    hits = hit_ids if hit_ids is not None else set()
    prod_hit = bool(rid and rid in hits) or int(rule.get("hits") or rule.get("hit_count") or 0) > 0
    # 最高达到的阶梯状态（五态互斥展示用）
    if prod_hit:
        state = "production_hit"
    elif replayed:
        state = "replayed"
    elif fields_ok and compilable:
        state = "fields_complete"
    elif compilable:
        state = "compilable"
    else:
        state = "imported"
    return {
        "id": rid,
        "state": state,
        "imported": imported,
        "compilable": compilable,
        "fields_complete": fields_ok,
        "replayed": replayed,
        "production_hit": prod_hit,
    }


def rule_coverage_stats(*, include_items: bool = True) -> Dict[str, Any]:
    """覆盖率五态汇总：已导入 / 可编译 / 字段齐全 / 已回放 / 生产有命中。"""
    rules = _merge_evm_rules_for_ui(list_rules())
    hit_ids = _production_hit_rule_ids()
    ladder = {
        "imported": 0,
        "compilable": 0,
        "fields_complete": 0,
        "replayed": 0,
        "production_hit": 0,
    }
    items: List[Dict[str, Any]] = []
    for r in rules:
        cov = classify_rule_coverage(r, hit_ids=hit_ids)
        ladder[cov["state"]] = ladder.get(cov["state"], 0) + 1
        if include_items:
            items.append({
                "id": cov["id"],
                "title": str(r.get("title") or "")[:120],
                "enabled": bool(r.get("enabled", True)),
                "source": r.get("source") or ("sensor" if r.get("builtin") else "custom"),
                **{k: cov[k] for k in (
                    "state", "imported", "compilable", "fields_complete", "replayed", "production_hit",
                )},
            })
    labels = {
        "imported": "已导入",
        "compilable": "可编译",
        "fields_complete": "字段齐全",
        "replayed": "已回放",
        "production_hit": "生产有命中",
    }
    return {
        "ok": True,
        "total": len(rules),
        "ladder": ladder,
        "labels": labels,
        "states": [
            {"key": k, "label": labels[k], "count": ladder[k]}
            for k in ("imported", "compilable", "fields_complete", "replayed", "production_hit")
        ],
        "hit_ids_sampled": len(hit_ids),
        "items": items if include_items else [],
    }


def list_platform_rule_stats() -> Dict[str, Any]:
    """兼容旧接口：返回独立规则库统计。"""
    rules = _merge_evm_rules_for_ui(list_rules())
    enabled = [r for r in rules if r.get("enabled", True)]
    coverage = rule_coverage_stats(include_items=False)
    return {
        "ok": True,
        "source": "Agent 独立规则库",
        "path": str(_path()),
        "count": len(rules),
        "enabled": len(enabled),
        "counts": {"agent_rules": len(rules), "enabled": len(enabled)},
        "coverage": {
            "ladder": coverage.get("ladder") or {},
            "labels": coverage.get("labels") or {},
            "states": coverage.get("states") or [],
            "total": coverage.get("total") or 0,
        },
        "items": rules,
    }

from .agent_rule_defaults import _default_rules, _sensor_builtin_rules
