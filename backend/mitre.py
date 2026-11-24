"""ATT&CK 技术映射：从规则 mitre 字段落到告警，并提供中文名。"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)

_STAGE_CN = {
    "persistence": "持久化",
    "execution": "执行",
    "persistence_execution": "持久化/执行",
    "defense_evasion": "防御绕过",
    "privilege_escalation": "权限提升",
    "credential_access": "凭证访问",
    "discovery": "发现",
    "lateral_movement": "横向移动",
    "collection": "收集",
    "command_and_control": "命令与控制",
    "exfiltration": "数据渗出",
    "impact": "影响",
    "initial_access": "初始访问",
}

# 无规则 mitre 时的粗粒度回退（宁可少标，不乱标）
_FALLBACK_BY_PERSIST = {
    "task": ["T1053.005"],
    "service": ["T1543.003"],
    "startup": ["T1547.001"],
    "registry": ["T1112"],
    "wmi": ["T1047"],
}
_FALLBACK_BY_CATEGORY = {
    "可疑进程": ["T1059"],
    "网络外联": ["T1071"],
}


@lru_cache(maxsize=1)
def _technique_catalog() -> Dict[str, Dict[str, str]]:
    p = Path(__file__).resolve().parent / "data" / "mitre_techniques_cn.json"
    if not p.is_file():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: Dict[str, Dict[str, str]] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            tid = normalize_technique_id(k)
            if not tid or not isinstance(v, dict):
                continue
            out[tid] = {
                "name_en": str(v.get("name_en") or ""),
                "name_cn": str(v.get("name_cn") or v.get("name_en") or tid),
            }
    return out


@lru_cache(maxsize=1)
def _version_catalog() -> Dict[str, Any]:
    """ATT&CK 版本演进登记（revoked_by / deprecated / data_sources / mitre_version）。

    独立文件，缺省或非法时返回空模型，绝不影响现有技术的名称与展示。
    借鉴 wazuh mitredb.py 的版本字段建模。
    """
    empty: Dict[str, Any] = {
        "mitre_version": "", "verified": False, "deprecated": set(),
        "revoked_by": {}, "data_sources": {}, "allowed_data_sources": set(),
    }
    p = Path(__file__).resolve().parent / "data" / "mitre_versioning.json"
    if not p.is_file():
        return empty
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return empty
    if not isinstance(raw, dict):
        return empty

    def _valid_ids(values: Any) -> set:
        out = set()
        if isinstance(values, list):
            for v in values:
                tid = normalize_technique_id(v)
                if tid:
                    out.add(tid)
        return out

    deprecated = _valid_ids(raw.get("deprecated"))
    revoked: Dict[str, str] = {}
    if isinstance(raw.get("revoked_by"), dict):
        for k, v in raw["revoked_by"].items():
            tid, repl = normalize_technique_id(k), normalize_technique_id(v)
            if tid and repl:
                revoked[tid] = repl
    data_sources: Dict[str, List[str]] = {}
    allowed = {str(x) for x in (raw.get("allowed_data_sources") or []) if isinstance(x, str)} if isinstance(raw.get("allowed_data_sources"), list) else set()
    if isinstance(raw.get("data_sources"), dict):
        for k, v in raw["data_sources"].items():
            tid = normalize_technique_id(k)
            if not tid or not isinstance(v, list):
                continue
            clean = [str(x) for x in v if isinstance(x, str) and (not allowed or x in allowed)]
            if clean:
                data_sources[tid] = clean
    return {
        "mitre_version": str(raw.get("mitre_version") or ""),
        "verified": bool(raw.get("verified")),
        "deprecated": deprecated,
        "revoked_by": revoked,
        "data_sources": data_sources,
        "allowed_data_sources": allowed,
    }


def validate_versioning(raw: Any) -> List[str]:
    """校验版本登记文件的闭集字段，返回错误列表（空=合法）。

    供 scripts/validate_rules.py 或 CI 调用，防止非法 tid / 非法 data_source 静默生效。
    """
    errors: List[str] = []
    if not isinstance(raw, dict):
        return ["根节点必须是对象"]
    allowed_top = {
        "_comment", "note", "mitre_version", "verified", "allowed_data_sources",
        "deprecated", "revoked_by", "data_sources", "example_entry_shape",
    }
    for k in raw:
        if k not in allowed_top:
            errors.append(f"未知顶层键: {k}")
    if not isinstance(raw.get("mitre_version", ""), str):
        errors.append("mitre_version 必须是字符串")
    if not isinstance(raw.get("verified", False), bool):
        errors.append("verified 必须是布尔")
    allowed = raw.get("allowed_data_sources")
    if not isinstance(allowed, list) or not all(isinstance(x, str) and x.strip() for x in allowed):
        errors.append("allowed_data_sources 必须是非空字符串数组")
    dep = raw.get("deprecated")
    if not isinstance(dep, list):
        errors.append("deprecated 必须是数组")
    else:
        for v in dep:
            if not normalize_technique_id(v):
                errors.append(f"deprecated 含非法技术 ID: {v}")
    rev = raw.get("revoked_by")
    if not isinstance(rev, dict):
        errors.append("revoked_by 必须是对象")
    else:
        for k, v in rev.items():
            if not normalize_technique_id(k) or not normalize_technique_id(v):
                errors.append(f"revoked_by 键/值须为技术 ID: {k}->{v}")
    ds = raw.get("data_sources")
    if not isinstance(ds, dict):
        errors.append("data_sources 必须是对象")
    else:
        allowed_set = set(allowed) if isinstance(allowed, list) else set()
        for k, v in ds.items():
            if not normalize_technique_id(k):
                errors.append(f"data_sources 键含非法技术 ID: {k}")
            if not isinstance(v, list):
                errors.append(f"data_sources[{k}] 必须是数组")
                continue
            for x in v:
                if not isinstance(x, str) or (allowed_set and x not in allowed_set):
                    errors.append(f"data_sources[{k}] 含非白名单数据源: {x}")
    return errors


def version_status(tid: str, *, versioning: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """返回技术的版本状态；子技术在自身未登记时继承父技术状态。

    status: active | deprecated | revoked
    """
    cat = versioning if versioning is not None else _version_catalog()
    tid_n = normalize_technique_id(tid)
    out: Dict[str, Any] = {
        "status": "active", "deprecated": False, "revoked_by": "",
        "data_sources": [], "mitre_version": str(cat.get("mitre_version") or ""),
        "verified": bool(cat.get("verified")),
    }
    if not tid_n:
        return out
    deprecated = cat.get("deprecated") or set()
    revoked = cat.get("revoked_by") or {}
    sources = cat.get("data_sources") or {}

    def _lookup(t: str) -> Dict[str, Any]:
        return {
            "deprecated": t in deprecated,
            "replacement": str(revoked.get(t) or ""),
            "sources": list(sources.get(t) or []),
        }

    own = _lookup(tid_n)
    parent = tid_n.split(".", 1)[0]
    inherited = _lookup(parent) if parent != tid_n else own
    # 子技术：自身状态优先；父技术已废弃/撤销时子技术继承（除自身有独立登记）
    eff = own if (own["deprecated"] or own["replacement"] or own["sources"]) else inherited
    out["deprecated"] = bool(eff["deprecated"])
    out["revoked_by"] = str(eff["replacement"] or "")
    out["data_sources"] = list(eff["sources"])[:20]
    if out["revoked_by"]:
        out["status"] = "revoked"
    elif out["deprecated"]:
        out["status"] = "deprecated"
    return out


def normalize_technique_id(raw: Any) -> str:
    s = str(raw or "").strip().upper().replace(" ", "")
    if not s:
        return ""
    if s.startswith("ATTACK."):
        s = s[7:]
    if not s.startswith("T"):
        s = "T" + s
    return s if _TECH_RE.match(s) else ""


def normalize_technique_ids(values: Any) -> List[str]:
    out: List[str] = []
    seen = set()
    if isinstance(values, str):
        values = re.split(r"[,;\s]+", values)
    if not isinstance(values, (list, tuple, set)):
        return out
    for v in values:
        tid = normalize_technique_id(v)
        if tid and tid not in seen:
            seen.add(tid)
            out.append(tid)
    return out


def technique_meta(tid: str, *, versioning: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """技术元数据；新增版本演进字段（向后兼容，旧消费者只读 id/name_*/label 不受影响）。

    - status: active | deprecated | revoked
    - revoked_by: 替代技术 ID（若有）
    - data_sources: ATT&CK 数据源（白名单内）
    - mitre_version / verified: 所用 ATT&CK 版本与是否已核实
    - 子技术继承父技术的废弃/撤销状态（ADR-015）
    """
    tid_n = normalize_technique_id(tid)
    cat = _technique_catalog()
    info = cat.get(tid_n) or {}
    if not info and "." in tid_n:
        info = cat.get(tid_n.split(".", 1)[0]) or {}
    name_cn = info.get("name_cn") or ""
    name_en = info.get("name_en") or ""
    label = f"{tid_n} · {name_cn}" if name_cn else tid_n
    out: Dict[str, Any] = {
        "id": tid_n,
        "name_cn": name_cn,
        "name_en": name_en,
        "label": label,
        "label_plain": label,
    }
    vs = version_status(tid_n, versioning=versioning)
    out.update(vs)
    if vs["status"] != "active":
        # 展示层提示，避免分析人员误用已废弃技术（label 前缀，不覆盖原 label 语义）
        suffix = f"（已撤销 → {vs['revoked_by']}）" if vs["revoked_by"] else "（已废弃）"
        out["label_with_status"] = f"{label} {suffix}"
        out["label"] = f"{label} {suffix}"
    return out


def stage_label(stage: Any) -> str:
    s = str(stage or "").strip()
    if not s:
        return ""
    return _STAGE_CN.get(s.lower(), s)


def mitre_labels(ids: Sequence[str]) -> List[Dict[str, Any]]:
    return [technique_meta(t) for t in ids if normalize_technique_id(t)]


def enrich_extra_from_rule(extra: Optional[Dict[str, Any]], rule: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """匹配时把规则上的 mitre / attackStage 写入 Finding.extra。"""
    out = dict(extra or {})
    if not isinstance(rule, dict):
        return out
    m = normalize_technique_ids(rule.get("mitre"))
    if m:
        out["mitre"] = m
    stage = rule.get("attackStage") or rule.get("attack_stage")
    if stage:
        out["attack_stage"] = str(stage).strip()
    tags = rule.get("tags")
    if isinstance(tags, list) and tags and "tags" not in out:
        out["tags"] = [str(t) for t in tags if t][:12]
    return out


def _fallback_mitre(item: Dict[str, Any]) -> List[str]:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    kind = str(extra.get("persist_kind") or "").strip().lower()
    if kind in _FALLBACK_BY_PERSIST:
        return list(_FALLBACK_BY_PERSIST[kind])
    cat = str(item.get("category") or item.get("type") or "").strip()
    if cat in _FALLBACK_BY_CATEGORY:
        return list(_FALLBACK_BY_CATEGORY[cat])
    return []


def resolve_mitre_for_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """给单条告警解析 ATT&CK：优先已有字段 → 规则库 → 回退。"""
    if not isinstance(item, dict):
        return {"mitre": [], "mitre_labels": [], "attack_stage": "", "attack_stage_label": ""}
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    ids = normalize_technique_ids(item.get("mitre") or extra.get("mitre"))
    stage = str(item.get("attack_stage") or extra.get("attack_stage") or "").strip()
    if not ids:
        rid = str(item.get("rule_id") or "").strip()
        if rid:
            try:
                from .rules_loader import get_store
                rule = get_store().rule_by_id(rid)
            except Exception:
                rule = None
            if isinstance(rule, dict):
                ids = normalize_technique_ids(rule.get("mitre"))
                if not stage:
                    stage = str(rule.get("attackStage") or rule.get("attack_stage") or "").strip()
    if not ids:
        ids = _fallback_mitre(item)
    return {
        "mitre": ids,
        "mitre_labels": mitre_labels(ids),
        "attack_stage": stage,
        "attack_stage_label": stage_label(stage),
    }


def enrich_finding_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return item
    info = resolve_mitre_for_item(item)
    if info["mitre"]:
        item["mitre"] = info["mitre"]
        item["mitre_labels"] = info["mitre_labels"]
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        extra = dict(extra)
        extra["mitre"] = info["mitre"]
        if info["attack_stage"]:
            extra["attack_stage"] = info["attack_stage"]
            item["attack_stage"] = info["attack_stage"]
            item["attack_stage_label"] = info["attack_stage_label"]
        item["extra"] = extra
    elif info["attack_stage"]:
        item["attack_stage"] = info["attack_stage"]
        item["attack_stage_label"] = info["attack_stage_label"]
    return item


def enrich_findings_list(items: Optional[List[Any]]) -> List[Any]:
    out: List[Any] = []
    for it in items or []:
        if isinstance(it, dict):
            out.append(enrich_finding_dict(it))
        else:
            out.append(it)
    return out
