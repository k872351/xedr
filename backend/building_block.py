"""积木告警聚合：同一主机多战术/多规则命中后升级为威胁事件。"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any, Dict, List, Set

from . import agent_protocol, risk_scoring

_lock = threading.RLock()
# agent_id -> last upgrade ts (avoid spam)
_last_upgrade: Dict[str, float] = {}
_UPGRADE_COOLDOWN_SEC = 900
_MIN_DISTINCT_RULES = 3
_LOOKBACK_SEC = 1800


def _tactic_of(detail: Dict[str, Any]) -> str:
    mitre = detail.get("mitre")
    if isinstance(mitre, list) and mitre:
        t = str(mitre[0]).upper()
        if t.startswith("T"):
            return t.split(".")[0]
    m = detail.get("mitre_tactic") or detail.get("tactic")
    if m:
        return str(m).lower()
    rid = str(detail.get("correlation_rule_id") or detail.get("rule_id") or "")
    if "login" in rid or "credential" in rid:
        return "credential_access"
    if "net" in rid or "c2" in rid:
        return "command_and_control"
    if "proc" in rid or "office" in rid:
        return "execution"
    return "unknown"


def aggregate_building_blocks(agent_id: str, host: str) -> int:
    if not agent_id:
        return 0
    now = time.time()
    with _lock:
        if now - _last_upgrade.get(agent_id, 0) < _UPGRADE_COOLDOWN_SEC:
            return 0
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - _LOOKBACK_SEC))
    from . import agent_edr
    agent_edr.ensure()
    rows: List[Any] = []
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            rows = conn.execute(
                """SELECT id, title, detail, module, severity FROM agent_events
                   WHERE agent_id=? AND status='open' AND created_at>=?
                   ORDER BY id DESC LIMIT 80""",
                (agent_id, since),
            ).fetchall()
        finally:
            conn.close()
    bb_rules: Set[str] = set()
    tactics: Set[str] = set()
    related: List[Dict[str, Any]] = []
    seen_related: Set[str] = set()
    for r in rows:
        mod = str(r["module"] or "")
        detail_raw = str(r["detail"] or "")
        detail: Dict[str, Any] = {}
        try:
            detail = json.loads(detail_raw) if detail_raw.startswith("{") else {}
        except Exception:
            detail = {}
        is_bb = mod == "building_block" or detail.get("building_block") is True
        if not is_bb and mod != "correlation":
            continue
        if detail.get("building_block_upgrade"):
            continue
        if str(r["severity"] or "").lower() in ("critical", "high"):
            continue
        rid = str(detail.get("correlation_rule_id") or detail.get("rule_id") or r["title"] or "")
        if rid:
            bb_rules.add(rid)
        tac = _tactic_of(detail)
        if tac != "unknown":
            tactics.add(tac)
        rel_key = rid or str(r["id"])
        if rel_key in seen_related:
            continue
        seen_related.add(rel_key)
        cmd = str(detail.get("command_line") or detail.get("command") or detail.get("script_block") or "")
        path = str(detail.get("path") or detail.get("image") or detail.get("TargetFilename") or "")
        reg = str(detail.get("reg_key") or detail.get("key") or "")
        related.append({
            "event_id": r["id"],
            "rule_id": rid[:80],
            "title": str(detail.get("rule_title") or r["title"] or "")[:160],
            "summary": str(detail.get("summary") or detail.get("matched") or r["title"] or "")[:240],
            "matched": str(detail.get("matched") or "")[:240],
            "etype": str(detail.get("etype") or "")[:40],
            "module": mod[:40],
            "process_name": str(detail.get("process_name") or detail.get("name") or "")[:80],
            "pid": detail.get("pid"),
            "ppid": detail.get("ppid"),
            "parent_name": str(detail.get("parent_name") or "")[:80],
            "user": str(detail.get("user") or detail.get("username") or "")[:80],
            "path": path[:260],
            "command_line": cmd[:500],
            "reg_key": reg[:260],
            "value_name": str(detail.get("value_name") or "")[:80],
            "value": str(detail.get("value") or "")[:200],
            "remote": str(detail.get("remote") or detail.get("remote_ip") or "")[:80],
            "domain": str(detail.get("domain") or "")[:120],
            "severity": str(r["severity"] or ""),
            "created_at": str(detail.get("event_ts") or detail.get("ts") or "")[:32],
        })
    if len(bb_rules) < _MIN_DISTINCT_RULES and len(tactics) < 2:
        return 0
    title = f"多阶段可疑行为：{host or agent_id} 命中 {len(bb_rules)} 条积木/关联"
    matched_bits = []
    for item in related[:10]:
        bit = item.get("title") or item.get("rule_id") or ""
        extra = item.get("matched") or item.get("summary") or ""
        if extra and extra != bit:
            bit = f"{bit} · {extra}"
        proc = item.get("process_name") or ""
        if proc and proc not in bit:
            bit = f"{bit} [{proc}]"
        if bit:
            matched_bits.append(f"{len(matched_bits)+1}) {bit}")
    detail = {
        "building_block_upgrade": True,
        "etype": "building_block_upgrade",
        "distinct_rules": sorted(bb_rules)[:20],
        "tactics": sorted(tactics),
        "window_sec": _LOOKBACK_SEC,
        "related_hits": related[:16],
        "related_count": len(related),
        "matched": " | ".join(matched_bits)[:1200] or f"{len(bb_rules)} 条积木/关联规则",
        "investigation": (
            f"同一主机在 {_LOOKBACK_SEC // 60} 分钟内出现 {len(bb_rules)} 条低置信关联/积木告警"
            f"（战术：{', '.join(sorted(tactics)) or '未映射'}）。"
            "请展开下方「积木子告警」逐条查看进程/路径/命令行/注册表，并结合威胁视图进程树与外联溯源。"
        ),
        "risk_score": 72,
    }
    # 多战术叠加的聚合结果作为一个"高战术宽度"信号纳入主机级评分快照。
    risk_scoring.report(agent_id, detail, "default", weight=72)
    r = agent_protocol.report_event({
        "agent_id": agent_id,
        "hostname": host,
        "module": "correlation",
        "severity": "high",
        "title": title[:200],
        "detail": detail,
    })
    if r.get("ok") and not r.get("deduped") and not r.get("suppressed"):
        with _lock:
            _last_upgrade[agent_id] = now
        return 1
    return 0
