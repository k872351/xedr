"""Agent policy validation, rollout and revision management."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from . import agent_protocol
from .agent_edr import _DEFAULT_POLICY, _audit, _connect, _lock, _now, ensure


def get_policy(scope: str = "global") -> Dict[str, Any]:
    ensure()
    scope = str(scope or "global")
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM agent_policy WHERE scope=?", (scope,)).fetchone()
            if not row:
                now = _now()
                conn.execute(
                    "INSERT INTO agent_policy(scope, policy_json, rev, updated_at) VALUES(?,?,1,?)",
                    (scope, json.dumps(_DEFAULT_POLICY, ensure_ascii=False), now),
                )
                conn.commit()
                return {"ok": True, "scope": scope, "rev": 1, "policy": dict(_DEFAULT_POLICY), "updated_at": now}
            try:
                pol = json.loads(row["policy_json"] or "{}")
            except Exception:
                pol = dict(_DEFAULT_POLICY)
            return {
                "ok": True,
                "scope": scope,
                "rev": int(row["rev"] or 1),
                "policy": pol,
                "updated_at": row["updated_at"],
            }
        finally:
            conn.close()


_POLICY_BOOL_KEYS = (
    "response_enabled", "timeline_process", "timeline_file", "timeline_network", "self_protect",
    "fim_enabled", "isolate_allow_server", "whitelist_skip_rules", "mysql_dual_write",
    "remote_ops_enabled", "sysmon_managed",
)


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    return None


def validate_policy(p: Dict[str, Any]) -> List[str]:
    """与 Agent 侧 validatePolicy 同口径：任一项非法整份拒绝，避免终端出现"半生效"。"""
    errs: List[str] = []
    for k in _POLICY_BOOL_KEYS:
        if k in p and not isinstance(p[k], bool):
            errs.append(f"{k} 必须是布尔值")
    hb = _num(p.get("heartbeat_sec")) if "heartbeat_sec" in p else 5.0
    if hb is None or not 3 <= hb <= 120:
        errs.append("heartbeat_sec 必须在 3~120")
    iv = p.get("intervals_sec")
    if iv is not None:
        if not isinstance(iv, dict):
            errs.append("intervals_sec 必须是对象")
        else:
            for k in sorted(iv):
                n = _num(iv[k])
                if n is None or not 3 <= n <= 86400:
                    errs.append(f"intervals_sec.{k} 必须在 3~86400 秒")
    for k, lo, hi in (("timeline_retain_days", 1, 365), ("events_retain_days", 7, 730)):
        if k in p:
            n = _num(p[k])
            if n is None or not lo <= n <= hi:
                errs.append(f"{k} 必须在 {lo}~{hi}")
    fp = p.get("fim_paths")
    if fp is not None:
        if not isinstance(fp, list):
            errs.append("fim_paths 必须是数组")
        elif len(fp) > 50:
            errs.append("fim_paths 最多 50 项")
        else:
            for x in fp:
                s = str(x).strip() if isinstance(x, str) else ""
                path = s.rsplit("|", 1)[0].strip() if "|" in s else s
                if not re.match(r"^[A-Za-z]:\\", path) or len(path.rstrip("\\")) <= 2:
                    errs.append(f"fim_paths 非法路径（需绝对路径且不能是整个磁盘）: {x}")
    ltp = p.get("log_tail_paths")
    if ltp is not None:
        if not isinstance(ltp, list):
            errs.append("log_tail_paths 必须是数组")
        elif len(ltp) > 20:
            errs.append("log_tail_paths 最多 20 项")
        else:
            for x in ltp:
                s = str(x).strip() if isinstance(x, str) else ""
                if not re.match(r"^[A-Za-z]:\\", s) or len(s) <= 4 or s.endswith("\\"):
                    errs.append(f"log_tail_paths 需绝对文件路径（非盘符根/目录）: {x}")
    ms = p.get("memory_scan")
    if ms is not None:
        if not isinstance(ms, dict):
            errs.append("memory_scan 必须是对象")
        else:
            mode = str(ms.get("mode") or "").strip().lower()
            ok_modes = {
                "off", "heuristic", "yara_on_demand", "yara_triggered", "yara_scheduled",
            }
            if mode and mode not in ok_modes:
                errs.append(f"memory_scan.mode 非法: {mode}")
            for nk, lo, hi in (
                ("max_processes_per_run", 1, 80),
                ("max_region_read_kb", 64, 4096),
                ("schedule_interval_sec", 300, 86400),
                ("integrity_interval_sec", 300, 86400),
            ):
                if nk in ms:
                    n = _num(ms[nk])
                    if n is None or not lo <= n <= hi:
                        errs.append(f"memory_scan.{nk} 必须在 {lo}~{hi}")
            tr = ms.get("triggers")
            if tr is not None and not isinstance(tr, list):
                errs.append("memory_scan.triggers 必须是数组")
    ds = p.get("drop_scan")
    if ds is not None:
        if not isinstance(ds, dict):
            errs.append("drop_scan 必须是对象")
        else:
            for nk, lo, hi in (("quarantine_min_score", 50, 200), ("max_file_mb", 1, 128)):
                if nk in ds:
                    n = _num(ds[nk])
                    if n is None or not lo <= n <= hi:
                        errs.append(f"drop_scan.{nk} 必须在 {lo}~{hi}")
    return errs


def set_policy(scope: str, policy: Dict[str, Any], *, actor: str = "", note: str = "") -> Dict[str, Any]:
    ensure()
    scope = str(scope or "global")
    if not isinstance(policy, dict):
        return {"ok": False, "error": "policy 必须是对象"}
    merged = dict(_DEFAULT_POLICY)
    merged.update(policy)
    # remote_ops 允许运营配置；缺省字段用默认值补齐
    ro = merged.get("remote_ops") if isinstance(merged.get("remote_ops"), dict) else {}
    base_ro = dict(_DEFAULT_POLICY.get("remote_ops") or {})
    base_ro.update(ro)
    if "remote_ops_enabled" in merged:
        base_ro["enabled"] = bool(merged.get("remote_ops_enabled"))
    merged["remote_ops"] = base_ro
    merged["remote_ops_enabled"] = bool(base_ro.get("enabled"))
    errs = validate_policy(merged)
    if errs:
        return {"ok": False, "error": "；".join(errs), "errors": errs}
    now = _now()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT rev FROM agent_policy WHERE scope=?", (scope,)).fetchone()
            rev = int(row["rev"] or 0) + 1 if row else 1
            conn.execute(
                """INSERT INTO agent_policy(scope, policy_json, rev, updated_at) VALUES(?,?,?,?)
                   ON CONFLICT(scope) DO UPDATE SET
                     policy_json=excluded.policy_json,
                     rev=excluded.rev,
                     updated_at=excluded.updated_at""",
                (scope, json.dumps(merged, ensure_ascii=False), rev, now),
            )
            conn.execute(
                """INSERT OR REPLACE INTO agent_policy_history(scope, rev, policy_json, actor, note, created_at)
                   VALUES(?,?,?,?,?,?)""",
                (scope, rev, json.dumps(merged, ensure_ascii=False), actor[:64], note[:200], now),
            )
            conn.commit()
        finally:
            conn.close()
    _audit("policy_update", detail=json.dumps({"scope": scope, "rev": rev, "note": note}, ensure_ascii=False), actor=actor)
    agent_protocol.bump_live("policy", scope=scope, rev=rev)
    try:
        from . import agent_sync
        agent_sync.bump_sync("policy")
    except Exception:
        pass
    return {"ok": True, "scope": scope, "rev": rev, "policy": merged}


def list_policy_history(scope: str = "global", *, limit: int = 50) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT scope, rev, policy_json, actor, note, created_at FROM agent_policy_history "
                "WHERE scope=? ORDER BY rev DESC LIMIT ?",
                (str(scope or "global"), max(1, min(int(limit or 50), 200))),
            ).fetchall()
        finally:
            conn.close()
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["policy"] = json.loads(d.pop("policy_json") or "{}")
        except Exception:
            d["policy"] = {}
        items.append(d)
    return {"ok": True, "items": items}


def rollback_policy(scope: str, rev: int, *, actor: str = "") -> Dict[str, Any]:
    """回滚 = 以历史版本内容发布一个新 rev（rev 单调递增，终端按新 rev 原子生效）。"""
    ensure()
    scope = str(scope or "global")
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT policy_json FROM agent_policy_history WHERE scope=? AND rev=?", (scope, int(rev))
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return {"ok": False, "error": f"历史版本 rev {rev} 不存在"}
    try:
        pol = json.loads(row["policy_json"] or "{}")
    except Exception:
        return {"ok": False, "error": "历史版本内容损坏"}
    return set_policy(scope, pol, actor=actor, note=f"回滚到 rev {int(rev)}")


def policy_rollout(scope: str = "global") -> Dict[str, Any]:
    """各终端对当前策略的生效情况（取自心跳 health.policy）。"""
    cur = get_policy(scope)
    rev = int(cur.get("rev") or 0)
    agents = agent_protocol.list_agents(online_within_sec=120).get("items") or []
    summary = {"total": 0, "applied": 0, "probation": 0, "rejected": 0, "rolled_back": 0, "pending": 0, "legacy": 0}
    problems: List[Dict[str, Any]] = []
    for a in agents:
        summary["total"] += 1
        st = (a.get("health") or {}).get("policy")
        if not isinstance(st, dict):
            summary["legacy"] += 1  # 旧 Agent 不回报策略状态
            continue
        status = str(st.get("status") or "")
        applied = int(st.get("applied_rev") or 0)
        if status in ("rejected", "rolled_back") and int(st.get("bad_rev") or 0) == rev:
            summary[status] += 1
            problems.append({
                "agent_id": a.get("agent_id"), "hostname": a.get("hostname"), "online": a.get("online"),
                "status": status, "applied_rev": applied, "lkg_rev": st.get("lkg_rev"), "error": st.get("error"),
            })
        elif applied == rev and status == "probation":
            summary["probation"] += 1
        elif applied == rev:
            summary["applied"] += 1
        else:
            summary["pending"] += 1
    return {"ok": True, "scope": scope, "rev": rev, "summary": summary, "problems": problems[:200]}
