"""主机行为基线 + 全网流行度（基于 agent_timeline / agent_processes / 快照）。"""
from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from . import agent_edr


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def _path_base(p: str) -> str:
    s = str(p or "").replace("/", "\\").strip()
    if "\\" in s:
        s = s.rsplit("\\", 1)[-1]
    return s.lower()


def build_host_baseline(agent_id: str, *, days: int = 7) -> Dict[str, Any]:
    """统计主机近 N 天进程/外联/文件/用户等画像，作为行为基线。"""
    agent_edr.ensure()
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    days_n = max(1, min(int(days or 7), 30))
    # 时间线 ts 多为本地 ISO（含 T）或空格分隔，两种 since 均兼容字符串比较
    since = (datetime.now() - timedelta(days=days_n)).strftime("%Y-%m-%dT%H:%M:%S")
    since_alt = since.replace("T", " ")
    inv_counts: Dict[str, Any] = {}
    inv_samples: Dict[str, List[Dict[str, Any]]] = {}
    snap_procs = []
    host_row = None
    rows = []
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            rows = conn.execute(
                """SELECT etype, summary, detail_json, ts FROM agent_timeline
                   WHERE agent_id=? AND (ts>=? OR ts>=?) ORDER BY ts DESC LIMIT 12000""",
                (aid, since, since_alt),
            ).fetchall()
            # 最近进程快照（当前运行态，非历史计数）
            try:
                snap_procs = conn.execute(
                    """SELECT name, path, user, pid, ppid, command_line FROM agent_processes
                       WHERE agent_id=? AND (exit_time IS NULL OR exit_time='')
                       ORDER BY last_seen DESC LIMIT 200""",
                    (aid,),
                ).fetchall()
            except Exception:
                try:
                    snap_procs = conn.execute(
                        """SELECT name, path, user, pid, ppid, command_line FROM agent_processes
                           WHERE agent_id=? ORDER BY last_seen DESC LIMIT 200""",
                        (aid,),
                    ).fetchall()
                except Exception:
                    snap_procs = []
            # 资产快照条目数 + 样例条目（供基线页点开）
            try:
                for mod in ("software", "service", "startup", "listen", "driver", "netif", "user", "task"):
                    row = conn.execute(
                        "SELECT item_count, collected_at, payload_json FROM agent_snapshots WHERE agent_id=? AND module=?",
                        (aid, mod),
                    ).fetchone()
                    if not row:
                        continue
                    inv_counts[mod] = {
                        "count": int(row[0] or 0),
                        "collected_at": row[1] or "",
                    }
                    try:
                        items = json.loads(row[2] or "[]")
                    except Exception:
                        items = []
                    if not isinstance(items, list):
                        items = []
                    sample = []
                    for it in items[:40]:
                        if not isinstance(it, dict):
                            continue
                        sample.append({
                            "name": str(it.get("name") or it.get("display_name") or it.get("task_name") or "")[:160],
                            "path": str(it.get("path") or it.get("command") or it.get("image_path") or "")[:240],
                            "status": str(it.get("status") or it.get("start_type") or it.get("state") or "")[:64],
                            "user": str(it.get("user") or it.get("account") or it.get("location") or "")[:80],
                            "extra": str(it.get("version") or it.get("publisher") or it.get("proto") or it.get("local") or "")[:80],
                        })
                    inv_samples[mod] = sample
            except Exception:
                inv_counts = {}
                inv_samples = {}
            host_row = conn.execute(
                "SELECT hostname, os_family, version, ip, last_heartbeat_at FROM agents WHERE agent_id=?",
                (aid,),
            ).fetchone()
        finally:
            conn.close()

    procs: Counter = Counter()
    parents: Counter = Counter()
    ports: Counter = Counter()
    hosts: Counter = Counter()
    users: Counter = Counter()
    files: Counter = Counter()
    etypes: Counter = Counter()
    hours: Counter = Counter()
    signed: Counter = Counter()
    first_ts = ""
    last_ts = ""

    for etype, summary, detail_s, ts in rows:
        et = str(etype or "")
        etypes[et] += 1
        ts_s = str(ts or "")
        if ts_s:
            if not last_ts or ts_s > last_ts:
                last_ts = ts_s
            if not first_ts or ts_s < first_ts:
                first_ts = ts_s
            try:
                hours[ts_s[11:13]] += 1
            except Exception:
                pass
        try:
            d = json.loads(detail_s or "{}")
        except Exception:
            d = {}
        if not isinstance(d, dict):
            d = {}
        name = str(d.get("process_name") or d.get("name") or "").lower()
        if name and ("process" in et or et.startswith("process")):
            procs[name] += 1
            pn = str(d.get("parent_name") or "").lower()
            if pn:
                parents[f"{pn} → {name}"] += 1
            u = str(d.get("user") or d.get("username") or "")
            if u:
                users[u] += 1
            sig = d.get("signed")
            if sig is True or str(sig).lower() in ("1", "true", "yes"):
                signed["signed"] += 1
            elif sig is False or str(sig).lower() in ("0", "false", "no"):
                signed["unsigned"] += 1
        if "network" in et or et in ("http_request_etw", "dns_query", "dns_query_etw"):
            port = str(d.get("remote_port") or d.get("port") or "")
            if port:
                ports[port] += 1
            h = str(d.get("host") or d.get("domain") or d.get("remote_ip") or d.get("query") or "")
            if h:
                hosts[h.lower()] += 1
        if "file" in et or et.startswith("fim") or "registry" in et:
            fp = str(d.get("path") or d.get("target_path") or d.get("file_path") or summary or "")
            base = _path_base(fp)
            if base and len(base) > 1:
                files[base] += 1

    # 活跃时段：按小时计数取 Top
    busy_hours = [f"{h}:00" for h, _ in hours.most_common(5)]

    live_procs = []
    for row in snap_procs[:40]:
        try:
            live_procs.append({
                "name": row["name"] if hasattr(row, "keys") else row[0],
                "path": (row["path"] if hasattr(row, "keys") else row[1]) or "",
                "user": (row["user"] if hasattr(row, "keys") else row[2]) or "",
                "pid": row["pid"] if hasattr(row, "keys") else row[3],
            })
        except Exception:
            continue

    host_meta = {}
    if host_row:
        try:
            host_meta = {
                "hostname": host_row["hostname"] if hasattr(host_row, "keys") else host_row[0],
                "os_family": host_row["os_family"] if hasattr(host_row, "keys") else host_row[1],
                "version": host_row["version"] if hasattr(host_row, "keys") else host_row[2],
                "ip": host_row["ip"] if hasattr(host_row, "keys") else host_row[3],
                "last_heartbeat_at": host_row["last_heartbeat_at"] if hasattr(host_row, "keys") else host_row[4],
            }
        except Exception:
            host_meta = {}

    return {
        "ok": True,
        "agent_id": aid,
        "days": days_n,
        "since": since,
        "built_at": _now(),
        "host": host_meta,
        "event_count": len(rows),
        "first_event_at": first_ts,
        "last_event_at": last_ts,
        "unique_processes": len(procs),
        "unique_destinations": len(hosts),
        "unique_ports": len(ports),
        "unique_users": len(users),
        "top_processes": procs.most_common(40),
        "top_parent_child": parents.most_common(30),
        "top_ports": ports.most_common(25),
        "top_destinations": hosts.most_common(40),
        "top_users": users.most_common(15),
        "top_files": files.most_common(25),
        "etype_breakdown": etypes.most_common(20),
        "busy_hours": busy_hours,
        "signed_stats": dict(signed),
        "live_processes": live_procs,
        "inventory_counts": inv_counts,
        "inventory_samples": inv_samples,
    }


def score_against_baseline(agent_id: str, *, process_name: str = "", remote_port: str = "", dest: str = "") -> Dict[str, Any]:
    bl = build_host_baseline(agent_id, days=7)
    if not bl.get("ok"):
        return bl
    reasons: List[str] = []
    score = 0
    pn = (process_name or "").lower()
    if pn:
        known = {k for k, _ in bl.get("top_processes") or []}
        if pn not in known:
            score += 40
            reasons.append("进程不在主机近 7 日基线")
        else:
            reasons.append("进程见于主机基线")
    if remote_port:
        known_p = {k for k, _ in bl.get("top_ports") or []}
        if remote_port not in known_p:
            score += 25
            reasons.append(f"端口 {remote_port} 不在常见外联端口")
    if dest:
        known_d = {k for k, _ in bl.get("top_destinations") or []}
        if dest.lower() not in known_d:
            score += 25
            reasons.append("目的地不在常见外联集合")
    return {
        "ok": True,
        "agent_id": agent_id,
        "score": score,
        "severity": "high" if score >= 50 else ("medium" if score >= 25 else "low"),
        "reasons": reasons,
        "baseline_summary": {
            "top_processes": (bl.get("top_processes") or [])[:8],
            "top_ports": (bl.get("top_ports") or [])[:8],
            "top_destinations": (bl.get("top_destinations") or [])[:8],
        },
    }


def fleet_prevalence(value: str, *, limit: int = 30) -> Dict[str, Any]:
    """全网流行度（路径/进程/域名/Hash 片段）。"""
    from .ai import edr_tools
    return edr_tools.t_get_prevalence(value=value, agent_id="")
