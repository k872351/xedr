"""AI 调查用的 EDR 证据工具集。

查询类工具只读，AI 可自主调用；会改变终端状态的工具标记为 active，
只有调查发起时显式允许才可调用，且全部落调用审计。
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional

_STR_LIMIT = 300

# 持久化 / 注册表类时间线事件
_PERSIST_ETYPES = (
    "persist_add", "persist_modify", "persist_delete",
    "registry_set", "registry_delete",
    "win_service_install", "win_service_config", "win_task_create", "win_task_update",
    "wmi_persist", "startup_add",
)
_REGISTRY_ETYPES = ("registry_set", "registry_delete", "persist_add", "persist_modify", "persist_delete")
_NETWORK_ETYPES = (
    "network_connect", "network_connect_etw", "http_request_etw", "beacon_like",
    "dns_nx_burst", "win_smb", "win_bits",
)
_MODULE_ETYPES = ("image_load_etw", "image_load_kernel", "driver_load_etw", "driver_load_kernel", "driver_load")
_MEMORY_ETYPES = ("memory_scan_hit", "remote_thread", "remote_thread_kernel", "process_access", "api_call", "api_amsi")


def _s(v: Any, limit: int = _STR_LIMIT) -> str:
    s = str(v if v is not None else "")
    return s if len(s) <= limit else s[:limit] + "…"


def _since(hours: Any) -> str:
    try:
        h = float(hours or 0)
    except (TypeError, ValueError):
        h = 0
    if h <= 0:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - h * 3600))


def _clamp(v: Any, default: int, lo: int = 1, hi: int = 200) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        n = default
    return max(lo, min(n, hi))


def _slim_detail(d: Dict[str, Any]) -> Dict[str, Any]:
    keep = (
        "pid", "ppid", "name", "process_name", "path", "image", "command_line", "parent_name",
        "parent_command_line", "user", "integrity", "signed", "signer", "sha256", "md5",
        "key", "reg_key", "value_name", "value", "old_value", "data", "category", "label",
        "remote", "remote_ip", "remote_port", "local_port", "proto", "domain", "query", "answers",
        "service_name", "task_name", "target", "target_path", "event_id", "channel",
        "rule_id", "rule_title", "matched", "address", "protect", "type", "entity_id",
        "parent_entity_id", "script_block", "api",
    )
    out: Dict[str, Any] = {}
    for k in keep:
        v = d.get(k)
        if v in (None, "", [], {}):
            continue
        out[k] = _s(v, 400 if k in ("command_line", "script_block") else _STR_LIMIT) if isinstance(v, str) else v
    return out


def _timeline(
    agent_id: str,
    *,
    etypes: Optional[tuple] = None,
    q: str = "",
    hours: Any = 0,
    entity_id: str = "",
    limit: int = 40,
) -> List[Dict[str, Any]]:
    from .. import agent_edr
    agent_edr.ensure()
    clauses, args = ["agent_id=?"], [agent_id]
    if etypes:
        clauses.append(f"etype IN ({','.join('?' * len(etypes))})")
        args.extend(etypes)
    if q:
        clauses.append("(summary LIKE ? OR detail_json LIKE ?)")
        like = f"%{q}%"
        args.extend([like, like])
    cut = _since(hours)
    if cut:
        clauses.append("ts>=?")
        args.append(cut)
    if entity_id:
        clauses.append("entity_id=?")
        args.append(entity_id)
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            rows = conn.execute(
                f"SELECT id, ts, etype, severity, summary, detail_json FROM agent_timeline "
                f"WHERE {' AND '.join(clauses)} ORDER BY ts DESC, id DESC LIMIT ?",
                (*args, int(limit)),
            ).fetchall()
        except Exception:
            rows = []
        finally:
            conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            det = json.loads(d.pop("detail_json") or "{}")
        except Exception:
            det = {}
        out.append({
            "tl_id": d.get("id"),
            "ts": d.get("ts"),
            "etype": d.get("etype"),
            "severity": d.get("severity"),
            "summary": _s(d.get("summary"), 240),
            "detail": _slim_detail(det if isinstance(det, dict) else {}),
        })
    return out


def _agent_row(agent_id: str) -> Optional[Dict[str, Any]]:
    from .. import agent_protocol
    for a in (agent_protocol.list_agents(online_within_sec=180).get("items") or []):
        if str(a.get("agent_id") or "") == agent_id:
            return a
    return None


def _snapshot_items(agent_id: str, module: str) -> Dict[str, Any]:
    from .. import agent_protocol
    snap = agent_protocol.get_snapshot(agent_id, module)
    if not snap.get("ok"):
        return {"updated_at": "", "items": []}
    item = snap.get("item") or {}
    items = item.get("items") if isinstance(item.get("items"), list) else []
    return {"updated_at": item.get("updated_at") or item.get("ts") or "", "items": items}


def _match(row: Dict[str, Any], q: str) -> bool:
    if not q:
        return True
    return q.lower() in json.dumps(row, ensure_ascii=False).lower()


# ---------------- 工具实现 ----------------

def t_get_host_overview(agent_id: str, **_: Any) -> Dict[str, Any]:
    from .. import agent_protocol
    a = _agent_row(agent_id)
    if not a:
        return {"ok": False, "error": "终端不存在"}
    mods = {}
    for m in ("process", "service", "task", "startup", "network", "listen", "user", "software"):
        snap = _snapshot_items(agent_id, m)
        mods[m] = {"count": len(snap["items"]), "updated_at": snap["updated_at"]}
    ev = agent_protocol.list_events(status="open", agent_id=agent_id, limit=200)
    sev: Dict[str, int] = {}
    for e in ev.get("items") or []:
        k = str(e.get("severity") or "info")
        sev[k] = sev.get(k, 0) + 1
    health = (a.get("health") or {}) if isinstance(a.get("health"), dict) else {}
    return {
        "ok": True,
        "host": {
            "agent_id": agent_id,
            "hostname": a.get("hostname"),
            "ip": a.get("ip"),
            "os": a.get("os_family") or a.get("os"),
            "version": a.get("version"),
            "online": bool(a.get("online")),
            "last_seen": a.get("last_seen"),
        },
        "snapshot_modules": mods,
        "open_threats_by_severity": sev,
        "capture": {k: health.get(k) for k in ("sensors", "capture_status") if health.get(k)} if health else {},
    }


def t_list_threat_events(agent_id: str, status: str = "", limit: Any = 20, **_: Any) -> Dict[str, Any]:
    from .. import agent_protocol
    ev = agent_protocol.list_events(status=str(status or ""), agent_id=agent_id, limit=_clamp(limit, 20, hi=60))
    items = []
    for e in ev.get("items") or []:
        det = e.get("detail_obj") if isinstance(e.get("detail_obj"), dict) else {}
        items.append({
            "event_id": e.get("id"),
            "severity": e.get("severity"),
            "status": e.get("status"),
            "title": _s(e.get("title"), 160),
            "module": e.get("module"),
            "hit_count": e.get("hit_count"),
            "created_at": e.get("created_at"),
            "updated_at": e.get("updated_at"),
            "detail": _slim_detail(det),
        })
    return {"ok": True, "count": len(items), "items": items}


def t_search_endpoint_events(
    agent_id: str, q: str = "", etype: str = "", hours: Any = 24, limit: Any = 30, **_: Any,
) -> Dict[str, Any]:
    ets = tuple(x.strip() for x in str(etype or "").split(",") if x.strip()) or None
    items = _timeline(agent_id, etypes=ets, q=str(q or "").strip(), hours=hours, limit=_clamp(limit, 30, hi=80))
    return {"ok": True, "count": len(items), "items": items}


def t_list_processes(agent_id: str, q: str = "", alive: Any = None, limit: Any = 25, **_: Any) -> Dict[str, Any]:
    from .. import agent_telemetry
    alive_v: Optional[bool] = None
    if isinstance(alive, bool):
        alive_v = alive
    elif str(alive).lower() in ("true", "1", "yes"):
        alive_v = True
    elif str(alive).lower() in ("false", "0", "no"):
        alive_v = False
    res = agent_telemetry.list_processes(agent_id, q=str(q or ""), alive=alive_v, limit=_clamp(limit, 25, hi=80))
    items = []
    for p in res.get("items") or []:
        items.append({
            "entity_id": p.get("entity_id"),
            "parent_entity_id": p.get("parent_entity_id"),
            "pid": p.get("pid"),
            "ppid": p.get("ppid"),
            "name": p.get("name"),
            "path": _s(p.get("path")),
            "command_line": _s(p.get("command_line"), 400),
            "user": p.get("user"),
            "integrity": p.get("integrity"),
            "create_time": p.get("create_time"),
            "exit_time": p.get("exit_time"),
        })
    return {"ok": True, "count": len(items), "items": items}


def t_get_process_detail(agent_id: str, entity_id: str = "", pid: Any = None, **_: Any) -> Dict[str, Any]:
    from .. import agent_telemetry
    eid = str(entity_id or "").strip()
    if not eid and pid not in (None, ""):
        got = agent_telemetry.list_processes(agent_id, q=str(pid), limit=5).get("items") or []
        got = [x for x in got if str(x.get("pid")) == str(pid)]
        if got:
            eid = str(got[0].get("entity_id") or "")
    if not eid:
        return {"ok": False, "error": "需要 entity_id 或可定位的 pid"}
    res = agent_telemetry.process_detail(agent_id, eid, events_limit=40)
    if not res.get("ok"):
        return res

    def brief(p: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not p:
            return {}
        return {k: (_s(p.get(k), 400) if k == "command_line" else p.get(k)) for k in (
            "entity_id", "pid", "name", "path", "command_line", "user", "integrity",
            "create_time", "exit_time", "missing",
        ) if p.get(k) not in (None, "")}

    events = []
    for e in res.get("events") or []:
        try:
            det = json.loads(e.get("detail_json") or "{}")
        except Exception:
            det = {}
        events.append({
            "ts": e.get("ts"), "etype": e.get("etype"), "severity": e.get("severity"),
            "summary": _s(e.get("summary"), 200), "detail": _slim_detail(det if isinstance(det, dict) else {}),
        })
    return {
        "ok": True,
        "process": brief(res.get("entity")),
        "ancestors": [brief(a) for a in res.get("ancestors") or []],
        "children": [brief(c) for c in (res.get("children") or [])[:20]],
        "event_counts": res.get("event_counts") or {},
        "events": events[:30],
    }


def t_get_process_tree(agent_id: str, event_id: Any = 0, **_: Any) -> Dict[str, Any]:
    from .. import agent_edr
    try:
        eid = int(event_id or 0)
    except (TypeError, ValueError):
        eid = 0
    res = agent_edr.threat_process_tree(agent_id, event_id=eid, max_nodes=40)
    nodes = []
    for n in (res.get("nodes") or [])[:40]:
        if not isinstance(n, dict):
            continue
        nodes.append({k: (_s(n.get(k), 300) if isinstance(n.get(k), str) else n.get(k)) for k in (
            "id", "parent_id", "pid", "ppid", "name", "path", "command_line", "user",
            "is_hit", "exit_time", "missing", "signed",
        ) if n.get(k) not in (None, "", [], False)})
    return {"ok": bool(res.get("ok", True)), "title": res.get("title") or "", "hit_id": res.get("hit_id") or "",
            "nodes": nodes, "error": res.get("error") or ""}


def t_get_persistence_items(agent_id: str, kind: str = "", q: str = "", limit: Any = 30, **_: Any) -> Dict[str, Any]:
    kinds = [k for k in ("service", "task", "startup") if not kind or kind == k]
    lim = _clamp(limit, 30, hi=80)
    out: Dict[str, Any] = {"ok": True}
    for k in kinds:
        snap = _snapshot_items(agent_id, k)
        rows = [r for r in snap["items"] if isinstance(r, dict) and _match(r, q)]
        slim = []
        for r in rows[:lim]:
            slim.append({kk: (_s(r.get(kk), 300) if isinstance(r.get(kk), str) else r.get(kk)) for kk in (
                "name", "display_name", "path", "image_path", "command", "execute", "command_line",
                "start_type", "status", "account", "user", "task_name", "location", "signed", "signer",
                "sha256", "service_dll", "author", "trigger", "created", "modified",
            ) if r.get(kk) not in (None, "", [])})
        out[k] = {"snapshot_at": snap["updated_at"], "total": len(snap["items"]), "matched": len(rows), "items": slim}
    if not kind or kind in ("registry", "wmi", "changes"):
        out["recent_changes"] = _timeline(agent_id, etypes=_PERSIST_ETYPES, q=str(q or ""), hours=24 * 7, limit=lim)
    return out


def t_get_registry_changes(agent_id: str, q: str = "", hours: Any = 168, limit: Any = 30, **_: Any) -> Dict[str, Any]:
    items = _timeline(agent_id, etypes=_REGISTRY_ETYPES, q=str(q or ""), hours=hours, limit=_clamp(limit, 30, hi=80))
    return {
        "ok": True, "count": len(items), "items": items,
        "note": "当前注册表监控基于变更通知，修改者进程可能缺失；old_value 为修改前值。",
    }


def t_get_network_connections(agent_id: str, q: str = "", hours: Any = 24, limit: Any = 30, **_: Any) -> Dict[str, Any]:
    lim = _clamp(limit, 30, hi=80)
    live = [r for r in _snapshot_items(agent_id, "network")["items"] if isinstance(r, dict) and _match(r, q)]
    listen = [r for r in _snapshot_items(agent_id, "listen")["items"] if isinstance(r, dict) and _match(r, q)]

    def slim(r: Dict[str, Any]) -> Dict[str, Any]:
        return {k: r.get(k) for k in (
            "proto", "local", "remote", "state", "pid", "process", "name", "path", "remote_ip", "remote_port",
            "local_port",
        ) if r.get(k) not in (None, "")}

    return {
        "ok": True,
        "live_connections": [slim(r) for r in live[:lim]],
        "listening": [slim(r) for r in listen[:lim]],
        "recent_events": _timeline(agent_id, etypes=_NETWORK_ETYPES, q=str(q or ""), hours=hours, limit=lim),
    }


def t_get_dns_queries(agent_id: str, q: str = "", nx_only: Any = False, limit: Any = 30, **_: Any) -> Dict[str, Any]:
    from .. import agent_telemetry
    res = agent_telemetry.list_dns(agent_id, q=str(q or ""), nx_only=bool(nx_only), limit=_clamp(limit, 30, hi=80))
    items = []
    for d in res.get("items") or []:
        items.append({
            "domain": d.get("domain"),
            "hits": d.get("hits"),
            "nx_hits": d.get("nx_hits"),
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
            "max_dga": d.get("max_dga"),
            "answers": (d.get("answers") or [])[:5],
            "processes": (d.get("processes") or [])[:5],
            "ioc_hit": bool(d.get("ioc_hit")),
            "ioc_hits": (d.get("ioc_hits") or [])[:3],
        })
    return {"ok": True, "count": len(items), "items": items}


def t_get_module_loads(agent_id: str, q: str = "", hours: Any = 72, limit: Any = 30, **_: Any) -> Dict[str, Any]:
    items = _timeline(agent_id, etypes=_MODULE_ETYPES, q=str(q or ""), hours=hours, limit=_clamp(limit, 30, hi=80))
    return {"ok": True, "count": len(items), "items": items}


def t_get_memory_findings(agent_id: str, q: str = "", hours: Any = 168, limit: Any = 30, **_: Any) -> Dict[str, Any]:
    items = _timeline(agent_id, etypes=_MEMORY_ETYPES, q=str(q or ""), hours=hours, limit=_clamp(limit, 30, hi=80))
    return {
        "ok": True, "count": len(items), "items": items,
        "note": "跨进程内存写入/APC 等 Threat-Intelligence 事件需 PPL 才能收到，缺失不代表没有注入。",
    }


def t_get_file_metadata(agent_id: str, path: str = "", sha256: str = "", **_: Any) -> Dict[str, Any]:
    needle = str(sha256 or path or "").strip()
    if not needle:
        return {"ok": False, "error": "需要 path 或 sha256"}
    hits = []
    for mod in ("process", "service", "startup", "task", "file"):
        for r in _snapshot_items(agent_id, mod)["items"]:
            if isinstance(r, dict) and _match(r, needle):
                hits.append({"source": f"snapshot.{mod}", **{k: r.get(k) for k in (
                    "name", "path", "image_path", "sha256", "md5", "signed", "signer", "size",
                    "created", "modified", "company", "version", "description",
                ) if r.get(k) not in (None, "")}})
                if len(hits) >= 10:
                    break
    events = _timeline(agent_id, q=needle, hours=24 * 30, limit=15)
    return {"ok": True, "snapshot_hits": hits, "related_events": events}


def t_search_ioc(value: str = "", ioc_type: str = "", **_: Any) -> Dict[str, Any]:
    from .. import ioc_db
    v = str(value or "").strip()
    if not v:
        return {"ok": False, "error": "需要 value"}
    try:
        hits = ioc_db.lookup(v, ioc_type or None) or []
    except Exception as e:
        return {"ok": False, "error": _s(e, 200)}
    slim = []
    for h in hits[:8]:
        if isinstance(h, dict):
            slim.append({k: h.get(k) for k in (
                "value", "type", "ioc_type", "source", "tags", "malware", "family", "confidence",
                "severity", "first_seen", "last_seen", "description",
            ) if h.get(k) not in (None, "", [])})
    return {"ok": True, "value": v, "hit": bool(slim), "matches": slim}


def t_get_prevalence(value: str = "", agent_id: str = "", **_: Any) -> Dict[str, Any]:
    """全网流行度：多少台终端出现过该路径/Hash/域名/进程名，以及本机首次出现时间。"""
    from .. import agent_edr
    v = str(value or "").strip()
    if len(v) < 3:
        return {"ok": False, "error": "value 太短"}
    agent_edr.ensure()
    like = f"%{v}%"
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            hosts = conn.execute(
                "SELECT agent_id, MAX(hostname) AS hostname, COUNT(*) AS n, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
                "FROM agent_timeline WHERE detail_json LIKE ? OR summary LIKE ? GROUP BY agent_id "
                "ORDER BY n DESC LIMIT 20",
                (like, like),
            ).fetchall()
            proc_hosts = conn.execute(
                "SELECT COUNT(DISTINCT agent_id) AS c FROM agent_processes WHERE path LIKE ? OR command_line LIKE ?",
                (like, like),
            ).fetchone()
            total_agents = conn.execute("SELECT COUNT(*) AS c FROM agents").fetchone()
        except Exception as e:
            return {"ok": False, "error": _s(e, 200)}
        finally:
            conn.close()
    rows = [dict(h) for h in hosts]
    this_host = next((r for r in rows if r.get("agent_id") == agent_id), None)
    return {
        "ok": True,
        "value": v,
        "fleet_agents": int((total_agents or {"c": 0})["c"] or 0),
        "hosts_in_timeline": len(rows),
        "hosts_in_process_table": int((proc_hosts or {"c": 0})["c"] or 0),
        "this_host_first_seen": (this_host or {}).get("first_ts") or "",
        "this_host_count": (this_host or {}).get("n") or 0,
        "hosts": rows[:10],
    }


def t_get_attack_story(agent_id: str, event_id: Any = 0, **_: Any) -> Dict[str, Any]:
    from .. import agent_edr
    try:
        eid = int(event_id or 0)
    except (TypeError, ValueError):
        eid = 0
    res = agent_edr.attack_story(agent_id, event_id=eid, limit=40)
    nodes = []
    for n in (res.get("nodes") or res.get("items") or [])[:40]:
        if isinstance(n, dict):
            nodes.append({k: (_s(n.get(k), 240) if isinstance(n.get(k), str) else n.get(k)) for k in (
                "ts", "kind", "title", "summary", "etype", "severity", "tactic", "technique", "mitre", "process",
            ) if n.get(k) not in (None, "", [])})
    return {"ok": bool(res.get("ok", True)), "nodes": nodes, "error": res.get("error") or ""}


def t_match_log_rules(agent_id: str, hours: Any = 24, **_: Any) -> Dict[str, Any]:
    from .. import agent_edr
    rows = _timeline(agent_id, hours=hours, limit=200)
    shaped = []
    for r in rows:
        det = r.get("detail") or {}
        if det.get("event_id") in (None, ""):
            continue
        ev = agent_edr._timeline_to_eventlog_shape({"ts": r.get("ts"), "summary": r.get("summary"), "detail": det})
        if ev:
            shaped.append(ev)
    if not shaped:
        return {"ok": True, "checked": 0, "hits": [], "note": "时间窗内没有带 EventID 的日志事件"}
    from ..eventlog_rules import match_events
    hits, _meta = match_events(shaped[:150], max_hits=40)
    out = [{
        "rule_title": h.get("title"), "level": h.get("level"), "event_id": h.get("event_id"),
        "channel": h.get("channel"), "time": h.get("time"), "evidence": _s(h.get("evidence"), 200),
    } for h in hits[:25]]
    return {"ok": True, "checked": len(shaped), "hits": out}


def t_request_memory_scan(agent_id: str, pid: Any = None, actor: str = "", **_: Any) -> Dict[str, Any]:
    from .. import agent_edr
    params: Dict[str, Any] = {"trigger": "ai_investigation"}
    try:
        if pid not in (None, ""):
            params["pid"] = int(pid)
    except (TypeError, ValueError):
        pass
    res = agent_edr.create_command(agent_id, "scan_memory", params, actor=actor or "ai-investigator")
    return {
        "ok": bool(res.get("ok")),
        "command_id": res.get("id"),
        "status": res.get("status") or ("queued" if res.get("ok") else ""),
        "error": res.get("error") or "",
        "note": "命令已下发，结果稍后以 memory_scan_hit 事件回传，可再用 get_memory_findings 查看。",
    }


# ---------------- 工具目录 ----------------

ToolFn = Callable[..., Dict[str, Any]]

TOOLS: Dict[str, Dict[str, Any]] = {
    "get_host_overview": {
        "fn": t_get_host_overview, "mode": "read",
        "desc": "终端基本信息、在线状态、各快照模块条数、未处置威胁按级别统计。调查开始时先调用。",
        "params": {},
    },
    "list_threat_events": {
        "fn": t_list_threat_events, "mode": "read",
        "desc": "列出该终端的威胁告警（含标题、级别、命中详情）。",
        "params": {"status": "open|closed|空=全部", "limit": "条数，默认20"},
    },
    "search_endpoint_events": {
        "fn": t_search_endpoint_events, "mode": "read",
        "desc": "按关键字/事件类型/时间窗检索端点原始时间线（进程、文件、网络、注册表、日志等）。",
        "params": {"q": "关键字（路径/进程名/IP/命令行片段）", "etype": "事件类型，逗号分隔，可空",
                   "hours": "回溯小时数，默认24", "limit": "条数，默认30"},
    },
    "list_processes": {
        "fn": t_list_processes, "mode": "read",
        "desc": "查询进程实体（含 entity_id、父进程、命令行、用户、完整性级别、创建/退出时间）。",
        "params": {"q": "进程名/路径/命令行/pid", "alive": "true 仅存活 / false 仅已退出", "limit": "默认25"},
    },
    "get_process_detail": {
        "fn": t_get_process_detail, "mode": "read",
        "desc": "单个进程实例的祖先链、子进程和该进程产生的全部行为事件。",
        "params": {"entity_id": "进程实体 ID（优先）", "pid": "无 entity_id 时用 pid 定位"},
    },
    "get_process_tree": {
        "fn": t_get_process_tree, "mode": "read",
        "desc": "以某条威胁告警为种子还原进程树。",
        "params": {"event_id": "威胁事件 ID"},
    },
    "get_persistence_items": {
        "fn": t_get_persistence_items, "mode": "read",
        "desc": "当前服务、计划任务、启动项快照，以及近 7 天持久化/注册表/WMI 变化。",
        "params": {"kind": "service|task|startup|changes，可空", "q": "过滤关键字", "limit": "默认30"},
    },
    "get_registry_changes": {
        "fn": t_get_registry_changes, "mode": "read",
        "desc": "注册表持久化位置的修改记录（含修改前值 old_value）。",
        "params": {"q": "键路径/值关键字", "hours": "默认168", "limit": "默认30"},
    },
    "get_network_connections": {
        "fn": t_get_network_connections, "mode": "read",
        "desc": "当前网络连接、监听端口及近期外联事件（含进程归属）。",
        "params": {"q": "IP/端口/进程名", "hours": "默认24", "limit": "默认30"},
    },
    "get_dns_queries": {
        "fn": t_get_dns_queries, "mode": "read",
        "desc": "DNS 解析聚合（域名、解析结果、发起进程、DGA 分、情报命中）。",
        "params": {"q": "域名关键字", "nx_only": "仅解析失败", "limit": "默认30"},
    },
    "get_module_loads": {
        "fn": t_get_module_loads, "mode": "read",
        "desc": "DLL / 驱动加载事件（路径、签名、加载进程）。",
        "params": {"q": "模块名/路径", "hours": "默认72", "limit": "默认30"},
    },
    "get_memory_findings": {
        "fn": t_get_memory_findings, "mode": "read",
        "desc": "内存扫描命中、远程线程、跨进程访问、敏感 API 调用、AMSI 事件。",
        "params": {"q": "进程名/规则名", "hours": "默认168", "limit": "默认30"},
    },
    "get_file_metadata": {
        "fn": t_get_file_metadata, "mode": "read",
        "desc": "按路径或 SHA256 查文件属性（签名、哈希、大小、时间）及相关事件。",
        "params": {"path": "文件路径", "sha256": "哈希"},
    },
    "search_ioc": {
        "fn": t_search_ioc, "mode": "read",
        "desc": "威胁情报库查询（IP / 域名 / Hash / URL）。",
        "params": {"value": "要查的值", "ioc_type": "可空"},
    },
    "get_prevalence": {
        "fn": t_get_prevalence, "mode": "read",
        "desc": "全网流行度：多少台终端出现过该路径/Hash/域名/进程名，本机首次出现时间。用于判断罕见度与误报。",
        "params": {"value": "路径/Hash/域名/进程名"},
    },
    "get_attack_story": {
        "fn": t_get_attack_story, "mode": "read",
        "desc": "按时间顺序的攻击链节点（带 ATT&CK 标注），可指定某条威胁事件。",
        "params": {"event_id": "威胁事件 ID，可空"},
    },
    "match_log_rules": {
        "fn": t_match_log_rules, "mode": "read",
        "desc": "用平台 Sigma 日志规则精确匹配该终端近期带 EventID 的日志。",
        "params": {"hours": "默认24"},
    },
    "request_memory_scan": {
        "fn": t_request_memory_scan, "mode": "active",
        "desc": "向终端下发内存扫描（会占用终端资源）。仅在允许主动操作时可用。",
        "params": {"pid": "指定进程，可空=按策略扫描"},
    },
}


def tool_catalog(*, allow_active: bool = False) -> List[Dict[str, Any]]:
    out = []
    for name, spec in TOOLS.items():
        if spec["mode"] == "active" and not allow_active:
            continue
        out.append({"name": name, "mode": spec["mode"], "description": spec["desc"], "params": spec["params"]})
    return out


def call_tool(
    name: str,
    args: Optional[Dict[str, Any]],
    *,
    agent_id: str,
    allow_active: bool = False,
    actor: str = "",
) -> Dict[str, Any]:
    spec = TOOLS.get(str(name or ""))
    if not spec:
        return {"ok": False, "error": f"未知工具: {name}"}
    if spec["mode"] == "active" and not allow_active:
        return {"ok": False, "error": "该工具会改变终端状态，本次调查未授权主动操作"}
    kw = dict(args or {})
    kw.pop("agent_id", None)
    try:
        if name in ("search_ioc",):
            return spec["fn"](**kw)
        if name == "get_prevalence":
            return spec["fn"](agent_id=agent_id, **kw)
        if spec["mode"] == "active":
            return spec["fn"](agent_id, actor=actor, **kw)
        return spec["fn"](agent_id, **kw)
    except TypeError as e:
        return {"ok": False, "error": f"参数错误: {_s(e, 200)}"}
    except Exception as e:
        return {"ok": False, "error": _s(e, 300)}
