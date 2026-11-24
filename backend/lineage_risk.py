"""进程血缘风险评分 + 攻击故事线。

把时间线上的中高危信号归到进程实体，按「严重度基础分 × 时间衰减 × 重复递减」计分，
向祖先传播（每层 50%，最多 8 层，不进入系统枢纽进程），按血缘根聚合为一条故事线，
跨战术给予加成，最终给出分级与处置建议（处置仍走审批流）。
"""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from . import agent_edr

SEV_BASE = {"low": 4.0, "medium": 12.0, "high": 30.0, "critical": 50.0}
HALF_LIFE_HOURS = 6.0
PROPAGATE_RATIO = 0.5
PROPAGATE_DEPTH = 8
REPEAT_CAP = 6
CROSS_TACTIC_BONUS = 15.0
# 高危组合：同一血缘内同时出现时额外加分
COMBO_BONUS = [
    ({"execution", "command_and_control"}, 20.0),
    ({"credential_access", "lateral_movement"}, 25.0),
    ({"defense_evasion", "credential_access"}, 15.0),
    ({"persistence", "command_and_control"}, 15.0),
]
BANDS = [(120.0, "critical"), (70.0, "high"), (35.0, "medium")]

# 系统枢纽进程：不作为血缘根、不接收传播分，避免 explorer/services 永远高分
HUB_PROCESSES = frozenset({
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe", "userinit.exe", "sihost.exe",
    "runtimebroker.exe", "taskhostw.exe", "dwm.exe", "fontdrvhost.exe",
})

_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f")


def _parse_ts(s: Any) -> Optional[datetime]:
    v = str(s or "").strip().replace("Z", "")
    if not v:
        return None
    if "+" in v[10:]:
        v = v[: 10 + v[10:].index("+")]
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(v[:26], fmt)
        except ValueError:
            continue
    return None


def _band(score: float) -> str:
    for th, name in BANDS:
        if score >= th:
            return name
    return "low"


def _decay(ts: Optional[datetime], now: datetime) -> float:
    if not ts:
        return 0.5
    hours = max(0.0, (now - ts).total_seconds() / 3600.0)
    return math.pow(0.5, hours / HALF_LIFE_HOURS)


def _detail(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        d = json.loads(raw or "{}")
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


_KEY_SPLIT = re.compile(r"[：:]\s*|\s+pid=|\s+0x[0-9a-f]+", re.I)


def _signal_key(etype: str, summary: str, d: Dict[str, Any]) -> str:
    """同类命中归为一个信号：优先 rule_id / 检测类型，否则取摘要冒号前的类别前缀。"""
    rid = str(d.get("rule_id") or d.get("type") or d.get("kind") or "").strip()
    if rid:
        return f"{etype}:{rid}"
    head = _KEY_SPLIT.split(summary, maxsplit=1)[0].strip()
    return f"{etype}:{(head or summary)[:48]}"


def _tactic_of(summary: str, etype: str, d: Dict[str, Any]) -> Tuple[str, str]:
    mapped = agent_edr._map_attck(summary, "", etype)
    tac = str(mapped.get("tactic") or "")
    tech = str(mapped.get("technique") or "")
    if not tech:
        mitre = d.get("mitre")
        if isinstance(mitre, list) and mitre:
            tech = str(mitre[0])
        elif isinstance(mitre, str):
            tech = mitre
    return tac, tech


class _ProcIndex:
    def __init__(self, rows: List[Dict[str, Any]]):
        self.by_eid: Dict[str, Dict[str, Any]] = {}
        self.by_pid: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for p in rows:
            eid = str(p.get("entity_id") or "").strip()
            if not eid:
                continue
            self.by_eid[eid] = p
            try:
                self.by_pid[int(p.get("pid") or 0)].append(p)
            except (TypeError, ValueError):
                pass

    def resolve(self, eid: str, pid: Any, ts: Optional[datetime]) -> str:
        if eid and eid in self.by_eid:
            return eid
        try:
            want = int(pid or 0)
        except (TypeError, ValueError):
            want = 0
        if not want:
            return eid
        cands = self.by_pid.get(want) or []
        if not cands:
            return eid
        if ts:
            best = None
            for p in cands:
                ct = _parse_ts(p.get("create_time"))
                if ct and ct <= ts + timedelta(seconds=5):
                    if best is None or (_parse_ts(best.get("create_time")) or datetime.min) < ct:
                        best = p
            if best:
                return str(best.get("entity_id") or "")
        return str(cands[0].get("entity_id") or "")

    def name(self, eid: str) -> str:
        p = self.by_eid.get(eid) or {}
        return str(p.get("name") or "").lower()

    def parent(self, eid: str) -> str:
        p = self.by_eid.get(eid) or {}
        return str(p.get("parent_entity_id") or "").strip()

    def ancestors(self, eid: str, depth: int = 14) -> List[str]:
        out: List[str] = []
        seen = {eid}
        cur = self.parent(eid)
        while cur and cur not in seen and len(out) < depth:
            out.append(cur)
            seen.add(cur)
            cur = self.parent(cur)
        return out

    def lineage_root(self, eid: str) -> str:
        """最高的非枢纽祖先；自身是枢纽进程时返回自身。"""
        if self.name(eid) in HUB_PROCESSES:
            return eid
        root = eid
        for a in self.ancestors(eid):
            if a not in self.by_eid or self.name(a) in HUB_PROCESSES:
                break
            root = a
        return root


def _load(agent_id: str, since: str, limit: int) -> Tuple[List[Dict[str, Any]], Dict[str, _ProcIndex]]:
    agent_edr.ensure()
    sql = ("SELECT id, agent_id, hostname, etype, summary, detail_json, severity, ts, entity_id "
           "FROM agent_timeline WHERE ts>=? AND severity IN ('low','medium','high','critical')")
    args: List[Any] = [since]
    if agent_id:
        sql += " AND agent_id=?"
        args.append(agent_id)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
            aids = sorted({str(r.get("agent_id") or "") for r in rows if r.get("agent_id")})
            idx: Dict[str, _ProcIndex] = {}
            for aid in aids:
                procs = [dict(p) for p in conn.execute(
                    "SELECT entity_id, pid, ppid, parent_entity_id, name, path, command_line, user, "
                    "integrity, elevated, create_time, exit_time, source, last_seen "
                    "FROM agent_processes WHERE agent_id=? "
                    "ORDER BY last_seen DESC LIMIT 6000", (aid,)).fetchall()]
                idx[aid] = _ProcIndex(procs)
        finally:
            conn.close()
    return rows, idx


def _is_benign_noise(etype: str, d: Dict[str, Any]) -> bool:
    """平台侧兜底：.NET NGen 本机映像天然无 Authenticode，不计入风险。"""
    blob = " ".join(str(d.get(k) or "") for k in ("image", "path", "name")).lower()
    return "\\assembly\\nativeimages_" in blob


def _score_signals(rows: List[Dict[str, Any]], idx: Dict[str, _ProcIndex], now: datetime):
    """返回 {(aid, eid): {"own": float, "signals": [...], "tactics": set}}，以及无法归属的主机级信号。

    重复递减按「血缘根 + 信号键」计算：同一规则在同一血缘多个子进程上反复命中只按一条信号递减累计。
    """
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    hosts: Dict[str, str] = {}
    unattributed: Dict[str, int] = defaultdict(int)
    for r in rows:
        aid = str(r.get("agent_id") or "")
        hosts.setdefault(aid, str(r.get("hostname") or ""))
        sev = str(r.get("severity") or "").lower()
        if sev not in SEV_BASE:
            continue
        d = _detail(r.get("detail_json"))
        ts = _parse_ts(r.get("ts"))
        pi = idx.get(aid)
        eid = str(r.get("entity_id") or d.get("entity_id") or "").strip()
        pid = d.get("pid") or d.get("target_pid")
        if not pid and isinstance(d.get("ecs"), dict):
            pid = ((d["ecs"].get("process") or {}) if isinstance(d["ecs"].get("process"), dict) else {}).get("pid")
        if pi:
            eid = pi.resolve(eid, pid, ts)
        if not eid:
            unattributed[aid] += 1
            continue
        etype = str(r.get("etype") or "")
        if _is_benign_noise(etype, d):
            continue
        summary = str(r.get("summary") or "")
        root = pi.lineage_root(eid) if pi else eid
        grouped[(aid, root, _signal_key(etype, summary, d))].append({
            "id": r.get("id"), "ts": r.get("ts"), "dt": ts, "etype": etype, "summary": summary,
            "severity": sev, "detail": d, "eid": eid,
        })

    per_proc: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(
        lambda: {"own": 0.0, "signals": [], "tactics": set()})
    for (aid, _root, key), items in grouped.items():
        items.sort(key=lambda x: x["dt"] or datetime.min, reverse=True)
        weights: Dict[str, float] = defaultdict(float)
        counts: Dict[str, int] = defaultdict(int)
        for it in items:
            counts[it["eid"]] += 1
        for i, it in enumerate(items[:REPEAT_CAP]):
            weights[it["eid"]] += SEV_BASE[it["severity"]] * _decay(it["dt"], now) * math.pow(0.5, i)
        head = items[0]
        for eid, n in counts.items():
            contrib = weights.get(eid, 0.0)
            mine = [it for it in items if it["eid"] == eid]
            tac, tech = _tactic_of(mine[0]["summary"], mine[0]["etype"], mine[0]["detail"])
            slot = per_proc[(aid, eid)]
            slot["own"] += contrib
            if tac:
                slot["tactics"].add(tac)
            d0 = mine[0]["detail"] if isinstance(mine[0].get("detail"), dict) else {}
            extra = _signal_extra(d0)
            slot["signals"].append({
                "key": key, "title": mine[0]["summary"], "etype": head["etype"], "severity": mine[0]["severity"],
                "tactic": tac, "technique": tech, "count": n, "score": round(contrib, 1),
                "first_ts": mine[-1]["ts"], "last_ts": mine[0]["ts"], "timeline_id": mine[0]["id"],
                "entity_id": eid,
                **extra,
            })
    return per_proc, hosts, unattributed


def _signal_extra(d: Dict[str, Any]) -> Dict[str, Any]:
    """从时间线 detail 里抽出可展示的命令/目标，给节点详情和故事线用。"""
    out: Dict[str, Any] = {}
    cmd = str(d.get("command_line") or d.get("command") or d.get("cmdline") or "").strip()
    if cmd:
        out["command_line"] = cmd[:2000]
    path = str(d.get("path") or d.get("image") or d.get("Image") or "").strip()
    if path:
        out["path"] = path[:500]
    for k, aliases in (
        ("target", ("target", "target_name", "TargetImage", "target_process")),
        ("remote", ("remote_ip", "dest_ip", "dst_ip", "ip", "domain", "url", "dest_key", "remote_url")),
        ("user", ("user", "User", "account", "username")),
        ("signed", ("signed", "signature_status")),
        ("signer", ("signer", "company")),
        ("sha256", ("sha256", "hash")),
        ("md5", ("md5",)),
        ("local_path", ("local_path", "payload_path")),
        ("job_name", ("job_name",)),
    ):
        for a in aliases:
            v = d.get(a)
            if v is None and isinstance(d.get("ecs"), dict):
                continue
            s = str(v or "").strip()
            if s:
                out[k] = s[:300]
                break
    return out


def _proc_view(pi: Optional[_ProcIndex], eid: str, *, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    p = (pi.by_eid.get(eid) if pi else None) or {}
    parent_eid = str(p.get("parent_entity_id") or "").strip()
    parent = (pi.by_eid.get(parent_eid) if pi and parent_eid else None) or {}
    m = meta if isinstance(meta, dict) else {}
    path = str(p.get("path") or m.get("path") or "").strip()
    return {
        "entity_id": eid,
        "name": p.get("name") or m.get("name") or "",
        "pid": p.get("pid") if p.get("pid") not in (None, "") else m.get("pid"),
        "ppid": p.get("ppid"),
        "path": path,
        "command_line": str(p.get("command_line") or m.get("command_line") or "")[:2000],
        "user": p.get("user") or m.get("user") or "",
        "integrity": p.get("integrity") or m.get("integrity") or "",
        "elevated": p.get("elevated") or "",
        "signed": m.get("signed") or "",
        "signer": m.get("signer") or "",
        "sha256": m.get("sha256") or "",
        "md5": m.get("md5") or "",
        "company": m.get("company") or "",
        "parent_entity_id": parent_eid,
        "parent_name": parent.get("name") or "",
        "parent_pid": parent.get("pid"),
        "create_time": p.get("create_time") or "",
        "exit_time": p.get("exit_time") or "",
        "source": p.get("source") or "",
        "known": bool(p),
    }


def _recommend(band: str, root: Dict[str, Any], tactics: List[str]) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    if band in ("critical", "high") and root.get("pid") and root.get("known") and not root.get("exit_time"):
        recs.append({"action": "kill_process", "label": "结束进程树（需审批）",
                     "params": {"pid": root.get("pid"), "process_guid": root.get("entity_id"), "tree": True}})
    if band == "critical" or (band == "high" and {"command_and_control", "exfiltration", "lateral_movement"} & set(tactics)):
        recs.append({"action": "isolate_network", "label": "隔离主机网络（需审批）", "params": {}})
    if band in ("medium", "high", "critical"):
        recs.append({"action": "investigate", "label": "发起 AI 调查", "params": {}})
    return recs


def _aggregate(per_proc, idx, hosts, unattributed, *, min_score: float):
    lineages: Dict[Tuple[str, str], Dict[str, Any]] = {}
    propagated: Dict[Tuple[str, str], float] = defaultdict(float)
    for (aid, eid), slot in per_proc.items():
        pi = idx.get(aid)
        propagated[(aid, eid)] += slot["own"]
        if pi:
            for depth, anc in enumerate(pi.ancestors(eid, PROPAGATE_DEPTH), start=1):
                if pi.name(anc) in HUB_PROCESSES:
                    break
                propagated[(aid, anc)] += slot["own"] * math.pow(PROPAGATE_RATIO, depth)
        root = pi.lineage_root(eid) if pi else eid
        lin = lineages.setdefault((aid, root), {
            "agent_id": aid, "hostname": hosts.get(aid, ""), "root_entity_id": root,
            "base": 0.0, "tactics": set(), "members": set(), "signals": [],
        })
        lin["base"] += slot["own"]
        lin["tactics"] |= slot["tactics"]
        lin["members"].add(eid)
        lin["signals"].extend(slot["signals"])

    out: List[Dict[str, Any]] = []
    for (aid, root), lin in lineages.items():
        tactics = sorted(lin["tactics"])
        bonus = CROSS_TACTIC_BONUS * max(0, len(tactics) - 1)
        for combo, add in COMBO_BONUS:
            if combo <= lin["tactics"]:
                bonus += add
        score = lin["base"] + bonus
        if score < min_score:
            continue
        pi = idx.get(aid)
        band = _band(score)
        root_view = _proc_view(pi, root)
        sigs = sorted(lin["signals"], key=lambda s: -s["score"])
        ts_all = [s["last_ts"] for s in sigs if s.get("last_ts")] + [s["first_ts"] for s in sigs if s.get("first_ts")]
        out.append({
            "agent_id": aid,
            "hostname": lin["hostname"],
            "root": root_view,
            "score": round(score, 1),
            "base_score": round(lin["base"], 1),
            "bonus": round(bonus, 1),
            "severity": band,
            "tactics": tactics,
            "tactic_names": [dict(agent_edr._ATTCK_TACTICS).get(t, t) for t in tactics],
            "member_count": len(lin["members"]),
            "signal_count": sum(s["count"] for s in sigs),
            "top_signals": sigs[:8],
            "first_ts": min(ts_all) if ts_all else "",
            "last_ts": max(ts_all) if ts_all else "",
            "root_propagated": round(propagated.get((aid, root), 0.0), 1),
            "unattributed_host_signals": unattributed.get(aid, 0),
            "recommended": _recommend(band, root_view, tactics),
        })
    out.sort(key=lambda x: (-x["score"], x["hostname"]))
    return out, propagated, lineages


def list_lineage_risk(*, agent_id: str = "", hours: int = 24, limit: int = 50,
                      min_score: float = 20.0, row_limit: int = 20000) -> Dict[str, Any]:
    hours = max(1, min(int(hours or 24), 24 * 14))
    now = datetime.now()
    since = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    rows, idx = _load(str(agent_id or "").strip(), since, row_limit)
    per_proc, hosts, unattributed = _score_signals(rows, idx, now)
    items, _, _ = _aggregate(per_proc, idx, hosts, unattributed, min_score=float(min_score))
    stats = {b: 0 for b in ("critical", "high", "medium", "low")}
    for it in items:
        stats[it["severity"]] += 1
    return {
        "ok": True,
        "since": since,
        "hours": hours,
        "scanned_signals": len(rows),
        "stats": stats,
        "items": items[: max(1, min(int(limit or 50), 300))],
        "params": {"half_life_hours": HALF_LIFE_HOURS, "propagate_ratio": PROPAGATE_RATIO,
                   "propagate_depth": PROPAGATE_DEPTH, "cross_tactic_bonus": CROSS_TACTIC_BONUS},
    }


def lineage_detail(agent_id: str, root_entity_id: str, *, hours: int = 24) -> Dict[str, Any]:
    aid = str(agent_id or "").strip()
    root = str(root_entity_id or "").strip()
    if not aid or not root:
        return {"ok": False, "error": "缺少 agent_id 或 root_entity_id"}
    hours = max(1, min(int(hours or 24), 24 * 14))
    now = datetime.now()
    since = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    rows, idx = _load(aid, since, 20000)
    per_proc, hosts, unattributed = _score_signals(rows, idx, now)
    items, propagated, lineages = _aggregate(per_proc, idx, hosts, unattributed, min_score=0.0)
    summary = next((x for x in items if x["root"]["entity_id"] == root), None)
    lin = lineages.get((aid, root))
    if not summary or not lin:
        return {"ok": False, "error": "该血缘在时间窗内无信号"}
    pi = idx.get(aid)

    member_set = set(lin["members"])
    # 补齐成员到根之间的中间节点，保证树连通
    for m in list(member_set):
        if not pi:
            break
        for a in pi.ancestors(m):
            member_set.add(a)
            if a == root:
                break
    # 从信号 detail 汇总每个实体的签名/哈希/路径补充
    meta_by_eid: Dict[str, Dict[str, Any]] = defaultdict(dict)
    for s in lin.get("signals") or []:
        eid = str(s.get("entity_id") or "")
        if not eid:
            continue
        slot = meta_by_eid[eid]
        for k in ("path", "command_line", "user", "signed", "signer", "sha256", "md5", "company", "local_path", "job_name", "remote"):
            if s.get(k) and not slot.get(k):
                slot[k] = s.get(k)
    # 进程快照补签名/哈希（agent_processes 本身不含这些字段）
    snap_items: List[Any] = []
    try:
        from . import agent_protocol as ap
        snap = ap.get_snapshot(aid, "process") or {}
        item = snap.get("item") if isinstance(snap.get("item"), dict) else snap
        snap_items = (item or {}).get("items") or snap.get("items") or []
    except Exception:
        snap_items = []
    if not isinstance(snap_items, list):
        snap_items = []
    snap_by_pid: Dict[int, Dict[str, Any]] = {}
    snap_by_name: Dict[str, Dict[str, Any]] = {}
    for it in snap_items:
        if not isinstance(it, dict):
            continue
        try:
            pid_i = int(it.get("pid") or 0)
            if pid_i:
                snap_by_pid[pid_i] = it
        except (TypeError, ValueError):
            pass
        nm = str(it.get("name") or "").lower()
        if nm and nm not in snap_by_name:
            snap_by_name[nm] = it

    nodes = []
    for eid in member_set:
        base_meta = dict(meta_by_eid.get(eid) or {})
        view = _proc_view(pi, eid, meta=base_meta)
        # 用快照补齐签名/哈希/路径
        hit = None
        try:
            if view.get("pid") is not None:
                hit = snap_by_pid.get(int(view["pid"]))
        except (TypeError, ValueError):
            hit = None
        if not hit and view.get("name"):
            hit = snap_by_name.get(str(view["name"]).lower())
        if hit:
            if not view.get("path") and hit.get("path"):
                view["path"] = hit.get("path")
            if not view.get("command_line") and hit.get("command_line"):
                view["command_line"] = str(hit.get("command_line") or "")[:2000]
            for k in ("signed", "signer", "sha256", "md5", "company", "file_version", "ext", "size_kb", "size"):
                if hit.get(k) not in (None, "") and not view.get(k):
                    view[k] = hit.get(k)
            if hit.get("user") and not view.get("user"):
                view["user"] = hit.get("user")
        slot = per_proc.get((aid, eid))
        view.update({
            "own_score": round(slot["own"], 1) if slot else 0.0,
            "propagated_score": round(propagated.get((aid, eid), 0.0), 1),
            "tactics": sorted(slot["tactics"]) if slot else [],
            "is_root": eid == root,
            "has_signal": bool(slot),
        })
        nodes.append(view)
    ids = {n["entity_id"] for n in nodes}
    edges = [{"from": n["parent_entity_id"], "to": n["entity_id"]}
             for n in nodes if n["parent_entity_id"] in ids and n["entity_id"] != root]

    names = {n["entity_id"]: n["name"] for n in nodes}
    story = []
    for s in sorted(lin["signals"], key=lambda x: str(x.get("first_ts") or "")):
        s2 = dict(s)
        s2["process_name"] = names.get(s["entity_id"], "")
        s2["tactic_name"] = dict(agent_edr._ATTCK_TACTICS).get(s["tactic"], "未映射")
        story.append(s2)
    return {
        "ok": True,
        "summary": summary,
        "nodes": sorted(nodes, key=lambda n: str(n.get("create_time") or "")),
        "edges": edges,
        "storyline": story,
        "tactic_lanes": [{"id": t, "name": n} for t, n in agent_edr._ATTCK_TACTICS],
    }
