"""Presentation helpers for building ATT&CK incident story lanes."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple


_ATTCK_TACTICS = [
    ("initial_access", "初始访问"),
    ("execution", "执行"),
    ("persistence", "持久化"),
    ("privilege_escalation", "权限提升"),
    ("defense_evasion", "防御绕过"),
    ("credential_access", "凭证访问"),
    ("discovery", "发现"),
    ("lateral_movement", "横向移动"),
    ("collection", "收集"),
    ("command_and_control", "命令与控制"),
    ("exfiltration", "数据渗出"),
    ("impact", "影响"),
]


def _story_process_name(detail: Any, title: str = "") -> str:
    d = detail if isinstance(detail, dict) else {}
    if not d and isinstance(detail, str):
        try:
            d = json.loads(detail or "{}")
        except Exception:
            d = {}
    for k in ("process_name", "name", "host_process", "Image", "image"):
        v = str(d.get(k) or "").strip()
        if v:
            base = v.replace("/", "\\").rsplit("\\", 1)[-1]
            return base or v
    # 标题里常见「进程名: xxx」
    t = str(title or "")
    for sep in ("：", ": ", "→"):
        if sep in t:
            frag = t.split(sep, 1)[-1].strip()
            if frag and len(frag) < 80 and " " not in frag[:20]:
                return frag.replace("/", "\\").rsplit("\\", 1)[-1]
    return ""


def _build_story_lanes(nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """把故事节点投影到 ATT&CK 战术泳道（时间横轴 × 战术纵轴）。"""
    tactic_names = dict(_ATTCK_TACTICS)
    order = [t[0] for t in _ATTCK_TACTICS]
    # 泳道图优先保留有战术映射或中高危节点，避免 info 噪声铺满
    ranked = []
    for i, n in enumerate(nodes):
        sev = str(n.get("severity") or "").lower()
        tac = str(n.get("tactic") or "").strip()
        if tac in tactic_names or sev in ("medium", "high", "critical") or n.get("kind") == "threat":
            ranked.append((i, n))
    if not ranked:
        ranked = list(enumerate(nodes))
    # 同战术+同标题折叠，保留首末时间
    collapsed: List[Dict[str, Any]] = []
    key_idx: Dict[Tuple[str, str], int] = {}
    for src_i, n in ranked:
        tac = str(n.get("tactic") or "").strip() or "unmapped"
        title = str(n.get("title") or "")[:120]
        key = (tac, title)
        if key in key_idx:
            cur = collapsed[key_idx[key]]
            cur["count"] = int(cur.get("count") or 1) + 1
            if str(n.get("ts") or "") > str(cur.get("ts") or ""):
                cur["ts"] = n.get("ts")
                cur["severity"] = n.get("severity") or cur.get("severity")
            continue
        key_idx[key] = len(collapsed)
        pn = n.get("process_name") or _story_process_name(n.get("detail"), title)
        collapsed.append({
            "id": f"sn-{len(collapsed)}",
            "kind": n.get("kind"),
            "ts": n.get("ts"),
            "title": title,
            "severity": n.get("severity"),
            "etype": n.get("etype"),
            "module": n.get("module"),
            "technique": n.get("technique"),
            "technique_label": n.get("technique_label"),
            "tactic": tac if tac in tactic_names else "unmapped",
            "tactic_name": tactic_names.get(tac, "未映射"),
            "process_name": pn,
            "event_id": n.get("id"),
            "count": 1,
            "src_index": src_i,
        })
    # 控制节点数量
    if len(collapsed) > 48:
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        collapsed.sort(key=lambda x: (
            sev_rank.get(str(x.get("severity") or "").lower(), 5),
            str(x.get("ts") or ""),
        ))
        collapsed = collapsed[:48]
    collapsed.sort(key=lambda x: str(x.get("ts") or ""))
    for i, n in enumerate(collapsed):
        n["seq"] = i
        n["id"] = f"sn-{i}"

    used = []
    for tid in order:
        if any(n["tactic"] == tid for n in collapsed):
            used.append({"id": tid, "name": tactic_names[tid]})
    if any(n["tactic"] == "unmapped" for n in collapsed):
        used.append({"id": "unmapped", "name": "未映射"})
    lane_of = {L["id"]: i for i, L in enumerate(used)}
    for n in collapsed:
        n["lane"] = lane_of.get(n["tactic"], len(used) - 1)

    edges = []
    for i in range(1, len(collapsed)):
        a, b = collapsed[i - 1], collapsed[i]
        edges.append({
            "from": a["id"], "to": b["id"],
            "same_process": bool(a.get("process_name") and a.get("process_name") == b.get("process_name")),
            "cross_tactic": a.get("tactic") != b.get("tactic"),
        })
    return {"lanes": used, "lane_nodes": collapsed, "lane_edges": edges}
