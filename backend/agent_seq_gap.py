"""Agent 时间线 agent_seq 缺口检测。"""
from __future__ import annotations

import json
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

_lock = threading.Lock()
_last: Dict[str, int] = {}
_last_emit: Dict[str, float] = {}


def note_and_gaps(agent_id: str, events: List[Dict[str, Any]]) -> List[int]:
    """更新该 Agent 最近序号，返回本批中检测到的缺口序号。"""
    agent_id = str(agent_id or "").strip()
    if not agent_id or not events:
        return []
    seqs: List[int] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        v = ev.get("agent_seq")
        try:
            n = int(v)
        except Exception:
            continue
        if n > 0:
            seqs.append(n)
    if not seqs:
        return []
    gaps: List[int] = []
    with _lock:
        prev = _last.get(agent_id)
        for n in seqs:
            if prev is not None and n > prev + 1:
                for g in range(prev + 1, n):
                    gaps.append(g)
                    if len(gaps) >= 32:
                        break
            if prev is None or n > prev:
                prev = n
        if prev is not None:
            _last[agent_id] = prev
    return gaps


def maybe_emit_gap_event(conn, agent_id: str, hostname: str, gaps: List[int]) -> int:
    if not gaps:
        return 0
    import time
    now_m = time.monotonic()
    with _lock:
        if now_m - _last_emit.get(agent_id, 0) < 300:
            return 0
        _last_emit[agent_id] = now_m
    title = f"Agent 事件序号缺口: 缺失 {len(gaps)} 个（例 {gaps[0]}…）"
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    detail = json.dumps({
        "gaps": gaps[:32], "gap_count": len(gaps),
        "source": "agent_seq_gap", "evidence": "上报事件 agent_seq 不连续",
    }, ensure_ascii=False)
    exists = conn.execute(
        """SELECT 1 FROM agent_events WHERE agent_id=? AND title=? AND status='open'
           AND created_at>=datetime('now','-1 hours') LIMIT 1""",
        (agent_id, title),
    ).fetchone()
    if exists:
        return 0
    conn.execute(
        """INSERT INTO agent_events(agent_id, hostname, severity, title, detail, module, status,
                                    hit_count, created_at, updated_at)
           VALUES(?,?,?,?,?,?, 'open', 1, ?, ?)""",
        (agent_id, hostname or "", "medium", title, detail, "agent_integrity", now, now),
    )
    # 同步写入时间线便于狩猎
    conn.execute(
        """INSERT INTO agent_timeline(agent_id, hostname, etype, summary, detail_json, severity, ts, created_at, entity_id)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (agent_id, hostname or "", "agent_seq_gap", title, detail, "medium", now, now, ""),
    )
    return 1
