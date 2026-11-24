"""告警归并为案件：同主机短窗口内相关告警聚合。"""
from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any, Dict, List

from . import agent_edr

_lock = threading.RLock()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_cases (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    title TEXT DEFAULT '',
    status TEXT DEFAULT 'open',
    severity TEXT DEFAULT 'medium',
    event_ids_json TEXT DEFAULT '[]',
    summary TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cases_agent ON alert_cases(agent_id, status);
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def _conn():
    agent_edr.ensure()
    conn = agent_edr._connect()
    conn.executescript(_SCHEMA)
    return conn


def _sev_rank(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(s or "").lower(), 0)


def merge_open_alerts(agent_id: str = "", *, window_min: int = 60) -> Dict[str, Any]:
    """将近期 open 告警按主机归并为案件（已有未关闭案件则追加）。"""
    agent_edr.ensure()
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - max(10, window_min) * 60))
    with _lock:
        conn = _conn()
        try:
            clauses = ["status='open'", "created_at>=?"]
            args: List[Any] = [since]
            if agent_id:
                clauses.append("agent_id=?")
                args.append(agent_id)
            rows = [dict(r) for r in conn.execute(
                f"""SELECT id, agent_id, hostname, title, severity, module, created_at FROM agent_events
                    WHERE {' AND '.join(clauses)} ORDER BY created_at ASC LIMIT 2000""",
                args,
            ).fetchall()]

            by_agent: Dict[str, List[Dict[str, Any]]] = {}
            for r in rows:
                by_agent.setdefault(r["agent_id"], []).append(r)

            created = 0
            updated = 0
            for aid, evs in by_agent.items():
                case = conn.execute(
                    """SELECT * FROM alert_cases WHERE agent_id=? AND status='open'
                       ORDER BY updated_at DESC LIMIT 1""",
                    (aid,),
                ).fetchone()
                ids = [int(e["id"]) for e in evs]
                max_sev = max(evs, key=lambda x: _sev_rank(x.get("severity"))).get("severity") or "medium"
                title = f"{evs[0].get('hostname') or aid} 案件 · {len(evs)} 条告警"
                summary = "；".join(str(e.get("title") or "")[:80] for e in evs[-5:])
                now = _now()
                if case:
                    try:
                        old_ids = json.loads(case["event_ids_json"] or "[]")
                    except Exception:
                        old_ids = []
                    merged = sorted(set(int(x) for x in old_ids) | set(ids))
                    sev = case["severity"]
                    if _sev_rank(max_sev) > _sev_rank(sev):
                        sev = max_sev
                    conn.execute(
                        """UPDATE alert_cases SET event_ids_json=?, severity=?, summary=?, title=?, updated_at=?
                           WHERE id=?""",
                        (json.dumps(merged), sev, summary[:1000], title[:200], now, case["id"]),
                    )
                    updated += 1
                else:
                    cid = uuid.uuid4().hex
                    conn.execute(
                        """INSERT INTO alert_cases(id, agent_id, hostname, title, status, severity,
                           event_ids_json, summary, created_at, updated_at)
                           VALUES(?,?,?,?, 'open', ?, ?, ?, ?, ?)""",
                        (cid, aid, evs[0].get("hostname") or "", title[:200], max_sev,
                         json.dumps(ids), summary[:1000], now, now),
                    )
                    created += 1
            conn.commit()
            return {"ok": True, "created": created, "updated": updated, "alerts": len(rows)}
        finally:
            conn.close()


def list_cases(*, status: str = "open", agent_id: str = "", limit: int = 50) -> Dict[str, Any]:
    with _lock:
        conn = _conn()
        try:
            clauses = ["1=1"]
            args: List[Any] = []
            if status:
                clauses.append("status=?")
                args.append(status)
            if agent_id:
                clauses.append("agent_id=?")
                args.append(agent_id)
            args.append(max(1, min(limit, 200)))
            rows = conn.execute(
                f"SELECT * FROM alert_cases WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC LIMIT ?",
                args,
            ).fetchall()
            return {"ok": True, "items": [dict(r) for r in rows]}
        finally:
            conn.close()


def set_case_status(case_id: str, status: str, *, note: str = "") -> Dict[str, Any]:
    st = str(status or "").strip().lower()
    if st not in ("open", "closed", "investigating"):
        return {"ok": False, "error": "无效状态"}
    with _lock:
        conn = _conn()
        try:
            conn.execute(
                "UPDATE alert_cases SET status=?, summary=CASE WHEN ?<>'' THEN summary||'\n'||? ELSE summary END, updated_at=? WHERE id=?",
                (st, note, note[:300], _now(), case_id),
            )
            conn.commit()
            return {"ok": True, "id": case_id, "status": st}
        finally:
            conn.close()
