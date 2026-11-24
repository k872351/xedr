"""每日持久化快照对比（服务/计划任务/启动项）+ 可选 AI 解释入口。"""
from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any, Dict, List, Set

from . import agent_edr

_lock = threading.RLock()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS persist_daily_snap (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    day TEXT NOT NULL,
    services_json TEXT DEFAULT '[]',
    tasks_json TEXT DEFAULT '[]',
    startup_json TEXT DEFAULT '[]',
    created_at TEXT DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_persist_daily_agent_day ON persist_daily_snap(agent_id, day);
CREATE TABLE IF NOT EXISTS persist_daily_diff (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    day TEXT NOT NULL,
    diff_json TEXT DEFAULT '{}',
    ai_note TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def _day() -> str:
    return time.strftime("%Y-%m-%d", time.localtime())


def _conn():
    agent_edr.ensure()
    conn = agent_edr._connect()
    conn.executescript(_SCHEMA)
    return conn


def _snap_module(conn, agent_id: str, module: str) -> List[Any]:
    row = conn.execute(
        """SELECT payload_json FROM agent_snapshots
           WHERE agent_id=? AND module=? ORDER BY collected_at DESC LIMIT 1""",
        (agent_id, module),
    ).fetchone()
    if not row:
        return []
    try:
        data = json.loads(row["payload_json"] or "[]")
    except Exception:
        return []
    return data if isinstance(data, list) else []


def _keys(items: List[Any], fields: List[str]) -> Set[str]:
    out: Set[str] = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        for f in fields:
            v = str(it.get(f) or "").strip().lower()
            if v:
                out.add(v)
                break
    return out


def capture_and_diff(agent_id: str = "") -> Dict[str, Any]:
    agent_edr.ensure()
    day = _day()
    with _lock:
        conn = _conn()
        try:
            if agent_id:
                agents = [agent_id]
            else:
                agents = [r["agent_id"] for r in conn.execute("SELECT agent_id FROM agents").fetchall()]
            results = []
            for aid in agents:
                services = _snap_module(conn, aid, "services") or _snap_module(conn, aid, "service")
                tasks = _snap_module(conn, aid, "tasks") or _snap_module(conn, aid, "scheduled_tasks")
                startup = _snap_module(conn, aid, "startup") or _snap_module(conn, aid, "autoruns")
                sid = uuid.uuid4().hex
                conn.execute(
                    """INSERT INTO persist_daily_snap(id, agent_id, day, services_json, tasks_json, startup_json, created_at)
                       VALUES(?,?,?,?,?,?,?)
                       ON CONFLICT(agent_id, day) DO UPDATE SET
                         services_json=excluded.services_json, tasks_json=excluded.tasks_json,
                         startup_json=excluded.startup_json, created_at=excluded.created_at""",
                    (sid, aid, day, json.dumps(services, ensure_ascii=False),
                     json.dumps(tasks, ensure_ascii=False), json.dumps(startup, ensure_ascii=False), _now()),
                )
                prev = conn.execute(
                    """SELECT * FROM persist_daily_snap WHERE agent_id=? AND day<? ORDER BY day DESC LIMIT 1""",
                    (aid, day),
                ).fetchone()
                diff: Dict[str, Any] = {"added": {}, "removed": {}}
                if prev:
                    try:
                        ps = json.loads(prev["services_json"] or "[]")
                        pt = json.loads(prev["tasks_json"] or "[]")
                        pu = json.loads(prev["startup_json"] or "[]")
                    except Exception:
                        ps, pt, pu = [], [], []
                    for kind, cur, old, fields in (
                        ("services", services, ps, ["name", "service_name", "display_name"]),
                        ("tasks", tasks, pt, ["name", "task_name", "path"]),
                        ("startup", startup, pu, ["name", "command", "path"]),
                    ):
                        ck, ok = _keys(cur, fields), _keys(old, fields)
                        diff["added"][kind] = sorted(ck - ok)[:50]
                        diff["removed"][kind] = sorted(ok - ck)[:50]
                    has = any(diff["added"].get(k) or diff["removed"].get(k) for k in ("services", "tasks", "startup"))
                    if has:
                        did = uuid.uuid4().hex
                        conn.execute(
                            """INSERT INTO persist_daily_diff(id, agent_id, day, diff_json, created_at)
                               VALUES(?,?,?,?,?)""",
                            (did, aid, day, json.dumps(diff, ensure_ascii=False), _now()),
                        )
                        results.append({"agent_id": aid, "diff_id": did, "diff": diff})
            conn.commit()
            return {"ok": True, "day": day, "diffs": results, "agents": len(agents)}
        finally:
            conn.close()


def explain_diff(diff_id: str) -> Dict[str, Any]:
    """生成简短中文解释（规则模板；有 AI 时可再润色）。"""
    with _lock:
        conn = _conn()
        try:
            row = conn.execute("SELECT * FROM persist_daily_diff WHERE id=?", (diff_id,)).fetchone()
            if not row:
                return {"ok": False, "error": "diff 不存在"}
            diff = json.loads(row["diff_json"] or "{}")
        finally:
            conn.close()
    parts = []
    for kind, label in (("services", "服务"), ("tasks", "计划任务"), ("startup", "启动项")):
        add = (diff.get("added") or {}).get(kind) or []
        rem = (diff.get("removed") or {}).get(kind) or []
        if add:
            parts.append(f"新增{label}：{', '.join(add[:8])}")
        if rem:
            parts.append(f"消失{label}：{', '.join(rem[:8])}")
    note = "；".join(parts) or "无明显变化"
    # 尝试 AI 润色（可选）
    try:
        from .ai import analyzer
        if hasattr(analyzer, "quick_explain"):
            note2 = analyzer.quick_explain("解释主机持久化日变化：\n" + note)
            if note2:
                note = str(note2)[:800]
    except Exception:
        pass
    with _lock:
        conn = _conn()
        try:
            conn.execute("UPDATE persist_daily_diff SET ai_note=? WHERE id=?", (note, diff_id))
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "id": diff_id, "ai_note": note, "diff": diff}
