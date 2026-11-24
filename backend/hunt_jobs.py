"""定时狩猎 + 调查包导出。"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional

from . import agent_edr

_lock = threading.RLock()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS hunt_jobs (
    id TEXT PRIMARY KEY,
    name TEXT DEFAULT '',
    query TEXT NOT NULL,
    cron_min INTEGER DEFAULT 60,
    enabled INTEGER DEFAULT 1,
    last_run_at TEXT DEFAULT '',
    last_hits INTEGER DEFAULT 0,
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS hunt_job_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    started_at TEXT DEFAULT '',
    finished_at TEXT DEFAULT '',
    hit_count INTEGER DEFAULT 0,
    result_json TEXT DEFAULT ''
);
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def _conn():
    agent_edr.ensure()
    conn = agent_edr._connect()
    conn.executescript(_SCHEMA)
    return conn


def upsert_job(*, name: str, query: str, cron_min: int = 60, enabled: bool = True, actor: str = "", job_id: str = "") -> Dict[str, Any]:
    q = str(query or "").strip()
    if len(q) < 2:
        return {"ok": False, "error": "query 太短"}
    jid = str(job_id or "").strip() or uuid.uuid4().hex
    now = _now()
    with _lock:
        conn = _conn()
        try:
            conn.execute(
                """INSERT INTO hunt_jobs(id, name, query, cron_min, enabled, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET name=excluded.name, query=excluded.query,
                     cron_min=excluded.cron_min, enabled=excluded.enabled, updated_at=excluded.updated_at""",
                (jid, str(name or q)[:120], q, max(5, min(int(cron_min or 60), 10080)),
                 1 if enabled else 0, str(actor or "")[:64], now, now),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "id": jid}


def list_jobs(limit: int = 50) -> Dict[str, Any]:
    with _lock:
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT * FROM hunt_jobs ORDER BY updated_at DESC LIMIT ?",
                (max(1, min(limit, 200)),),
            ).fetchall()
            return {"ok": True, "items": [dict(r) for r in rows]}
        finally:
            conn.close()


def run_job(job_id: str) -> Dict[str, Any]:
    with _lock:
        conn = _conn()
        try:
            row = conn.execute("SELECT * FROM hunt_jobs WHERE id=?", (job_id,)).fetchone()
            if not row:
                return {"ok": False, "error": "任务不存在"}
            job = dict(row)
        finally:
            conn.close()
    started = _now()
    pack = agent_edr.hunt(job["query"], limit=200)
    hits = pack.get("hits") or []
    rid = uuid.uuid4().hex
    finished = _now()
    with _lock:
        conn = _conn()
        try:
            conn.execute(
                """INSERT INTO hunt_job_runs(id, job_id, started_at, finished_at, hit_count, result_json)
                   VALUES(?,?,?,?,?,?)""",
                (rid, job_id, started, finished, len(hits), json.dumps({"hits": hits[:100]}, ensure_ascii=False)),
            )
            conn.execute(
                "UPDATE hunt_jobs SET last_run_at=?, last_hits=?, updated_at=? WHERE id=?",
                (finished, len(hits), finished, job_id),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "run_id": rid, "hit_count": len(hits), "hits": hits[:50]}


def tick_due_jobs() -> Dict[str, Any]:
    """扫描到期任务并执行（可由后台定时调用）。"""
    now = time.time()
    ran = []
    with _lock:
        conn = _conn()
        try:
            rows = [dict(r) for r in conn.execute("SELECT * FROM hunt_jobs WHERE enabled=1").fetchall()]
        finally:
            conn.close()
    for j in rows:
        last = j.get("last_run_at") or ""
        interval = max(5, int(j.get("cron_min") or 60)) * 60
        due = True
        if last:
            try:
                ts = time.mktime(time.strptime(last[:19], "%Y-%m-%dT%H:%M:%S"))
                due = now - ts >= interval
            except Exception:
                due = True
        if due:
            out = run_job(j["id"])
            ran.append({"id": j["id"], "hits": out.get("hit_count"), "ok": out.get("ok")})
    return {"ok": True, "ran": ran}


def build_investigation_pack(agent_id: str, *, hours: int = 24, event_id: int = 0) -> Dict[str, Any]:
    """打包主机近期时间线/告警/进程为 zip 调查包。"""
    agent_edr.ensure()
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - max(1, hours) * 3600))
    try:
        from . import agent_protocol
        base = os.path.dirname(str(agent_protocol.db_path()))
    except Exception:
        base = "data"
    out_dir = os.path.join(base, "invest_packs")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = os.path.join(out_dir, f"invest_{aid[:12]}_{stamp}.zip")

    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            tl = [dict(r) for r in conn.execute(
                """SELECT id, etype, summary, detail_json, severity, ts FROM agent_timeline
                   WHERE agent_id=? AND ts>=? ORDER BY ts DESC LIMIT 3000""",
                (aid, since),
            ).fetchall()]
            evs = [dict(r) for r in conn.execute(
                """SELECT id, title, detail, module, severity, status, created_at FROM agent_events
                   WHERE agent_id=? AND created_at>=? ORDER BY id DESC LIMIT 500""",
                (aid, since),
            ).fetchall()]
            procs = [dict(r) for r in conn.execute(
                """SELECT entity_id, pid, name, path, command_line, user, start_ts, exit_ts
                   FROM agent_processes WHERE agent_id=? ORDER BY start_ts DESC LIMIT 800""",
                (aid,),
            ).fetchall()]
            host = conn.execute("SELECT * FROM agents WHERE agent_id=?", (aid,)).fetchone()
        finally:
            conn.close()

    meta = {
        "agent_id": aid,
        "hostname": dict(host).get("hostname") if host else "",
        "hours": hours, "event_id": event_id,
        "generated_at": _now(),
        "counts": {"timeline": len(tl), "events": len(evs), "processes": len(procs)},
    }
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("meta.json", json.dumps(meta, ensure_ascii=False, indent=2))
        zf.writestr("timeline.json", json.dumps(tl, ensure_ascii=False))
        zf.writestr("events.json", json.dumps(evs, ensure_ascii=False))
        zf.writestr("processes.json", json.dumps(procs, ensure_ascii=False))
    return {"ok": True, "path": zip_path, "meta": meta}
