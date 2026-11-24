# -*- coding: utf-8 -*-
"""持久化 ES 事件索引队列：替代一次性 daemon Thread，支持中断恢复与去重。"""
from __future__ import annotations

import json
import hashlib
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from . import config

_LOCK = threading.RLock()
_WORKER: Optional[threading.Thread] = None
_STOP = threading.Event()
_DB = "es_event_queue.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS es_queue (
    id TEXT PRIMARY KEY,
    event_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    last_error TEXT DEFAULT '',
    created_at REAL,
    updated_at REAL
);
CREATE INDEX IF NOT EXISTS idx_es_queue_status ON es_queue(status, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_es_queue_event_key ON es_queue(event_key);
"""


def _path() -> Path:
    return Path(config.DATA_ROOT) / _DB


def ensure_transactional_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA.split(";"):
        if statement.strip():
            conn.execute(statement)


def _connect(*, transactional: bool = False) -> sqlite3.Connection:
    if transactional:
        from .agent_protocol import db_path
        p = db_path()
    else:
        p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=30)
    conn.row_factory = sqlite3.Row
    if not transactional:
        ensure_transactional_schema(conn)
        conn.commit()
    return conn


def _event_key(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def enqueue_timeline_event(*, conn=None, source_id: str = "", **kwargs: Any) -> str:
    """入队一条时间线事件；已存在相同 event_key 且未失败终态则复用。"""
    payload = {
        "agent_id": kwargs.get("agent_id") or "",
        "hostname": kwargs.get("hostname") or "",
        "etype": kwargs.get("etype") or "",
        "summary": kwargs.get("summary") or "",
        "detail": kwargs.get("detail") if isinstance(kwargs.get("detail"), dict) else {},
        "ts": kwargs.get("ts") or "",
    }
    key = _event_key({**payload, "source_id": source_id})
    now = time.time()
    if conn is not None:
        # Shares the business transaction and its savepoints, including Agent v2 receipts.
        conn.execute(
            """INSERT OR IGNORE INTO es_queue(id,event_key,payload_json,attempts,status,created_at,updated_at)
               VALUES(?,?,?,0,'pending',?,?)""",
            (key, key, json.dumps(payload, ensure_ascii=False), now, now),
        )
        return key
    eid = ""
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT id, status FROM es_queue WHERE event_key=?", (key,)
            ).fetchone()
            if row and row["status"] in ("pending", "done", "active"):
                eid = str(row["id"])
            else:
                eid = uuid.uuid4().hex
                conn.execute(
                    """INSERT INTO es_queue(id, event_key, payload_json, attempts, status, created_at, updated_at)
                       VALUES(?,?,?,0,'pending',?,?)
                       ON CONFLICT(event_key) DO UPDATE SET
                         payload_json=excluded.payload_json,
                         status='pending',
                         updated_at=excluded.updated_at,
                         last_error=''""",
                    (eid, key, json.dumps(payload, ensure_ascii=False), now, now),
                )
                conn.commit()
        finally:
            conn.close()
    _ensure_worker()
    return eid


def _ensure_worker() -> None:
    global _WORKER
    with _LOCK:
        if _WORKER and _WORKER.is_alive():
            return
        _STOP.clear()
        _WORKER = threading.Thread(target=_worker_loop, name="es-event-queue", daemon=True)
        _WORKER.start()


def start_worker() -> None:
    _ensure_worker()


def stop_worker() -> None:
    _STOP.set()


def _worker_loop() -> None:
    while not _STOP.is_set():
        try:
            did = _drain_once(limit=40, transactional=True)
            # Keep existing on-disk queue recoverable across the schema change.
            did = _drain_once(limit=40) or did
        except Exception as exc:
            print(f"[edr-es] queue worker: {type(exc).__name__}")
            did = False
        if not did:
            _STOP.wait(1.5)


def _drain_once(*, limit: int = 40, transactional: bool = False) -> bool:
    from . import elastic_detection_es as edes

    rows = []
    with _LOCK:
        conn = _connect(transactional=transactional)
        try:
            now = time.time()
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE es_queue SET status='pending' WHERE status='active' AND updated_at<?", (now-300,))
            rows = conn.execute(
                """SELECT id, event_key, payload_json, attempts FROM es_queue
                   WHERE status='pending' AND (attempts=0 OR updated_at<=?)
                   ORDER BY created_at ASC LIMIT ?""",
                (now, max(1, min(limit, 100))),
            ).fetchall()
            rows = [dict(r) for r in rows]
            for r in rows:
                r["claim_at"] = time.time()
                conn.execute(
                    "UPDATE es_queue SET status='active', updated_at=? WHERE id=? AND status='pending'",
                    (r["claim_at"], r["id"]),
                )
            conn.commit()
        finally:
            conn.close()
    if not rows:
        return False

    requests = []
    for r in rows:
        try:
            payload = json.loads(r["payload_json"] or "{}")
        except Exception:
            continue
        requests.append((hashlib.sha256(str(r["event_key"]).encode()).hexdigest(), payload))
    try:
        results = edes.index_timeline_batch(requests)
    except Exception:
        results = {}
    for r in rows:
        key = hashlib.sha256(str(r["event_key"]).encode()).hexdigest()
        ok = results.get(key, False)
        with _LOCK:
            conn = _connect(transactional=transactional)
            try:
                if ok:
                    conn.execute(
                        "UPDATE es_queue SET status='done', attempts=attempts+1, last_error='', updated_at=? WHERE id=? AND status='active' AND updated_at=?",
                        (time.time(), r["id"], r["claim_at"]),
                    )
                else:
                    conn.execute(
                        """UPDATE es_queue SET status='pending', attempts=attempts+1, last_error=?, updated_at=?
                           WHERE id=? AND status='active' AND updated_at=?""",
                        ("index unavailable or rejected", time.time() + min(300, 2 ** min(r["attempts"] + 1, 8)), r["id"], r["claim_at"]),
                    )
                conn.commit()
            finally:
                conn.close()
    return True


def queue_stats(*, transactional: bool = False) -> Dict[str, Any]:
    with _LOCK:
        conn = _connect(transactional=transactional)
        try:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM es_queue GROUP BY status"
            ).fetchall()
            return {"ok": True, "counts": {str(r["status"]): int(r["n"]) for r in rows}}
        finally:
            conn.close()
