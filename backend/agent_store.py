# -*- coding: utf-8 -*-
"""Agent 事件/时间线规模化存储：MySQL 双写（热表）+ SQLite 保留期清理。"""
from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List

_lock = threading.RLock()
_tables_ready = False

TIMELINE_TABLE = "agent_timeline_hot"
EVENTS_TABLE = "agent_events_hot"
AGENTS_TABLE = "agents_hot"
COMMANDS_TABLE = "agent_commands_hot"

_SCHEMA = [
    f"""CREATE TABLE IF NOT EXISTS {TIMELINE_TABLE} (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    hostname VARCHAR(128) DEFAULT '',
    etype VARCHAR(64) DEFAULT '',
    summary VARCHAR(512) DEFAULT '',
    detail_json MEDIUMTEXT,
    severity VARCHAR(16) DEFAULT 'info',
    ts VARCHAR(32) DEFAULT '',
    created_at VARCHAR(32) DEFAULT '',
    KEY idx_tl_agent_ts (agent_id, ts),
    KEY idx_tl_etype (etype),
    KEY idx_tl_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    f"""CREATE TABLE IF NOT EXISTS {EVENTS_TABLE} (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    local_id BIGINT DEFAULT 0,
    agent_id VARCHAR(64) NOT NULL,
    hostname VARCHAR(128) DEFAULT '',
    severity VARCHAR(16) DEFAULT 'medium',
    title VARCHAR(256) DEFAULT '',
    detail MEDIUMTEXT,
    module VARCHAR(32) DEFAULT '',
    status VARCHAR(16) DEFAULT 'open',
    created_at VARCHAR(32) DEFAULT '',
    updated_at VARCHAR(32) DEFAULT '',
    KEY idx_ev_agent (agent_id),
    KEY idx_ev_sev (severity),
    KEY idx_ev_created (created_at),
    KEY idx_ev_local (local_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    # 多实例起步：agents / commands 双写热表（SQLite 仍为主路径，MySQL 供其他节点可见）
    f"""CREATE TABLE IF NOT EXISTS {AGENTS_TABLE} (
    agent_id VARCHAR(64) NOT NULL PRIMARY KEY,
    hostname VARCHAR(128) DEFAULT '',
    os_family VARCHAR(32) DEFAULT '',
    ip VARCHAR(64) DEFAULT '',
    version VARCHAR(64) DEFAULT '',
    status VARCHAR(16) DEFAULT 'offline',
    last_seen VARCHAR(32) DEFAULT '',
    health_json MEDIUMTEXT,
    health_at VARCHAR(32) DEFAULT '',
    capabilities_json TEXT,
    meta_json TEXT,
    updated_at VARCHAR(32) DEFAULT '',
    KEY idx_agents_seen (last_seen),
    KEY idx_agents_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    f"""CREATE TABLE IF NOT EXISTS {COMMANDS_TABLE} (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) DEFAULT '',
    params_json MEDIUMTEXT,
    status VARCHAR(16) DEFAULT 'pending',
    result_json MEDIUMTEXT,
    created_by VARCHAR(64) DEFAULT '',
    created_at VARCHAR(32) DEFAULT '',
    updated_at VARCHAR(32) DEFAULT '',
    acked_at VARCHAR(32) DEFAULT '',
    deadline VARCHAR(32) DEFAULT '',
    idempotency_key VARCHAR(96) DEFAULT '',
    KEY idx_cmd_agent (agent_id),
    KEY idx_cmd_status (status),
    KEY idx_cmd_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]


def _mysql_ok() -> bool:
    try:
        from . import mysql_db
        return bool(mysql_db.mysql_ready())
    except Exception:
        return False


@contextmanager
def _mysql() -> Iterator[Any]:
    from . import mysql_db
    conn = mysql_db.connect_mysql()
    try:
        yield conn
    finally:
        mysql_db._pool_release(conn)


def ensure_mysql_tables() -> bool:
    global _tables_ready
    if _tables_ready:
        return True
    if not _mysql_ok():
        return False
    with _lock:
        if _tables_ready:
            return True
        try:
            with _mysql() as conn:
                cur = conn.cursor()
                for s in _SCHEMA:
                    cur.execute(s)
                conn.commit()
            _tables_ready = True
            return True
        except Exception:
            return False


def write_timeline_batch(rows: List[Dict[str, Any]]) -> int:
    """时间线双写 MySQL；失败忽略，不阻断 SQLite 主路径。"""
    if not rows or not retention_config().get("mysql_dual_write") or not ensure_mysql_tables():
        return 0
    data = []
    for r in rows[:500]:
        detail = r.get("detail_json")
        if isinstance(detail, (dict, list)):
            detail = json.dumps(detail, ensure_ascii=False)
        data.append((
            str(r.get("agent_id") or "")[:64],
            str(r.get("hostname") or "")[:128],
            str(r.get("etype") or "")[:64],
            str(r.get("summary") or "")[:512],
            str(detail or "")[:60000],
            str(r.get("severity") or "info")[:16],
            str(r.get("ts") or "")[:32],
            str(r.get("created_at") or "")[:32],
        ))
    try:
        with _mysql() as conn:
            cur = conn.cursor()
            cur.executemany(
                f"""INSERT INTO {TIMELINE_TABLE}
                    (agent_id, hostname, etype, summary, detail_json, severity, ts, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                data,
            )
            conn.commit()
        return len(data)
    except Exception:
        return 0


def write_event(row: Dict[str, Any]) -> bool:
    if not row or not retention_config().get("mysql_dual_write") or not ensure_mysql_tables():
        return False
    try:
        with _mysql() as conn:
            cur = conn.cursor()
            cur.execute(
                f"""INSERT INTO {EVENTS_TABLE}
                    (local_id, agent_id, hostname, severity, title, detail, module, status, created_at, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    int(row.get("id") or 0),
                    str(row.get("agent_id") or "")[:64],
                    str(row.get("hostname") or "")[:128],
                    str(row.get("severity") or "")[:16],
                    str(row.get("title") or "")[:256],
                    str(row.get("detail") or "")[:60000],
                    str(row.get("module") or "")[:32],
                    str(row.get("status") or "open")[:16],
                    str(row.get("created_at") or "")[:32],
                    str(row.get("updated_at") or "")[:32],
                ),
            )
            conn.commit()
        return True
    except Exception:
        return False


def write_agent(row: Dict[str, Any]) -> bool:
    """双写 Agent 注册/心跳状态到 MySQL（多实例可见起步）。失败不阻断 SQLite 主路径。"""
    if not row or not retention_config().get("mysql_dual_write") or not ensure_mysql_tables():
        return False
    aid = str(row.get("agent_id") or "").strip()[:64]
    if not aid:
        return False
    now = str(row.get("updated_at") or row.get("last_seen") or time.strftime("%Y-%m-%dT%H:%M:%S"))[:32]
    health = row.get("health_json")
    if isinstance(health, (dict, list)):
        health = json.dumps(health, ensure_ascii=False)
    caps = row.get("capabilities_json")
    if isinstance(caps, (dict, list)):
        caps = json.dumps(caps, ensure_ascii=False)
    meta = row.get("meta_json")
    if isinstance(meta, (dict, list)):
        meta = json.dumps(meta, ensure_ascii=False)
    try:
        with _mysql() as conn:
            cur = conn.cursor()
            cur.execute(
                f"""INSERT INTO {AGENTS_TABLE}
                    (agent_id, hostname, os_family, ip, version, status, last_seen,
                     health_json, health_at, capabilities_json, meta_json, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE
                      hostname=VALUES(hostname),
                      os_family=VALUES(os_family),
                      ip=IFNULL(NULLIF(VALUES(ip), ''), ip),
                      version=VALUES(version),
                      status=VALUES(status),
                      last_seen=VALUES(last_seen),
                      health_json=IFNULL(VALUES(health_json), health_json),
                      health_at=IFNULL(NULLIF(VALUES(health_at), ''), health_at),
                      capabilities_json=IFNULL(VALUES(capabilities_json), capabilities_json),
                      meta_json=IFNULL(VALUES(meta_json), meta_json),
                      updated_at=VALUES(updated_at)""",
                (
                    aid,
                    str(row.get("hostname") or "")[:128],
                    str(row.get("os_family") or "")[:32],
                    str(row.get("ip") or "")[:64],
                    str(row.get("version") or "")[:64],
                    str(row.get("status") or "online")[:16],
                    str(row.get("last_seen") or now)[:32],
                    str(health or "")[:60000] or None,
                    str(row.get("health_at") or "")[:32] or None,
                    str(caps or "")[:8000] or None,
                    str(meta or "")[:8000] or None,
                    now,
                ),
            )
            conn.commit()
        return True
    except Exception:
        return False


def write_command(row: Dict[str, Any]) -> bool:
    """双写命令/回执到 MySQL。"""
    if not row or not retention_config().get("mysql_dual_write") or not ensure_mysql_tables():
        return False
    cid = str(row.get("id") or "").strip()[:64]
    if not cid:
        return False
    try:
        with _mysql() as conn:
            cur = conn.cursor()
            cur.execute(
                f"""INSERT INTO {COMMANDS_TABLE}
                    (id, agent_id, action, params_json, status, result_json, created_by,
                     created_at, updated_at, acked_at, deadline, idempotency_key)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE
                      status=VALUES(status),
                      result_json=IFNULL(VALUES(result_json), result_json),
                      updated_at=VALUES(updated_at),
                      acked_at=IFNULL(NULLIF(VALUES(acked_at), ''), acked_at),
                      params_json=IFNULL(VALUES(params_json), params_json)""",
                (
                    cid,
                    str(row.get("agent_id") or "")[:64],
                    str(row.get("action") or "")[:64],
                    str(row.get("params_json") or "")[:60000] or None,
                    str(row.get("status") or "pending")[:16],
                    str(row.get("result_json") or "")[:60000] or None,
                    str(row.get("created_by") or "")[:64],
                    str(row.get("created_at") or "")[:32],
                    str(row.get("updated_at") or "")[:32],
                    str(row.get("acked_at") or "")[:32] or None,
                    str(row.get("deadline") or "")[:32] or None,
                    str(row.get("idempotency_key") or "")[:96] or None,
                ),
            )
            conn.commit()
        return True
    except Exception:
        return False


def shared_state_status() -> Dict[str, Any]:
    """管理台/健康检查：共享 Agent 状态表是否就绪。"""
    out = {
        "mysql_available": _mysql_ok(),
        "dual_write": bool(retention_config().get("mysql_dual_write")),
        "agents_table": AGENTS_TABLE,
        "commands_table": COMMANDS_TABLE,
        "tables_ready": False,
        "agents": None,
        "commands": None,
        "note": "SQLite 仍为节点主路径；启用 mysql_dual_write 后 agents/commands 双写 MySQL，供多实例可见起步。",
    }
    if not ensure_mysql_tables():
        return out
    out["tables_ready"] = True
    try:
        with _mysql() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) AS c FROM {AGENTS_TABLE}")
            out["agents"] = int(cur.fetchone()["c"])
            cur.execute(f"SELECT COUNT(*) AS c FROM {COMMANDS_TABLE}")
            out["commands"] = int(cur.fetchone()["c"])
    except Exception as e:
        out["error"] = str(e)[:160]
    return out


def search_mysql_timeline(q: str, *, agent_id: str = "", limit: int = 200) -> List[Dict[str, Any]]:
    """大跨度检索：SQLite 已清理的历史从 MySQL 热表查。"""
    if not ensure_mysql_tables():
        return []
    clauses = []
    args: List[Any] = []
    if agent_id:
        clauses.append("agent_id=%s")
        args.append(agent_id)
    if q:
        clauses.append("(summary LIKE %s OR detail_json LIKE %s)")
        args.extend([f"%{q}%", f"%{q}%"])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    try:
        with _mysql() as conn:
            cur = conn.cursor()
            cur.execute(
                f"SELECT agent_id, hostname, etype, summary, severity, ts FROM {TIMELINE_TABLE}{where} "
                f"ORDER BY id DESC LIMIT %s",
                (*args, max(1, min(int(limit), 1000))),
            )
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def retention_config() -> Dict[str, Any]:
    """保留期取自全局策略；默认时间线 14 天、已关闭事件 90 天。"""
    try:
        from . import agent_edr
        pol = agent_edr.get_policy("global").get("policy") or {}
        return {
            "timeline_days": max(1, min(int(pol.get("timeline_retain_days") or 14), 365)),
            "events_days": max(7, min(int(pol.get("events_retain_days") or 90), 730)),
            "mysql_dual_write": bool(pol.get("mysql_dual_write", True)),
        }
    except Exception:
        return {"timeline_days": 14, "events_days": 90, "mysql_dual_write": True}


def _cut(days: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - days * 86400))


def purge(*, timeline_days: int = 14, events_days: int = 90) -> Dict[str, Any]:
    """按保留期清理 SQLite（控制体积）与 MySQL 热表。open 事件永不清理。"""
    from . import agent_edr, agent_protocol

    tl_cut, ev_cut = _cut(timeline_days), _cut(events_days)
    out: Dict[str, Any] = {"ok": True, "timeline_cut": tl_cut, "events_cut": ev_cut}
    try:
        agent_edr.ensure()
        with agent_edr._lock:
            conn = agent_edr._connect()
            try:
                cur = conn.execute("DELETE FROM agent_timeline WHERE ts<?", (tl_cut,))
                out["timeline_deleted"] = cur.rowcount or 0
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        out["timeline_error"] = str(e)[:160]
    try:
        agent_protocol.ensure_db()
        with agent_protocol._lock:
            conn = agent_protocol._connect()
            try:
                cur = conn.execute(
                    "DELETE FROM agent_events WHERE status!='open' AND updated_at<?", (ev_cut,),
                )
                out["events_deleted"] = cur.rowcount or 0
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        out["events_error"] = str(e)[:160]
    if ensure_mysql_tables():
        try:
            with _mysql() as conn:
                cur = conn.cursor()
                # MySQL 热表保留 4 倍时长，作为历史检索层
                cur.execute(f"DELETE FROM {TIMELINE_TABLE} WHERE ts<%s", (_cut(timeline_days * 4),))
                out["mysql_timeline_deleted"] = cur.rowcount or 0
                cur.execute(
                    f"DELETE FROM {EVENTS_TABLE} WHERE status!='open' AND updated_at<%s",
                    (_cut(events_days * 4),),
                )
                out["mysql_events_deleted"] = cur.rowcount or 0
                conn.commit()
        except Exception as e:
            out["mysql_error"] = str(e)[:160]
    return out


def store_stats() -> Dict[str, Any]:
    from . import agent_edr, agent_protocol

    stats: Dict[str, Any] = {
        "ok": True,
        "retention": retention_config(),
        "mysql": {"available": _mysql_ok(), "tables_ready": False},
    }
    try:
        agent_edr.ensure()
        with agent_edr._lock:
            conn = agent_edr._connect()
            try:
                stats["sqlite_timeline"] = conn.execute("SELECT COUNT(*) AS c FROM agent_timeline").fetchone()["c"]
            finally:
                conn.close()
    except Exception:
        stats["sqlite_timeline"] = None
    try:
        agent_protocol.ensure_db()
        with agent_protocol._lock:
            conn = agent_protocol._connect()
            try:
                stats["sqlite_events"] = conn.execute("SELECT COUNT(*) AS c FROM agent_events").fetchone()["c"]
            finally:
                conn.close()
    except Exception:
        stats["sqlite_events"] = None
    if ensure_mysql_tables():
        stats["mysql"]["tables_ready"] = True
        try:
            with _mysql() as conn:
                cur = conn.cursor()
                cur.execute(f"SELECT COUNT(*) AS c FROM {TIMELINE_TABLE}")
                stats["mysql"]["timeline"] = int(cur.fetchone()["c"])
                cur.execute(f"SELECT COUNT(*) AS c FROM {EVENTS_TABLE}")
                stats["mysql"]["events"] = int(cur.fetchone()["c"])
                try:
                    cur.execute(f"SELECT COUNT(*) AS c FROM {AGENTS_TABLE}")
                    stats["mysql"]["agents"] = int(cur.fetchone()["c"])
                    cur.execute(f"SELECT COUNT(*) AS c FROM {COMMANDS_TABLE}")
                    stats["mysql"]["commands"] = int(cur.fetchone()["c"])
                except Exception:
                    stats["mysql"]["agents"] = None
                    stats["mysql"]["commands"] = None
        except Exception as e:
            stats["mysql"]["error"] = str(e)[:160]
    stats["shared_agent_state"] = shared_state_status()
    return stats


_last_purge = 0.0


def maybe_purge() -> None:
    """每小时最多触发一次后台清理。"""
    global _last_purge
    now = time.time()
    if now - _last_purge < 3600:
        return
    _last_purge = now
    rc = retention_config()
    threading.Thread(
        target=purge,
        kwargs={"timeline_days": rc["timeline_days"], "events_days": rc["events_days"]},
        daemon=True,
    ).start()
