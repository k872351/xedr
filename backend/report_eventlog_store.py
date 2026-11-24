# -*- coding: utf-8 -*-
"""Event log storage, paging and rule-hit annotation helpers."""
from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .cache_policy import capacity, ttl
from . import paths as P
from .report_batch_rows import _insert_event_log_rows
from .report_blob_metadata import _load_one_blob
from .report_event_format import _event_log_row_to_dict
from .report_event_query import _event_matches_q
from .report_json import _jdump

def _ensure_event_logs_table(conn: sqlite3.Connection) -> int:
    from . import db_store as store

    """若 event_logs 表空但 blob 有数据，一次性迁移，避免前端拉 10MB+ JSON。"""
    try:
        n = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
    except sqlite3.OperationalError:
        store._init_schema(conn)
        n = 0
    if n > 0:
        return n
    raw = _load_one_blob(conn, "event_logs")
    if not isinstance(raw, list) or not raw:
        return 0
    conn.execute("DELETE FROM event_logs")
    n = _insert_event_log_rows(conn, raw)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
        ("count_event_logs", str(n)),
    )
    # 大 blob 改为最多保留 300 条样例，完整数据在表里
    if n > 300:
        conn.execute(
            "INSERT OR REPLACE INTO blobs(name,data) VALUES(?,?)",
            ("event_logs", _jdump(raw[:300])),
        )
    try:
        conn.commit()
    except Exception:
        pass
    return n


def _event_log_channel_stats(conn: sqlite3.Connection) -> Dict[str, int]:
    try:
        rows = conn.execute(
            "SELECT IFNULL(channel,'') AS ch, COUNT(1) AS c FROM event_logs GROUP BY ch ORDER BY c DESC"
        ).fetchall()
        out: Dict[str, int] = {}
        for r in rows:
            ch = str(r["ch"] or "").strip() or "Other"
            out[ch] = int(r["c"] or 0)
        return out
    except Exception:
        return {}


def _parse_event_hit_key(hk: str) -> Optional[Tuple[str, int, str]]:
    parts = str(hk or "").split("|")
    if len(parts) < 3:
        return None
    ch, eid_s, tm = parts[0], parts[1], "|".join(parts[2:])
    try:
        eid = int(eid_s)
    except Exception:
        eid = 0
    return ch, eid, tm


_ELOG_HIT_CACHE: Dict[str, tuple] = {}
_ELOG_HIT_LOCK = threading.Lock()
_ELOG_HIT_TTL = ttl("eventlog_hit_index", 30.0, minimum=5.0, maximum=300.0)
_ELOG_HIT_MAX = capacity("eventlog_hit_index", 64)


def _eventlog_hit_index_for_rid(rid: str) -> Dict[str, Dict[str, Any]]:
    """分析时写入的命中索引：hit_key -> {title, rule_id, level}。不再现场全表重匹配。

    这个索引每次翻页都要用，但重建一次要读整份 summary view（7 万行的库上
    实测 58ms，是系统日志页最大的单项开销），所以按 rid 短时缓存。
    """
    now = time.time()
    with _ELOG_HIT_LOCK:
        hit = _ELOG_HIT_CACHE.get(rid)
        if hit and now - hit[0] < _ELOG_HIT_TTL:
            return hit[1]
    idx = _build_eventlog_hit_index(rid)
    with _ELOG_HIT_LOCK:
        _ELOG_HIT_CACHE[rid] = (now, idx)
        if len(_ELOG_HIT_CACHE) > _ELOG_HIT_MAX:
            trim = max(1, _ELOG_HIT_MAX // 4)
            for key, _ in sorted(_ELOG_HIT_CACHE.items(), key=lambda x: x[1][0])[:trim]:
                _ELOG_HIT_CACHE.pop(key, None)
    return idx


def _build_eventlog_hit_index(rid: str) -> Dict[str, Dict[str, Any]]:
    from . import db_store as store
    from .eventlog_rules import event_hit_key

    try:
        view = store.load_summary_view(rid) or {}
        meta = ((view.get("analysis") or {}).get("meta") or {})
        idx = meta.get("eventlog_hit_index")
        if isinstance(idx, dict) and idx:
            out: Dict[str, Dict[str, Any]] = {}
            for k, v in idx.items():
                if not k:
                    continue
                info = v if isinstance(v, dict) else {}
                out[str(k)] = {
                    "title": str(info.get("title") or ""),
                    "rule_id": str(info.get("rule_id") or ""),
                    "level": str(info.get("level") or "medium"),
                    "evidence": str(info.get("evidence") or ""),
                }
            if out:
                return out
        block = ((view.get("analysis") or {}).get("findings_by_module") or {}).get("eventlog") or {}
        out = {}
        for f in block.get("findings") or []:
            if not isinstance(f, dict):
                continue
            ex = f.get("extra") if isinstance(f.get("extra"), dict) else {}
            ch = ex.get("channel") or f.get("channel")
            eid = ex.get("event_id") if ex.get("event_id") is not None else f.get("event_id")
            tm = ex.get("time") or f.get("time")
            hk = event_hit_key(ch, eid, tm)
            if not hk or hk in out:
                continue
            out[hk] = {
                "title": str(f.get("title") or f.get("name") or ""),
                "rule_id": str(f.get("rule_id") or ""),
                "level": str(f.get("severity") or "medium"),
                "evidence": str(f.get("evidence") or ""),
            }
        return out
    except Exception:
        return {}


def _fetch_events_for_hit_index(
    conn: sqlite3.Connection,
    idx: Dict[str, Dict[str, Any]],
    *,
    q: str = "",
    channel: str = "",
) -> List[Dict[str, Any]]:
    """按分析命中索引定点取事件，避免全表重跑 Sigma。"""
    from .eventlog_rules import event_hit_key, normalize_event_time

    qq = (q or "").strip().lower()
    ch_exact = (channel or "").strip()
    items: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for hk, info in (idx or {}).items():
        parsed = _parse_event_hit_key(hk)
        if not parsed:
            continue
        ch, eid, tm = parsed
        if ch_exact and str(ch_exact).strip().lower() != ch:
            continue
        tnorm = normalize_event_time(tm)
        like_a = f"%{tnorm}%" if tnorm else "%"
        like_b = f"%{tnorm.replace(' ', 'T')}%" if tnorm else like_a
        try:
            rows = conn.execute(
                "SELECT channel,event_id,provider,time,level,computer,message,fields "
                "FROM event_logs WHERE event_id = ? AND lower(IFNULL(channel,'')) = ? "
                "AND (IFNULL(time,'') LIKE ? OR IFNULL(time,'') LIKE ?) "
                "ORDER BY id DESC LIMIT 12",
                (eid, ch, like_a, like_b),
            ).fetchall()
        except Exception:
            rows = []
        found: Optional[Dict[str, Any]] = None
        for r in rows:
            d = _event_log_row_to_dict(r)
            if event_hit_key(d.get("channel"), d.get("event_id"), d.get("time")) == hk:
                found = d
                break
        if found is None and rows:
            found = _event_log_row_to_dict(rows[0])
        if not found or hk in seen:
            continue
        if not _event_matches_q(found, qq):
            continue
        seen.add(hk)
        found = dict(found)
        found["hit_rule"] = {
            "title": str((info or {}).get("title") or ""),
            "rule_id": str((info or {}).get("rule_id") or ""),
            "level": str((info or {}).get("level") or "medium"),
            "evidence": str((info or {}).get("evidence") or ""),
        }
        items.append(found)
    items.sort(key=lambda x: str(x.get("time") or ""), reverse=True)
    return items


def _attach_eventlog_hit_rules(items: List[Dict[str, Any]], rid: str) -> None:
    if not rid or not items:
        return
    try:
        from .eventlog_rules import event_hit_key
        idx = _eventlog_hit_index_for_rid(rid)
        if not idx:
            return
        for d in items:
            if not isinstance(d, dict) or d.get("hit_rule"):
                continue
            hk = event_hit_key(d.get("channel"), d.get("event_id"), d.get("time"))
            info = idx.get(hk)
            if info:
                d["hit_rule"] = info
    except Exception:
        pass


def _query_event_logs_page(
    conn: sqlite3.Connection,
    *,
    offset: int = 0,
    limit: int = 100,
    q: str = "",
    channel: str = "",
    hit_keys: Optional[Set[str]] = None,
    rid: str = "",
    hits_only: bool = False,
) -> Dict[str, Any]:
    total = _ensure_event_logs_table(conn)
    where = ["1=1"]
    args: List[Any] = []
    ch_exact = (channel or "").strip()
    qq = (q or "").strip().lower()
    if ch_exact:
        where.append("channel = ?")
        args.append(ch_exact)
    if qq:
        where.append(
            "(lower(IFNULL(channel,'')) LIKE ? OR lower(IFNULL(provider,'')) LIKE ? "
            "OR lower(IFNULL(message,'')) LIKE ? OR CAST(event_id AS TEXT) LIKE ? "
            "OR lower(IFNULL(level,'')) LIKE ? OR lower(IFNULL(computer,'')) LIKE ? "
            "OR lower(IFNULL(fields,'')) LIKE ?)"
        )
        like = f"%{qq}%"
        args.extend([like, like, like, like, like, like, like])
    wh = " AND ".join(where)

    if hits_only or hit_keys is not None:
        idx = _eventlog_hit_index_for_rid(rid) if rid else {}
        if hit_keys:
            idx = {str(k): (idx.get(str(k)) or {}) for k in hit_keys if k}
        items = _fetch_events_for_hit_index(conn, idx, q=q, channel=channel)
        total = len(items)
        return {"total": total, "items": items[offset : offset + limit], "hits_only": True}

    # 带筛选时不做精确 COUNT(*)：7 列 LIKE 统计全量命中在 7 万行上要 155ms，
    # 而取本页只要 0.4ms。改成多取一条判断有没有下一页。
    approx = False
    rows = conn.execute(
        f"SELECT channel,event_id,provider,time,level,computer,message,fields "
        f"FROM event_logs WHERE {wh} ORDER BY time DESC, id DESC LIMIT ? OFFSET ?",
        (*args, limit + 1, offset),
    ).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    if qq or ch_exact:
        total = offset + len(rows) + (1 if has_more else 0)
        approx = has_more
    items = [_event_log_row_to_dict(r) for r in rows]
    _attach_eventlog_hit_rules(items, rid)
    return {"total": total, "items": items, "total_approx": approx, "has_more": has_more}


def invalidate_eventlog_hit_cache() -> None:
    with _ELOG_HIT_LOCK:
        _ELOG_HIT_CACHE.clear()


def _eventlog_hit_keys_for_rid(rid: str) -> Set[str]:
    """读取系统日志规则命中键集合。"""
    return set((_eventlog_hit_index_for_rid(rid) or {}).keys())


