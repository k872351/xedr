"""Cross-report content and finding search orchestration."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import paths as P
from .db_store import (
    CONTENT_SEARCH_BUDGET_S, CONTENT_SEARCH_WORKERS, _connect, _ensure_event_logs_table,
    _ensure_eventlog_fts, _ensure_files_fts, _finding_search_blob, _init_schema,
    _load_findings_for_search, _union_rows, list_index, prepare_search_db,
)


def _search_one_report(
    rid: str,
    hn: str,
    plan,
    limit: int,
) -> List[Dict[str, Any]]:
    """在单个报告库里检索。调用方保证 limit > 0。"""
    from .search_sql import (
        eventlog_where, files_hash_where, files_where, fts_like_pattern,
    )

    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return []
    key = str(dbp)
    out: List[Dict[str, Any]] = []
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        prepare_search_db(conn, key)
        pattern = fts_like_pattern(plan)

        # 路径段 / 通配：不能只用宽 FTS '%Temp%' 召回
        if plan.mode in ("segment", "glob"):
            where, params = files_where(plan)
            queries = [
                ("SELECT full_path,name,md5,sha256,signer FROM files "
                 f"WHERE {where} LIMIT ?", params),
            ]
        elif pattern and _ensure_files_fts(conn, key):
            hash_where, hash_params = files_hash_where(plan)
            queries = [
                ("SELECT f.full_path,f.name,f.md5,f.sha256,f.signer "
                 "FROM files_fts x JOIN files f ON f.rowid = x.rowid "
                 "WHERE x.full_path LIKE ? LIMIT ?", [pattern]),
                ("SELECT full_path,name,md5,sha256,signer FROM files "
                 f"WHERE {hash_where} LIMIT ?" if hash_where else "", hash_params),
            ]
        else:
            where, params = files_where(plan)
            queries = [
                ("SELECT full_path,name,md5,sha256,signer FROM files "
                 f"WHERE {where} LIMIT ?", params),
            ]
        for r in _union_rows(conn, queries, limit - len(out), lambda r: r["full_path"]):
            bits = [x for x in (r["signer"], r["md5"], r["sha256"]) if x]
            fp = str(r["full_path"] or r["name"] or "")
            out.append({
                "report_id": rid,
                "file": rid,
                "hostname": hn,
                "severity": "info",
                "category": "文件扫描",
                "title": fp,
                "evidence": " · ".join(str(x) for x in bits[:2]) or "file_scans",
                "matcher": "files",
                "module": "file",
                "kind": "file",
                "_source": "content",
                "path": fp,
                "md5": str(r["md5"] or ""),
                "sha256": str(r["sha256"] or ""),
            })
            if len(out) >= limit:
                return out

        _ensure_event_logs_table(conn)
        # 同理：倒排只盖 message，channel / event_id 要单独补
        if plan.mode in ("segment", "glob"):
            where, params = eventlog_where(plan)
            queries = [
                ("SELECT id,channel,event_id,time,message FROM event_logs "
                 f"WHERE {where} LIMIT ?", params),
            ]
        elif pattern and _ensure_eventlog_fts(conn, key):
            queries = [
                ("SELECT e.id,e.channel,e.event_id,e.time,e.message "
                 "FROM event_logs_fts x JOIN event_logs e ON e.id = x.rowid "
                 "WHERE x.message LIKE ? LIMIT ?", [pattern]),
                ("SELECT id,channel,event_id,time,message FROM event_logs "
                 "WHERE channel LIKE ? OR CAST(event_id AS TEXT) LIKE ? LIMIT ?",
                 [pattern, pattern]),
            ]
        else:
            where, params = eventlog_where(plan)
            queries = [
                ("SELECT id,channel,event_id,time,message FROM event_logs "
                 f"WHERE {where} LIMIT ?", params),
            ]
        for r in _union_rows(conn, queries, limit - len(out), lambda r: r["id"]):
            out.append({
                "report_id": rid,
                "file": rid,
                "hostname": hn,
                "severity": "info",
                "category": "系统日志",
                "title": f"{r['channel'] or 'Event'} #{int(r['event_id'] or 0)}",
                "evidence": str(r["message"] or "")[:240] or str(r["time"] or ""),
                "matcher": "eventlog",
                "module": "eventlog",
                "kind": "eventlog",
                "_source": "content",
            })
            if len(out) >= limit:
                break
    except Exception as e:
        print(f"[db_store] search content {rid}: {e}")
    finally:
        conn.close()
    return out


def search_report_content_local(
    q: str,
    hostname: Optional[str] = None,
    size: int = 50,
    user: Optional[Dict[str, Any]] = None,
    match_mode: str = "smart",
) -> List[Dict[str, Any]]:
    """跨报告检索 文件扫描 / 系统日志（各报告 analysis.db）。

    默认是子串包含，语义与历史实现一致，不会因为提速而少查。
    提速来自 trigram 倒排索引，见 _ensure_fts。
    """
    from .search_sql import classify

    needle = (q or "").strip()
    if not needle:
        return []
    want_hn = (hostname or "").strip()
    limit = max(1, int(size))
    try:
        rows = list_index(min(max(limit * 6, 120), 300), user=user)
    except Exception as e:
        print(f"[db_store] search content list_index: {e}")
        rows = []

    targets = []
    for row in rows:
        hn = str(row.get("hostname") or "")
        if want_hn and hn != want_hn:
            continue
        rid = str(row.get("file") or "")
        if rid:
            targets.append((rid, hn))
    if not targets:
        return []

    return _fanout_search(targets, classify(needle, match_mode), limit)


def _fanout_search(targets, plan, limit: int) -> List[Dict[str, Any]]:
    """并发查多个报告库，凑够 limit 或超出时间预算就停。"""
    from concurrent.futures import ThreadPoolExecutor

    out: List[Dict[str, Any]] = []
    deadline = time.perf_counter() + CONTENT_SEARCH_BUDGET_S
    workers = min(CONTENT_SEARCH_WORKERS, max(1, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_search_one_report, rid, hn, plan, limit): rid
            for rid, hn in targets
        }
        for fut in futures:
            if len(out) >= limit or time.perf_counter() > deadline:
                fut.cancel()
                continue
            try:
                out.extend(fut.result(timeout=max(0.1, deadline - time.perf_counter())))
            except Exception:
                continue
    return out[:limit]


def search_findings_local(
    q: str,
    hostname: Optional[str] = None,
    severity: Optional[str] = None,
    size: int = 50,
    user: Optional[Dict[str, Any]] = None,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """在本地 analysis.db / result.json 里搜告警标题、证据、分类（跨主机）。"""
    from backend.search_sql import text_matches_query

    needle = (q or "").strip()
    if not needle:
        return []
    want_hn = (hostname or "").strip()
    want_sev = (severity or "").strip().lower()
    skip = max(0, int(offset))
    need = int(size)
    out: List[Dict[str, Any]] = []
    try:
        rows = list_index(min(max((need + skip) * 4, 80), 2000), user=user)
    except Exception as e:
        print(f"[db_store] search list_index: {e}")
        rows = []
    if not rows:
        return []
    skipped = 0
    for row in rows:
        hn = str(row.get("hostname") or "")
        if want_hn and hn != want_hn:
            continue
        rid = str(row.get("file") or "")
        if not rid:
            continue
        for item in _load_findings_for_search(rid):
            sev = str(item.get("severity") or "medium").lower()
            if want_sev and sev != want_sev:
                continue
            if not text_matches_query(_finding_search_blob(item, hn, rid), needle):
                continue
            if skipped < skip:
                skipped += 1
                continue
            ev = item.get("evidence")
            if isinstance(ev, list):
                ev_s = "；".join(str(x) for x in ev[:4])
            else:
                ev_s = str(ev or "")
            out.append({
                "report_id": rid,
                "file": rid,
                "hostname": hn,
                "severity": item.get("severity") or "medium",
                "category": item.get("category") or "",
                "title": item.get("title") or item.get("name") or "",
                "evidence": ev_s or item.get("reason") or "",
                "matcher": item.get("matcher") or "",
                "rule_id": item.get("rule_id") or "",
                "_source": "local",
                "extra": item.get("extra") if isinstance(item.get("extra"), dict) else {},
                "path": str((item.get("extra") or {}).get("path") or item.get("path") or ""),
                "command": str(
                    (item.get("extra") or {}).get("command")
                    or (item.get("extra") or {}).get("image_path")
                    or item.get("command")
                    or ""
                ),
                "md5": str((item.get("extra") or {}).get("md5") or item.get("md5") or ""),
                "sha1": str((item.get("extra") or {}).get("sha1") or item.get("sha1") or ""),
                "sha256": str((item.get("extra") or {}).get("sha256") or item.get("sha256") or ""),
            })
            if len(out) >= need:
                return out
    return out
