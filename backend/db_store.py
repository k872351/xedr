"""每份报告对应一个 SQLite 结果库，避免反复解析大 JSON。"""
from __future__ import annotations
import json
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from .finding_evidence_format import (
    _BLACK_DLL_LABEL, _BLACK_MOD_HDR, _EVIDENCE_LIST_PREVIEW,
    _UNSIGNED_FILE_LABEL, _coalesce_black_mod_evidence, _looks_like_mod_line,
    _norm_evidence_list, slim_finding_for_list, slim_findings_by_module, slim_findings_list,
)

from . import config
from . import paths as P
from .cache_policy import capacity, ttl, versioned
from .iputil import pick_primary_ip
from .file_normalization import _norm_ext, _norm_hash_field, _norm_file_path, _file_parent, _directory_rows
from .report_json import _jdump, _jload, write_report_json
from .report_event_format import _elog_row_tuple, _event_log_row_to_dict
from .report_file_format import FILE_CONTENT_MAX_CHARS, _file_content_field, _file_row_tuple
from .report_batch_rows import _FILE_INSERT_SQL, _ELOG_INSERT_SQL, _insert_file_rows, _insert_event_log_rows
from .report_index_schema import INDEX_SCHEMA_VERSION, _init_index, _apply_index_schema
from .report_db_connection import _connect
from .report_db_metadata import _table_rows, _has_object
from .report_directory_index import (
    _FILES_PATH_NORM_INDEX_SQL, _ensure_files_path_norm_index, _ensure_files_hash_indexes,
    _rebuild_directory_index, _ensure_directory_index,
)
from .report_finding_format import _finding_search_blob
from .report_blob_metadata import _count_blob_fast, _nested_artifact_count, _load_one_blob, _conn_os_family, _derive_file_scan_roots
from .report_tree_format import _build_files_tree, _parse_mtime_bound, _file_row_to_tree_item, _root_where_clause as _report_root_where_clause
from .report_process_format import _proc_pid, _proc_ppid, _enrich_process_family, _slim_process_for_list
from .report_path_resolution import _resolve_task_paths_from_conn, _resolve_startup_paths_from_conn
from .report_search_query import _date_q_variants, _token_in_blob, _item_search_blob, _item_match_q
from .report_event_query import _event_matches_q
from .report_ingest import (
    _meta_int, ingest_event_logs, ingest_event_logs_iter, ingest_file_scans,
    ingest_file_scans_iter,
)
from .report_eventlog_store import (
    _attach_eventlog_hit_rules, _ensure_event_logs_table, _event_log_channel_stats,
    _eventlog_hit_index_for_rid, _eventlog_hit_keys_for_rid, _fetch_events_for_hit_index,
    _parse_event_hit_key, _query_event_logs_page, invalidate_eventlog_hit_cache,
)
from .report_enrichment import _enrich_linux_section_sigs, _annotate_persist_sideload_list
from .report_index_rows import upsert_index_row, _row_from_sqlite, list_index_rows
from .report_schema import (
    REPORT_SCHEMA_VERSION, _SCHEMA_READY, _SCHEMA_READY_LOCK, _apply_report_schema,
    _init_schema, _init_schema_uncached, _schema_cache_valid, _schema_conn_key,
)

_PARK_FILES = "_park_file_scans.pkl"
_PARK_EVENTS = "_park_event_logs.pkl"

DB_DIR = config.REPORTS_DIR / "dbs"
DB_DIR.mkdir(parents=True, exist_ok=True)
INDEX_DB = config.REPORTS_DIR / "index.db"

# 写入 DB 的报告分段（足够前端各页展示）
BLOB_KEYS = [
    "processes", "services", "scheduled_tasks", "startup_items", "installed_programs",
    "users", "usb_devices", "prefetch_files", "established_connections", "open_ports",
    "network", "hosts_file", "firewall_rules", "ps_history", "ps_artifacts", "browser_artifacts",
    "user_registry", "services_registry", "network_registry", "run_mru",
    "recycle_bin", "wmi_subscriptions", "wmi_namespaces", "environment", "collection_quality",
    "suspicious_items", "hotfixes", "drivers", "driver_entries", "dns_cache_entries",
    "office_artifacts", "wifi_profiles", "event_log_summary", "event_logs",
    "system_info", "usn_journal", "vss_shadows", "bits_jobs", "audit_pol", "vault_creds",
    "net_sessions", "net_shares", "execution_artifacts", "remote_access", "security_extras",
    "event_log_coverage", "system_timezone", "file_scan_roots",
    "linuxsc_raw",
]

# 已下线的内存 / $MFT 取证分段：旧库里的 blob 保留，但平台不再读取 / 展示
RETIRED_BLOB_KEYS = frozenset({"memory_artifacts", "mft_artifacts"})


def db_path_for_report(report_file: str) -> Path:
    """优先返回目录内 analysis.db；写入前会 create 目录。"""
    existing = P.resolve_analysis_db(report_file)
    if existing:
        return existing
    return P.db_path_for_write(report_file)


# 进程模块签名回查按 lower(replace(full_path,'/','\')) 匹配，必须是表达式索引，
# 否则 SQLite 用不上 full_path 主键索引，百万行的 files 表每次都全表扫描。
from .db_store_heavy import (  # noqa: E402
    _park_path, park_heavy_arrays, load_parked_heavy, clear_parked_heavy,
    detach_and_ingest_heavy, rewrite_report_json_slim, ensure_heavy_ready,
)

def files_rid(report: Dict[str, Any]) -> str:
    return str(report.get("_files_rid") or report.get("_rid") or "").strip()


def upsert_index(row: Dict[str, Any]) -> None:
    from .ownership import resolve_owner_fields
    owner = resolve_owner_fields(row)
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        upsert_index_row(conn, row, owner, time.time())
        conn.commit()
    finally:
        conn.close()
    invalidate_list_cache()
    # 同步主机台账（失败不影响索引）
    hn = (row.get("hostname") or "").strip()
    if hn and hn != "unknown":
        try:
            from .hosts import ensure_host
            ensure_host(hn, row.get("ip") or "")
        except Exception as e:
            print("[index] ensure_host:", e)
    # 双写 MySQL reports
    try:
        from .mysql_store import upsert_report_row
        payload = dict(row)
        payload["owner_id"] = owner.get("owner_id") or row.get("owner_id") or ""
        payload["owner_username"] = owner.get("owner_username") or row.get("owner_username") or ""
        upsert_report_row(payload)
    except Exception as e:
        print("[index] mysql upsert_report_row:", e)


def clear_index() -> None:
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        conn.execute("DELETE FROM reports")
        conn.commit()
    finally:
        conn.close()
    invalidate_list_cache()


def delete_index_entry(report_file: str, mysql: bool = True) -> None:
    rid = P.report_id(report_file)
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        conn.execute("DELETE FROM reports WHERE file=?", (rid,))
        conn.commit()
    finally:
        conn.close()
    if not mysql:
        return
    try:
        from .mysql_store import delete_report_row
        delete_report_row(rid)
    except Exception as e:
        print("[index] mysql delete_report_row:", e)



_DISK_CACHE: Dict[str, float] = {}
_DISK_CACHE_TTL = 120.0
_DISK_MISS_TTL = 20.0
_DISK_CACHE_LOCK = threading.Lock()
_DISK_MISS: Dict[str, float] = {}


def _report_on_disk(rid: str) -> bool:
    now = time.time()
    with _DISK_CACHE_LOCK:
        ts = _DISK_CACHE.get(rid)
        if ts is not None and now - ts < _DISK_CACHE_TTL:
            return True
        miss_ts = _DISK_MISS.get(rid)
        if miss_ts is not None and now - miss_ts < _DISK_MISS_TTL:
            return False
    result = bool(
        P.resolve_report_json(rid)
        or P.resolve_analysis_db(rid)
        or P.resolve_result_json(rid)
    )
    with _DISK_CACHE_LOCK:
        if result:
            _DISK_CACHE[rid] = now
            _DISK_MISS.pop(rid, None)
        else:
            _DISK_MISS[rid] = now
            _DISK_CACHE.pop(rid, None)
            if len(_DISK_MISS) > 4000:
                oldest = sorted(_DISK_MISS.items(), key=lambda x: x[1])[:1000]
                for k, _ in oldest:
                    _DISK_MISS.pop(k, None)
    return result


def _invalidate_disk_cache(rid: str) -> None:
    with _DISK_CACHE_LOCK:
        _DISK_CACHE.pop(rid, None)
        _DISK_MISS.pop(rid, None)


def prune_stale_index() -> int:
    """删掉磁盘上已不存在的索引项（SQLite + MySQL），避免幽灵主机/报告。"""
    removed = 0
    if INDEX_DB.exists():
        conn = _connect(INDEX_DB)
        try:
            _init_index(conn)
            rows = conn.execute("SELECT file FROM reports").fetchall()
            for r in rows:
                rid = r["file"]
                if _report_on_disk(rid):
                    continue
                conn.execute("DELETE FROM reports WHERE file=?", (rid,))
                removed += 1
                folder = P.report_dir(rid)
                if folder.exists() and folder.is_dir():
                    try:
                        if not any(folder.iterdir()):
                            folder.rmdir()
                    except OSError:
                        pass
            conn.commit()
        finally:
            conn.close()
    # MySQL 影子索引也要清，否则 list_hosts → sync_hosts_from_index 会把已删主机建回来
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import list_reports_mysql, delete_report_files
        if mysql_ready():
            rows = list_reports_mysql(limit=5000) or []
            stale = []
            for r in rows:
                rid = (r.get("file") or "").strip()
                if not rid or _report_on_disk(rid):
                    continue
                stale.append(rid)
            if stale:
                delete_report_files(stale)
                removed += len(stale)
    except Exception as e:
        print(f"[index] prune mysql: {e}")
    if removed:
        try:
            invalidate_list_cache()
        except Exception:
            pass
    return removed


def invalidate_list_cache() -> None:
    invalidate_findings_cache()
    with _OWNER_CACHE_LOCK:
        _OWNER_CACHE.clear()
    invalidate_eventlog_hit_cache()
    try:
        from .hosts import _invalidate_host_cache
        _invalidate_host_cache()
    except Exception:
        pass
    try:
        from .hot_cache import bump
        bump()
    except Exception:
        pass


def list_index(limit: int = 100, user: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Read the authoritative report index, falling back only when MySQL is unavailable."""
    from .ownership import is_admin

    admin = is_admin(user) if user else True
    uid = str((user or {}).get('id') or '') if user and not admin else ''
    uname = str((user or {}).get('username') or '') if user and not admin else ''
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import list_reports_mysql
        if mysql_ready():
            rows = list_reports_mysql(limit=limit, user=user)
            if rows is not None:
                return rows[:limit] if limit >= 0 else rows
    except Exception as e:
        print("[index] mysql list:", e)
        try:
            from .mysql_db import mark_mysql_down
            mark_mysql_down(str(e))
        except Exception:
            pass

    if not INDEX_DB.exists():
        return []
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        return list_index_rows(conn, limit, admin=admin, uid=uid, uname=uname)
    finally:
        conn.close()


def get_index_meta(report_file: str) -> Optional[Dict[str, Any]]:
    """按逻辑 ID 取索引一行：hostname / owner，不读大 JSON。找不到返回 None。"""
    rid = P.report_id(report_file)
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import get_report_meta_mysql
        if mysql_ready():
            m = get_report_meta_mysql(rid)
            if m:
                return m
    except Exception:
        pass
    if not INDEX_DB.exists():
        return None
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        row = conn.execute(
            "SELECT file, hostname, owner_id, owner_username FROM reports WHERE file=?",
            (rid,),
        ).fetchone()
        if not row:
            return None
        keys = set(row.keys()) if hasattr(row, "keys") else set()
        return {
            "file": row["file"] or rid,
            "hostname": row["hostname"] or "",
            "owner_id": (row["owner_id"] or "") if "owner_id" in keys else "",
            "owner_username": (row["owner_username"] or "") if "owner_username" in keys else "",
        }
    finally:
        conn.close()


_OWNER_CACHE: Dict[str, tuple] = {}
_OWNER_CACHE_LOCK = threading.Lock()
_OWNER_CACHE_TTL = ttl("report_owner", 20.0, minimum=2.0, maximum=120.0)
_OWNER_CACHE_MAX = capacity("report_owner", 2000)


def _owner_cache_put(rid: str, value: Dict[str, str], now: Optional[float] = None) -> None:
    with _OWNER_CACHE_LOCK:
        _OWNER_CACHE[rid] = (float(now or time.time()), dict(value))
        if len(_OWNER_CACHE) > _OWNER_CACHE_MAX:
            trim = max(1, _OWNER_CACHE_MAX // 4)
            for key, _ in sorted(_OWNER_CACHE.items(), key=lambda x: x[1][0])[:trim]:
                _OWNER_CACHE.pop(key, None)


def get_report_owner(report_file: str) -> Dict[str, str]:
    """返回报告归属 {owner_id, owner_username}。"""
    rid = P.report_id(report_file)
    now = time.time()
    with _OWNER_CACHE_LOCK:
        hit = _OWNER_CACHE.get(rid)
        if hit and now - float(hit[0]) < _OWNER_CACHE_TTL:
            return dict(hit[1])
    # MySQL 优先
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import get_report_owner_mysql
        if mysql_ready():
            m = get_report_owner_mysql(rid)
            if m is not None:
                _owner_cache_put(rid, m, now)
                return m
    except Exception:
        pass
    if not INDEX_DB.exists():
        empty = {"owner_id": "", "owner_username": ""}
        _owner_cache_put(rid, empty, now)
        return empty
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        row = conn.execute(
            "SELECT owner_id, owner_username FROM reports WHERE file=?", (rid,)
        ).fetchone()
        if not row:
            out = {"owner_id": "", "owner_username": ""}
        else:
            out = {
                "owner_id": (row["owner_id"] or "") if "owner_id" in row.keys() else "",
                "owner_username": (row["owner_username"] or "") if "owner_username" in row.keys() else "",
            }
        _owner_cache_put(rid, out, now)
        return out
    finally:
        conn.close()


def _load_findings_for_search(rid: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    dbp = P.resolve_analysis_db(rid)
    if dbp and dbp.exists():
        conn = _connect(dbp)
        try:
            _init_schema(conn)
            for r in conn.execute("SELECT * FROM findings_agg"):
                extra = _jload(r["extra"] if "extra" in r.keys() else "", {}) or {}
                item = {
                    "id": r["id"],
                    "category": r["category"] or "",
                    "severity": r["severity"] or "medium",
                    "title": r["title"] or "",
                    "count": r["count"] or 1,
                    "evidence": _jload(r["evidence"], []),
                    "sources": _jload(r["sources"], []),
                    "rule_id": r["rule_id"] or "",
                    "matcher": r["matcher"] or "",
                }
                if isinstance(extra, dict):
                    item.update(extra)
                items.append(item)
        except Exception as e:
            print(f"[db_store] load findings {rid}: {e}")
        finally:
            conn.close()
    rp = P.resolve_result_json(rid)
    if rp and rp.exists():
        try:
            with open(rp, encoding="utf-8") as f:
                data = json.load(f)
            analysis = data.get("analysis") if isinstance(data, dict) else None
            if not isinstance(analysis, dict):
                analysis = data if isinstance(data, dict) else {}
            raw = analysis.get("findings_aggregated") or analysis.get("findings") or []
            extra = [x for x in raw if isinstance(x, dict)]
            if len(extra) > len(items):
                return extra
        except Exception as e:
            print(f"[db_store] result.json findings {rid}: {e}")
    return items


#: 行数低于此值不建 trigram 索引：全表扫本来就够快，不值得多占磁盘
SEARCH_INDEX_MIN_ROWS = 200_000
#: event_logs 到这个量级才值得建 FTS5（7 万行时 LIKE 只要 37ms）
FTS_MIN_ROWS = 150_000
#: 单次跨报告检索的墙钟预算，超时就返回已拿到的结果并标记还有更多
CONTENT_SEARCH_BUDGET_S = 3.5
#: 并发打开报告库的线程数
CONTENT_SEARCH_WORKERS = 8


#: 已经备好检索索引的库，进程内只做一次（键为 db 路径）
_SEARCH_PREPPED: Set[str] = set()
#: (db 路径, FTS 表名) -> 是否可用
_FTS_READY: Dict[str, bool] = {}
#: 按 db 路径分片的锁：不同报告库的 FTS 构建可并发，避免全局排队。
_SEARCH_PREP_LOCKS: Dict[str, threading.Lock] = {}
_SEARCH_PREP_LOCKS_LOCK = threading.Lock()


def _invalidate_db_caches(key: str) -> None:
    """库被删库重建后，清掉所有以该库路径为 key 的缓存。

    这些缓存记的是「表已建好/索引可用」，库重建后路径不变但表全没了，
    不清就会拿着失效缓存去查不存在的表。
    """
    _SEARCH_PREPPED.discard(key)
    for ck in [c for c in _FTS_READY if c.split("::", 1)[0] == key]:
        _FTS_READY.pop(ck, None)
    with _SCHEMA_READY_LOCK:
        _SCHEMA_READY.discard(key)

#: 上一版按「前缀匹配」设计时建的索引。前缀匹配会漏结果，方案已废弃；
#: 这些索引在当前查询形态下用不到，留着白占几百 MB，遇到就顺手删掉。
_STALE_INDEXES = (
    "idx_files_name_nc", "idx_files_path_nc", "idx_files_fp_nc",
    "idx_mft_name_nc", "idx_mft_fp_nc", "idx_elog_chan_nc",
)


def prepare_search_db(conn: sqlite3.Connection, key: str) -> None:
    """清掉废弃索引；每个库每进程只做一次。

    缓存 key 是库路径，而重新分析会删库重建（路径不变、表全没）。命中缓存时
    再确认核心表在位，否则连同 FTS 缓存一起失效重做 —— 否则检索会拿着失效缓存
    去查已不存在的表，异常被上层吞掉后表现为「静默搜不到证据」。
    """
    if key in _SEARCH_PREPPED and _schema_cache_valid(conn):
        return
    with _SEARCH_PREP_LOCKS_LOCK:
        lock = _SEARCH_PREP_LOCKS.setdefault(key, threading.Lock())
    with lock:
        if key in _SEARCH_PREPPED and _schema_cache_valid(conn):
            return
        _invalidate_db_caches(key)
        try:
            for name in _STALE_INDEXES:
                if _has_object(conn, name):
                    try:
                        conn.execute(f"DROP INDEX IF EXISTS {name}")
                    except sqlite3.OperationalError:
                        pass
            conn.commit()
        except Exception as e:
            print(f"[db_store] prepare search db: {e}")
        _SEARCH_PREPPED.add(key)


def _ensure_fts(
    conn: sqlite3.Connection,
    key: str,
    *,
    fts_table: str,
    src_table: str,
    column: str,
    rowid: str,
) -> bool:
    """按需建 trigram FTS5 外部内容表；返回是否可用。

    trigram 分词器让 FTS5 表上的 LIKE '%x%' 走倒排，语义与普通 LIKE
    完全一致——这是提速的同时不丢结果的关键。content= 模式只存倒排，
    不复制原文。实测 118 万行 full_path：1006ms -> 4.6ms，结果逐条一致。

    索引只是加速器：建不出来时调用方退回普通 LIKE，结果依旧正确。
    """
    ck = f"{key}::{fts_table}"
    cached = _FTS_READY.get(ck)
    # 缓存说"可用"时确认虚拟表真在：库重建后路径不变而 FTS 表已随之消失，
    # 盲信缓存会让后续 SELECT 打到不存在的表上。
    if cached is True and not _has_object(conn, fts_table):
        cached = None
        _FTS_READY.pop(ck, None)
    if cached is not None:
        return cached
    with _SEARCH_PREP_LOCKS_LOCK:
        lock = _SEARCH_PREP_LOCKS.setdefault(key, threading.Lock())
    with lock:
        cached = _FTS_READY.get(ck)
        if cached is True and not _has_object(conn, fts_table):
            cached = None
            _FTS_READY.pop(ck, None)
        if cached is not None:
            return cached
        ok = False
        try:
            if _has_object(conn, fts_table):
                # 旧版本 FTS 没有同步触发器；首次升级时重建一次，之后由触发器增量维护。
                trigger_name = f"{fts_table}_ai"
                needs_rebuild = not _has_object(conn, trigger_name)
                _ensure_fts_sync_triggers(
                    conn, fts_table=fts_table, src_table=src_table,
                    column=column, rowid=rowid,
                )
                if needs_rebuild:
                    conn.execute(f"INSERT INTO {fts_table}({fts_table}) VALUES('rebuild')")
                    conn.commit()
                ok = True
            elif _table_rows(conn, src_table) >= SEARCH_INDEX_MIN_ROWS:
                t0 = time.perf_counter()
                conn.execute(
                    f"CREATE VIRTUAL TABLE {fts_table} USING fts5("
                    f"{column}, content='{src_table}', content_rowid='{rowid}', "
                    f"tokenize='trigram')"
                )
                conn.execute(
                    f"INSERT INTO {fts_table}(rowid, {column}) "
                    f"SELECT {rowid}, IFNULL({column},'') FROM {src_table}"
                )
                _ensure_fts_sync_triggers(
                    conn, fts_table=fts_table, src_table=src_table,
                    column=column, rowid=rowid,
                )
                conn.commit()
                print(f"[db_store] built {fts_table} in {time.perf_counter()-t0:.1f}s")
                ok = True
        except sqlite3.OperationalError as e:
            print(f"[db_store] {fts_table} unavailable, fallback to LIKE: {e}")
            ok = False
        _FTS_READY[ck] = ok
        return ok


def _ensure_fts_sync_triggers(
    conn: sqlite3.Connection,
    *,
    fts_table: str,
    src_table: str,
    column: str,
    rowid: str,
) -> None:
    """让外部内容 FTS 与源表保持同步，避免入库后命中陈旧索引。"""
    conn.executescript(
        f"""
        CREATE TRIGGER IF NOT EXISTS {fts_table}_ai AFTER INSERT ON {src_table} BEGIN
          INSERT INTO {fts_table}(rowid, {column}) VALUES (new.{rowid}, IFNULL(new.{column}, ''));
        END;
        CREATE TRIGGER IF NOT EXISTS {fts_table}_ad AFTER DELETE ON {src_table} BEGIN
          INSERT INTO {fts_table}({fts_table}, rowid, {column})
          VALUES ('delete', old.{rowid}, IFNULL(old.{column}, ''));
        END;
        CREATE TRIGGER IF NOT EXISTS {fts_table}_au AFTER UPDATE OF {column} ON {src_table} BEGIN
          INSERT INTO {fts_table}({fts_table}, rowid, {column})
          VALUES ('delete', old.{rowid}, IFNULL(old.{column}, ''));
          INSERT INTO {fts_table}(rowid, {column}) VALUES (new.{rowid}, IFNULL(new.{column}, ''));
        END;
        """
    )


def _ensure_files_fts(conn: sqlite3.Connection, key: str) -> bool:
    return _ensure_fts(
        conn, key, fts_table="files_fts", src_table="files",
        column="full_path", rowid="rowid",
    )


def _ensure_eventlog_fts(conn: sqlite3.Connection, key: str) -> bool:
    return _ensure_fts(
        conn, key, fts_table="event_logs_fts", src_table="event_logs",
        column="message", rowid="id",
    )


def _union_rows(conn, queries, limit: int, key_of) -> List[Any]:
    """依次跑多条查询并按 key 去重合并，凑够 limit 就停。

    倒排索引只覆盖单列，其余列得用普通谓词补上，否则会漏结果。
    """
    seen = set()
    out: List[Any] = []
    for sql, params in queries:
        if not sql or len(out) >= limit:
            continue
        try:
            rows = conn.execute(sql, (*params, limit - len(out))).fetchall()
        except sqlite3.OperationalError as e:
            print(f"[db_store] union query: {e}")
            continue
        for r in rows:
            k = key_of(r)
            if k in seen:
                continue
            seen.add(k)
            out.append(r)
            if len(out) >= limit:
                break
    return out














def upsert_ai_blob(report_file: str, ai: Dict[str, Any]) -> bool:
    """仅更新 analysis.db 中的 AI 研判 blob，不重写整库。"""
    rid = P.report_id(report_file)
    dbp = db_path_for_report(rid)
    ok = False
    if dbp.exists():
        conn = _connect(dbp)
        try:
            _init_schema(conn)
            conn.execute("DELETE FROM blobs WHERE name=?", ("ai",))
            conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("ai", _jdump(ai)))
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                ("ai_updated_at", time.strftime("%Y-%m-%dT%H:%M:%S")),
            )
            conn.commit()
            ok = True
        finally:
            conn.close()
    try:
        from .mysql_store import upsert_ai_mysql
        hostname = ""
        try:
            meta_path = P.resolve_report_json(rid)
            if meta_path and meta_path.exists():
                with open(meta_path, encoding="utf-8") as fh:
                    hostname = (json.load(fh) or {}).get("hostname") or ""
        except Exception:
            pass
        upsert_ai_mysql(rid, ai, hostname=hostname)
    except Exception as e:
        print(f"[store] upsert_ai_mysql: {e}")
    return ok


def load_ai_blob(report_file: str) -> Optional[Dict[str, Any]]:
    """只读取 blobs.ai，避免为了一个可选结果组装整个 2GB 报告视图。"""
    dbp = db_path_for_report(report_file)
    if not dbp.exists():
        return None
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        value = _load_one_blob(conn, "ai")
        return value if isinstance(value, dict) else None
    finally:
        conn.close()




# 重字段：摘要接口不返回，改走 section 分页
HEAVY_VIEW_KEYS = {
    "file_scans", "processes", "services", "scheduled_tasks", "startup_items",
    "installed_programs", "users", "usb_devices", "prefetch_files",
    "established_connections", "open_ports", "network", "hosts_file",
    "firewall_rules", "ps_history", "ps_artifacts", "browser_artifacts",
    "user_registry", "services_registry", "network_registry", "run_mru",
    "recycle_bin", "wmi_subscriptions", "wmi_namespaces", "environment",
    "hotfixes", "drivers", "driver_entries", "dns_cache_entries",
    "office_artifacts", "wifi_profiles", "event_log_summary", "event_logs",
    "system_info", "usn_journal", "vss_shadows", "bits_jobs", "audit_pol", "vault_creds",
    "net_sessions", "net_shares", "execution_artifacts", "remote_access", "security_extras",
    "event_log_coverage", "system_timezone", "file_scan_roots",
}

_SUMMARY_BLOB_NAMES = (
    "summary", "summary_aggregated", "pipeline", "timeline", "ai",
    "analysis_meta", "findings_raw_sample", "findings_by_module", "collection_quality",
)

# 列表/轻量视图每条告警最多带几条证据预览，完整证据走 finding-evidence 接口
_HASH_IN_EV = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_FILE_EV_PREFIX = re.compile(r"^(文件|文件哈希)[：:]\s*", re.I)


def enrich_linux_persistence_evidence(rid: str, items: List[Any]) -> List[Any]:
    """旧 Linux 告警证据常只有规则标题；按 report + rule_id 补命中上下文（仅响应侧）。"""
    if not rid or not items:
        return items
    need = False
    for it in items:
        if not isinstance(it, dict):
            continue
        mid = str(it.get("matcher") or it.get("source") or "").lower()
        if "linux" in mid or str(it.get("source") or "") == "linux_persistence":
            need = True
            break
    if not need:
        return items
    report_path = P.resolve_report_json(rid)
    if not report_path or not Path(report_path).is_file():
        return items
    try:
        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)
    except Exception:
        return items
    if not isinstance(report, dict):
        return items
    try:
        from .matchers.linux_persistence import enrich_linux_finding_items
        return enrich_linux_finding_items(report, items)
    except Exception:
        return items


def _process_index_from_conn(conn) -> Dict[int, Dict[str, str]]:
    try:
        from .net_process import build_process_index
        raw = _load_one_blob(conn, "processes") or []
        return build_process_index(raw if isinstance(raw, list) else [])
    except Exception:
        return {}


def enrich_network_finding_process(rid: str, items: List[Any]) -> List[Any]:
    """旧外联/IOC 网络告警证据常只有 PID；按进程表回填进程名。"""
    if not rid or not items:
        return items
    need = False
    for it in items:
        if not isinstance(it, dict):
            continue
        extra = it.get("extra") if isinstance(it.get("extra"), dict) else {}
        if extra.get("process_name"):
            continue
        matcher = str(it.get("matcher") or "").lower()
        cat = str(it.get("category") or it.get("type") or "")
        ev = str(it.get("evidence") or it.get("reason") or "")
        if matcher == "network" or "外联" in cat or cat in ("网络外联", "网络IOC"):
            need = True
            break
        if matcher in ("ioc", "ioc_db") and ("外联" in ev or extra.get("remote")):
            need = True
            break
    if not need:
        return items
    dbp = _resolve_db_path(rid) or P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not dbp or not Path(dbp).is_file():
        return items
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        idx = _process_index_from_conn(conn)
    finally:
        conn.close()
    if not idx:
        return items
    try:
        from .net_process import enrich_network_findings
        return enrich_network_findings(items, idx)
    except Exception:
        return items






def _resolve_db_path(report_file: str) -> Optional[Path]:
    dbp = db_path_for_report(report_file)
    if dbp.exists():
        return dbp
    if INDEX_DB.exists():
        conn = _connect(INDEX_DB)
        try:
            _init_index(conn)
            row = conn.execute("SELECT db_path FROM reports WHERE file=?", (P.report_id(report_file),)).fetchone()
            if row and row["db_path"]:
                rel = config.REPORTS_DIR / row["db_path"]
                if rel.exists():
                    return rel
        finally:
            conn.close()
    return None


def _load_findings_from_conn(conn) -> List[Dict[str, Any]]:
    findings = []
    for r in conn.execute("SELECT * FROM findings_agg"):
        item = {
            "id": r["id"],
            "category": r["category"],
            "severity": r["severity"],
            "title": r["title"],
            "count": r["count"],
            "evidence": _jload(r["evidence"], []),
            "sources": _jload(r["sources"], []),
            "rule_id": r["rule_id"],
            "matcher": r["matcher"],
            "type": r["category"],
            "name": r["title"],
        }
        extra = _jload(r["extra"], {}) or {}
        item.update(extra)
        if not item.get("reason"):
            ev = item.get("evidence")
            item["reason"] = ev[0] if isinstance(ev, list) and ev else item["title"]
        findings.append(item)
    try:
        from .matchers.persistence import filter_stale_microsoft_com_task_findings
        findings = filter_stale_microsoft_com_task_findings(findings)
    except Exception:
        pass
    return findings


_FINDINGS_CACHE: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
# 每份报告一个槽（LRU）。原来是全局单槽：并发分析/浏览多份报告时
# 后一次查询会顶掉前一次的缓存，命中率趋近 0，每次都要重跑百万行证据补全。
_FINDINGS_CACHE_MAX = 16
_FINDINGS_LOCK = threading.Lock()
_FINDINGS_LOAD_LOCKS: Dict[str, threading.Lock] = {}
_FINDINGS_LOAD_GUARD = threading.Lock()


def _findings_cache_get(cache_key: str) -> Optional[List[Dict[str, Any]]]:
    with _FINDINGS_LOCK:
        items = _FINDINGS_CACHE.get(cache_key)
        if items is None:
            return None
        _FINDINGS_CACHE.move_to_end(cache_key)
        return list(items)


def _findings_cache_put(cache_key: str, items: List[Dict[str, Any]]) -> None:
    with _FINDINGS_LOCK:
        _FINDINGS_CACHE[cache_key] = list(items)
        _FINDINGS_CACHE.move_to_end(cache_key)
        while len(_FINDINGS_CACHE) > _FINDINGS_CACHE_MAX:
            _FINDINGS_CACHE.popitem(last=False)


def _findings_load_lock(rid: str) -> threading.Lock:
    with _FINDINGS_LOAD_GUARD:
        lk = _FINDINGS_LOAD_LOCKS.get(rid)
        if lk is None:
            lk = threading.Lock()
            _FINDINGS_LOAD_LOCKS[rid] = lk
        return lk


def invalidate_findings_cache(rid: str = "") -> None:
    with _FINDINGS_LOCK:
        if not rid:
            _FINDINGS_CACHE.clear()
            return
        # key 形如 "<rid>|<result_mtime>|<db_mtime>"，同一 rid 可能有多个历史 key
        for k in [k for k in _FINDINGS_CACHE if k.startswith(f"{rid}|")]:
            _FINDINGS_CACHE.pop(k, None)


def _result_findings_from_path(rp: Path) -> List[Dict[str, Any]]:
    raw = json.loads(rp.read_text(encoding="utf-8"))
    an = raw.get("analysis") if isinstance(raw, dict) else {}
    out: List[Dict[str, Any]] = []
    for x in (
        (an or {}).get("findings_aggregated")
        or (an or {}).get("findings")
        or []
    ):
        if isinstance(x, dict):
            out.append(x)
    return out


def _load_fresh_findings(report_file: str) -> List[Dict[str, Any]]:
    """告警读数：按 mtime 在 result.json 与 analysis.db 中取较新者，最后回退 MySQL。

    light 只保证更新 result.json（并可同步 findings 到 analysis.db/MySQL）；
    若仍无条件地优先读库，会继续展示上一次 full 的旧误报。
    """
    rid = P.report_id(report_file)
    rp = P.result_json_path(rid)
    result_mtime = 0.0
    dbp = _resolve_db_path(report_file)
    db_mtime = 0.0
    try:
        if rp and rp.is_file():
            result_mtime = float(rp.stat().st_mtime or 0)
    except Exception:
        result_mtime = 0.0
    try:
        if dbp and Path(dbp).is_file():
            db_mtime = float(Path(dbp).stat().st_mtime or 0)
    except Exception:
        db_mtime = 0.0

    cache_key = f"{rid}|{result_mtime}|{db_mtime}"
    hit = _findings_cache_get(cache_key)
    if hit is not None:
        try:
            from .mitre import enrich_findings_list
            return enrich_findings_list(hit)
        except Exception:
            return hit

    lk = _findings_load_lock(rid)
    with lk:
        hit = _findings_cache_get(cache_key)
        if hit is not None:
            return hit
        items = _load_fresh_findings_uncached(rid, rp, result_mtime, dbp, db_mtime)
        # 证据路径/进程名补全也很重（百万 files 表）；缓存最终结果，
        # 避免总览的统计、风险列表、分析列表重复执行同一批查询。
        try:
            items = enrich_ioc_evidence_paths(rid, items)
        except Exception:
            pass
        try:
            items = enrich_linux_persistence_evidence(rid, items)
        except Exception:
            pass
        try:
            items = enrich_network_finding_process(rid, items)
        except Exception:
            pass
        try:
            from .mitre import enrich_findings_list
            items = enrich_findings_list(items)
        except Exception:
            pass
        _findings_cache_put(cache_key, items)
        return list(items)


def _filter_known_task_fps(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """读库/读 result 时滤掉已知系统 COM 计划任务误报（无需用户白名单）。"""
    if not items:
        return items
    try:
        from .matchers.persistence import filter_stale_microsoft_com_task_findings
        return filter_stale_microsoft_com_task_findings(items)
    except Exception:
        return items


def _load_fresh_findings_uncached(
    rid: str,
    rp: Optional[Path],
    result_mtime: float,
    dbp: Any,
    db_mtime: float,
) -> List[Dict[str, Any]]:
    result_items: List[Dict[str, Any]] = []
    if rp and rp.is_file() and result_mtime:
        try:
            result_items = _result_findings_from_path(rp)
        except Exception:
            result_items = []

    # result.json 更新（light）→ 优先 result，且不要为了比 mtime 去打开 2GB analysis.db
    if result_items and result_mtime >= db_mtime:
        return _filter_known_task_fps(result_items)

    db_items: List[Dict[str, Any]] = []
    if dbp and Path(dbp).is_file():
        try:
            conn = _connect(Path(dbp))
            try:
                db_items = _load_findings_from_conn(conn)
            finally:
                conn.close()
        except Exception:
            db_items = []

    if db_items:
        return _filter_known_task_fps(db_items)
    if result_items:
        return _filter_known_task_fps(result_items)

    try:
        from .mysql_store import load_analysis_from_mysql
        ma = load_analysis_from_mysql(rid)
        if ma and ma.get("findings_aggregated"):
            return _filter_known_task_fps(
                [x for x in (ma.get("findings_aggregated") or []) if isinstance(x, dict)]
            )
    except Exception:
        pass
    return []




def _file_sig_index_for_processes(conn, items: List[Any], rid: str = "") -> Dict[str, Dict[str, Any]]:
    """为当前页进程的未签模块路径，从 files 表批量取 Valid 签名。"""
    need: List[str] = []
    seen: Set[str] = set()
    try:
        from .matchers.windows_process import _iter_modules, _module_path
        from .matchers.persistence import _is_unsigned
    except Exception:
        return {}
    for it in items or []:
        if not isinstance(it, dict):
            continue
        for m in _iter_modules(it):
            if not _is_unsigned(m):
                continue
            mp = _module_path(m)
            if not mp:
                continue
            low = mp.lower()
            if low in seen:
                continue
            seen.add(low)
            need.append(mp)
    if not need:
        return {}
    # 调用方通常已经持有当前报告连接；仅当当前库确实没有 files 时才走懒入库兜底。
    if rid:
        try:
            has_files = conn.execute("SELECT 1 FROM files LIMIT 1").fetchone()
        except Exception:
            has_files = None
        if not has_files:
            try:
                return lookup_file_sigs_by_paths(rid, need) or {}
            except Exception:
                pass
    out: Dict[str, Dict[str, Any]] = {}
    try:
        _ensure_files_path_norm_index(conn, create=False)
        for i in range(0, len(need), 400):
            chunk = need[i : i + 400]
            ph = ",".join("?" * len(chunk))
            lows = [x.lower().replace("/", "\\") for x in chunk]
            rows = conn.execute(
                "SELECT full_path,signed,signer,sig_status,sig_type,company "
                f"FROM files WHERE lower(replace(full_path,'/','\\')) IN ({ph})",
                lows,
            ).fetchall()
            for r in rows or []:
                fp = str(r["full_path"] or "").strip()
                if not fp:
                    continue
                keys = r.keys()
                out[fp.replace("/", "\\").lower()] = {
                    "full_path": fp,
                    "signed": bool(r["signed"]),
                    "signer": r["signer"] or "",
                    "sig_status": r["sig_status"] or "",
                    "sig_type": (r["sig_type"] if "sig_type" in keys else "") or "",
                    "company": (r["company"] if "company" in keys else "") or "",
                }
    except Exception:
        return out
    return out


def load_process_detail(report_file: str, pid: int) -> Optional[Dict[str, Any]]:
    """按 PID 返回单个进程完整详情（含模块/DLL、父/子进程名称与路径）。"""
    rid = P.report_id(report_file)
    dbp = _resolve_db_path(rid)
    if not dbp:
        return None
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        raw = _load_one_blob(conn, "processes") or []
        if not isinstance(raw, list):
            return None
        target = None
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                item_pid = int(item.get("pid") if item.get("pid") is not None else item.get("PID"))
            except (TypeError, ValueError):
                continue
            if item_pid == int(pid):
                target = item
                break
        if target is None:
            return None
        try:
            from .text_fix import sanitize_process_modules, fix_tree
            pack = sanitize_process_modules({"processes": fix_tree([target], depth=0)})
            fixed = pack.get("processes") or [target]
            target = fixed[0] if fixed else target
        except Exception:
            pass
        target = dict(target)
        try:
            sig_idx = _file_sig_index_for_processes(conn, [target], rid=str(rid or ""))
            if sig_idx:
                from .matchers.windows_process import enrich_process_modules_from_file_sigs
                enrich_process_modules_from_file_sigs(target, sig_idx)
        except Exception:
            pass
        return _enrich_process_family(target, raw)
    finally:
        conn.close()












def load_timeline_only(report_file: str) -> Optional[List[Dict[str, Any]]]:
    """只读 timeline blob / MySQL，不加载大段采集与全量 view。"""
    # MySQL 优先
    try:
        from .mysql_store import load_analysis_from_mysql
        ma = load_analysis_from_mysql(report_file)
        if ma and isinstance(ma.get("timeline"), list) and ma["timeline"]:
            return ma["timeline"]
    except Exception:
        pass
    dbp = _resolve_db_path(report_file)
    if not dbp:
        return None
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        tl = _load_one_blob(conn, "timeline")
        if isinstance(tl, list) and tl:
            return tl
    except Exception:
        return None
    finally:
        conn.close()
    return None









_FILE_TREE_COLS = (
    "full_path,name,path,ext,size,company,product,description,"
    "file_version,signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system,"
    "mtime,mode,owner,file_group"
)

# 路径推断分目录（files 表无 root 列时用）
_ROOT_SQL = {
    "Users": (
        "(instr(lower(replace(full_path,'/','\\')), '\\users\\')>0 "
        "OR lower(full_path) LIKE 'c:\\users%')"
    ),
    "ProgramData": "instr(lower(replace(full_path,'/','\\')), 'programdata')>0",
    "ProgramFilesX86": "instr(lower(replace(full_path,'/','\\')), 'program files (x86)')>0",
    "ProgramFiles": (
        "(instr(lower(replace(full_path,'/','\\')), 'program files')>0 "
        "AND instr(lower(replace(full_path,'/','\\')), 'program files (x86)')=0)"
    ),
    "Windows": (
        "(instr(lower(replace(full_path,'/','\\')), '\\windows\\')>0 "
        "OR lower(full_path) LIKE 'c:\\windows%')"
    ),
}
_ROOT_ORDER = ("Users", "ProgramData", "ProgramFiles", "ProgramFilesX86", "Windows", "Other")


# ToDesk 等 Mars xlog：正文用厂商密钥加密，平台无法解读，只能说明并指向明文缓冲
_XLOG_SUFFIX_RX = re.compile(r"_\d{4}_\d{2}_\d{2}\.xlog$", re.I)


def load_file_content(rid: str, full_path: str) -> Optional[Dict[str, Any]]:
    """按完整路径取单个文件的元数据与正文（文件树点开查看）。"""
    fp = re.sub(r"\\+", r"\\", str(full_path or "").replace("/", "\\").strip())
    if not fp:
        return None
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return None
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        cols = f"{_FILE_TREE_COLS},content"
        row = conn.execute(f"SELECT {cols} FROM files WHERE full_path=?", (fp,)).fetchone()
        if row is None:
            # 大小写 / 分隔符差异：按父目录索引取一批再比对
            parent = _norm_file_path(fp.rsplit("\\", 1)[0] if "\\" in fp else "")
            want = _norm_file_path(fp)
            for r in conn.execute(
                f"SELECT {cols} FROM files WHERE parent_path_norm=? LIMIT 5000", (parent,),
            ).fetchall():
                if _norm_file_path(r["full_path"]) == want:
                    row = r
                    break
        if row is None:
            return None
        item = _file_row_to_tree_item(row)
        content = str(row["content"] or "")
        item["content"] = content
        item["has_content"] = bool(content)
        name = str(item.get("name") or "")
        kind = "text" if content else "none"
        note = ""
        related = ""
        if name.lower().endswith(".xlog"):
            kind = "encrypted"
            note = (
                "Mars xlog 加密日志（ToDesk 等使用）：正文经压缩并用厂商密钥加密，平台无法解读。"
                "文件修改时间约等于该日志最后写入时间（会话日志即会话结束时间）；"
                "写盘前的明文尾部可看同目录 cache 下同名 .mmap3。"
            )
            stem = _XLOG_SUFFIX_RX.sub("", name)
            parent_disp = str(item.get("full_path") or fp).rsplit("\\", 1)[0]
            cand = f"{parent_disp}\\cache\\{stem}.mmap3"
            hit = conn.execute(
                "SELECT full_path FROM files WHERE parent_path_norm=? AND lower(name)=?",
                (_norm_file_path(f"{parent_disp}\\cache"), f"{stem}.mmap3".lower()),
            ).fetchone()
            related = str(hit["full_path"]) if hit else ""
            if not related:
                note += f"（未采到 {cand}）"
        elif not content:
            note = "采集时未保留该文件正文（非文本类型、体积超限、被占用或超出采集预算）。"
        item["content_kind"] = kind
        item["content_note"] = note
        item["related_path"] = related
        return item
    finally:
        conn.close()


def _root_where_clause(root: str) -> Optional[str]:
    return _report_root_where_clause(root, _ROOT_SQL)


def _patch_index_file_count(rid: str, n_files: int) -> None:
    """文件入库后回写索引 files 字段，避免列表/摘要一直显示 0。"""
    if n_files < 0:
        return
    rid0 = P.report_id(rid)
    try:
        if INDEX_DB.exists():
            conn = _connect(INDEX_DB)
            try:
                _init_index(conn)
                conn.execute(
                    "UPDATE reports SET files=?, updated_at=? WHERE file=?",
                    (int(n_files), time.time(), rid0),
                )
                conn.commit()
            finally:
                conn.close()
            invalidate_list_cache()
    except Exception as e:
        print(f"[db_store] patch index files: {e}")
    try:
        from .mysql_db import mysql_ready, connect_mysql
        if mysql_ready():
            conn = connect_mysql()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE reports SET files=%s, updated_at=%s WHERE file=%s",
                        (int(n_files), time.time(), rid0),
                    )
                conn.commit()
            finally:
                conn.close()
    except Exception:
        pass




def db_exists(report_file: str) -> bool:
    return P.resolve_analysis_db(report_file) is not None


def migrate_from_json_if_needed(report_file: str) -> bool:
    """若有 result 且无 db，导入一次；并尽量迁入目录。"""
    rid = P.report_id(report_file)
    try:
        P.migrate_report_to_folder(rid)
    except Exception:
        pass
    if db_exists(rid):
        return True
    rp = P.resolve_result_json(rid)
    report_path = P.resolve_report_json(rid)
    if not report_path or not rp:
        return False
    try:
        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)
        with open(rp, encoding="utf-8") as f:
            analysis = (json.load(f) or {}).get("analysis") or {}
        if not analysis.get("findings_aggregated") and not analysis.get("findings"):
            return False
        save_report_db(report, analysis, rid)
        return True
    except Exception:
        return False


def rebuild_index_from_dbs() -> int:
    """扫描报告目录，清空后重建 index（与磁盘一致）。"""
    try:
        P.migrate_all_flat_reports()
    except Exception as e:
        print("[rebuild] migrate:", e)
    clear_index()
    n = 0
    for rid in P.iter_report_ids(300):
        if not P.resolve_report_json(rid) and not P.resolve_analysis_db(rid):
            continue
        if migrate_from_json_if_needed(rid) or db_exists(rid):
            view = load_view_from_db(rid)
            if not view:
                continue
            a = view.get("analysis") or {}
            sa = a.get("summary_aggregated") or {}
            s = a.get("summary") or {}
            dbp = db_path_for_report(rid)
            upsert_index({
                "file": rid,
                "db_path": str(dbp.relative_to(config.REPORTS_DIR)).replace("\\", "/") if dbp.exists() else "",
                "hostname": view.get("hostname"),
                "collect_time": view.get("collect_time"),
                "ip": pick_primary_ip(view.get("ip") or ""),
                "issues": sa.get("total") or s.get("total") or 0,
                "raw_issues": sa.get("raw_total") or s.get("total") or 0,
                "analyzed": True,
                "processes": len(view.get("processes") or []),
                "services": len(view.get("services") or []),
                "files": len(view.get("file_scans") or []),
                "os_family": view.get("os_family") or "",
                "os": view.get("os") or "",
            })
            n += 1
        else:
            rp = P.resolve_report_json(rid)
            if not rp:
                continue
            try:
                with open(rp, encoding="utf-8") as f:
                    d = json.load(f)
                upsert_index({
                    "file": rid,
                    "db_path": "",
                    "hostname": d.get("hostname"),
                    "collect_time": d.get("collect_time"),
                    "ip": pick_primary_ip(d.get("ip") or ""),
                    "issues": 0,
                    "raw_issues": 0,
                    "analyzed": False,
                    "processes": len(d.get("processes") or []),
                    "services": len(d.get("services") or []),
                    "files": len(d.get("file_scans") or []),
                    "os_family": d.get("os_family") or "",
                    "os": d.get("os") or "",
                })
                n += 1
            except Exception:
                pass
    return n


from .report_file_query import (
    query_files, query_files_under_dir, query_dir_subtree_stats, query_file_directory,
)


from .report_search_service import (
    _fanout_search, _search_one_report, search_findings_local, search_report_content_local,
)

from .report_file_tree import load_files_for_tree

from .report_read_service import load_section_page, load_summary_view, load_sections_batch

from .report_view_loader import load_view_from_db

from .report_write_service import save_report_db

from .report_evidence_service import enrich_ioc_evidence_paths, load_finding_evidence_page

from .report_metadata_service import rename_hostname, backfill_os_family_index, sync_findings_to_analysis_db

from .report_file_lookup import load_event_logs_for_match, lookup_file_sigs_by_paths
