# -*- coding: utf-8 -*-
"""Streaming and batch persistence for report file and event-log records."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import paths as P
from .report_batch_rows import _insert_event_log_rows, _insert_file_rows
from .report_blob_metadata import _derive_file_scan_roots
from .report_db_connection import _connect
from .file_normalization import _directory_rows, _norm_hash_field
from .report_directory_index import (
    _ensure_directory_index, _ensure_files_path_norm_index, _rebuild_directory_index,
)
from .report_json import _jdump
from .report_schema import _init_schema


def _patch_index_file_count(rid: str, n_files: int) -> None:
    from . import db_store
    db_store._patch_index_file_count(rid, n_files)


def ingest_file_scans(rid: str, files: Optional[List[Any]] = None, cancel_check=None) -> int:
    """分析前把 file_scans 写入 analysis.db，供按条件查询。

    数量一致时默认跳过；若源数据带 md5/sha* 而库内没有哈希，则强制重写。
    """
    dbp = P.db_path_for_write(rid)
    dbp.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        existing = int(conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"] or 0)
        rows = [f for f in (files or []) if isinstance(f, dict)]

        def _src_has_any_hash() -> bool:
            # 只需判断「有没有」，勿全表计数（大报告入库跳过路径会扫几十万次）
            for f in rows:
                if _norm_hash_field(f.get("md5") or f.get("MD5")) or _norm_hash_field(
                    f.get("sha1") or f.get("SHA1")
                ) or _norm_hash_field(f.get("sha256") or f.get("SHA256")):
                    return True
            return False

        def _db_has_any_hash() -> bool:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
            if not ({"md5", "sha1", "sha256"} & cols):
                return False
            try:
                row = conn.execute(
                    "SELECT 1 AS x FROM files WHERE "
                    "IFNULL(md5,'')!='' OR IFNULL(sha1,'')!='' OR IFNULL(sha256,'')!='' "
                    "LIMIT 1"
                ).fetchone()
                return bool(row)
            except sqlite3.OperationalError:
                return False

        # 数量一致时先走快速跳过；仅在「源有哈希、库无哈希」时强制重写
        force = False
        if existing > 0 and (not rows or existing == len(rows)):
            if rows and not _db_has_any_hash() and _src_has_any_hash():
                force = True
            else:
                _ensure_directory_index(conn)
                _ensure_files_path_norm_index(conn, create=True)
                conn.commit()
                try:
                    _patch_index_file_count(rid, existing)
                except Exception:
                    pass
                return existing
        if not rows:
            conn.commit()
            return existing
        if force:
            print(f"[db] re-ingest file_scans for hashes: rid={rid} files={len(rows)}")
        conn.execute("DELETE FROM files")
        conn.execute("DELETE FROM file_directories")
        n = _insert_file_rows(conn, rows, cancel_check=cancel_check)
        directory_rows = _directory_rows(rows)
        if directory_rows:
            conn.executemany(
                "INSERT OR REPLACE INTO file_directories(path_norm,parent_path_norm,name,full_path) "
                "VALUES(?,?,?,?)",
                directory_rows,
            )
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
            ("file_directory_index_count", str(len(directory_rows))),
        )
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", ("count_file_scans", str(n)))
        roots = _derive_file_scan_roots(rows)
        if roots:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                ("file_scan_roots", _jdump(roots)),
            )
        # 分析入库时建路径索引，避免进程页首开 GET 时 CREATE INDEX 卡 数秒
        _ensure_files_path_norm_index(conn, create=True)
        conn.commit()
        try:
            _patch_index_file_count(rid, n)
        except Exception:
            pass
        ms = int((time.perf_counter() - t0) * 1000)
        print(f"[db] ingest file_scans rid={rid} n={n} ms={ms}")
        try:
            from . import applog
            applog.info("db", f"ingest file_scans rid={rid} n={n} ms={ms}", rid=rid, n=n, ms=ms)
        except Exception:
            pass
        return n
    finally:
        conn.close()


def ingest_event_logs_iter(rid: str, rows_iter, cancel_check=None) -> int:
    """流式写入 event_logs（jsonl），已有数据则跳过。"""
    dbp = P.db_path_for_write(rid)
    dbp.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        try:
            existing = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
        except sqlite3.OperationalError:
            _init_schema(conn)
            existing = 0
        if existing > 0:
            conn.commit()
            return existing
        n = _insert_event_log_rows(conn, rows_iter, cancel_check=cancel_check)
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", ("count_event_logs", str(n)))
        conn.commit()
        print(f"[db] ingest event_logs jsonl rid={rid} n={n}")
        return n
    finally:
        conn.close()


def ingest_file_scans_iter(rid: str, rows_iter, cancel_check=None) -> int:
    """流式写入 files 表（jsonl），已有数据则跳过。"""
    dbp = P.db_path_for_write(rid)
    dbp.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        existing = int(conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"] or 0)
        if existing > 0:
            conn.commit()
            try:
                _patch_index_file_count(rid, existing)
            except Exception:
                pass
            return existing
        n = _insert_file_rows(conn, rows_iter, cancel_check=cancel_check)
        try:
            _rebuild_directory_index(conn)
        except Exception as e:
            print(f"[db] rebuild dir index after jsonl: {e}")
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", ("count_file_scans", str(n)))
        conn.commit()
        try:
            _patch_index_file_count(rid, n)
        except Exception:
            pass
        print(f"[db] ingest file_scans jsonl rid={rid} n={n}")
        return n
    finally:
        conn.close()


def ingest_event_logs(rid: str, events: Optional[List[Any]] = None, cancel_check=None) -> int:
    """把 event_logs 写入 analysis.db 表；已有且数量一致则跳过。"""
    dbp = P.db_path_for_write(rid)
    dbp.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        try:
            existing = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
        except sqlite3.OperationalError:
            _init_schema(conn)
            existing = 0
        rows = [e for e in (events or []) if isinstance(e, dict)]
        if existing > 0 and (not rows or existing == len(rows)):
            conn.commit()
            return existing
        if not rows:
            conn.commit()
            return existing
        conn.execute("DELETE FROM event_logs")
        n = _insert_event_log_rows(conn, rows, cancel_check=cancel_check)
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", ("count_event_logs", str(n)))
        sample = rows[:300]
        conn.execute("DELETE FROM blobs WHERE name=?", ("event_logs",))
        conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("event_logs", _jdump(sample)))
        conn.commit()
        ms = int((time.perf_counter() - t0) * 1000)
        print(f"[db] ingest event_logs rid={rid} n={n} ms={ms}")
        try:
            from . import applog
            applog.info("db", f"ingest event_logs rid={rid} n={n} ms={ms}", rid=rid, n=n, ms=ms)
        except Exception:
            pass
        return n
    finally:
        conn.close()


def _meta_int(rid: str, key: str, default: int = 0) -> int:
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return default
    conn = _connect(Path(dbp))
    try:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        return int(row["value"] or default)
    except Exception:
        return default
    finally:
        conn.close()


