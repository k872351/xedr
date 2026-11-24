"""Report database schema and migration lifecycle."""
import sqlite3
import threading
import os
from pathlib import Path
from typing import Set
from .sqlite_schema_tools import schema_migration


REPORT_SCHEMA_VERSION = 1


def _init_schema_uncached(conn: sqlite3.Connection) -> None:
    # executescript commits an existing transaction implicitly. Keep schema
    # changes within a savepoint so callers can roll back as a unit.
    with schema_migration(conn):
        _apply_report_schema(conn)
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version < REPORT_SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version={REPORT_SCHEMA_VERSION}")


def _apply_report_schema(conn: sqlite3.Connection) -> None:
    statements = (
        """
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS findings_agg (
            id TEXT PRIMARY KEY,
            category TEXT,
            severity TEXT,
            title TEXT,
            count INTEGER,
            evidence TEXT,
            sources TEXT,
            rule_id TEXT,
            matcher TEXT,
            extra TEXT
        );
        CREATE TABLE IF NOT EXISTS blobs (name TEXT PRIMARY KEY, data TEXT);
            CREATE TABLE IF NOT EXISTS files (
            full_path TEXT PRIMARY KEY,
            name TEXT,
            path TEXT,
            parent_path_norm TEXT,
            ext TEXT,
            size INTEGER,
            company TEXT,
            product TEXT,
            description TEXT,
            file_version TEXT,
            signed INTEGER DEFAULT 0,
            signer TEXT,
            sig_status TEXT,
            sig_type TEXT,
            magic_hex TEXT,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            hidden INTEGER DEFAULT 0,
            system INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
        CREATE INDEX IF NOT EXISTS idx_files_name ON files(name);
        CREATE INDEX IF NOT EXISTS idx_files_ext ON files(ext);
        CREATE TABLE IF NOT EXISTS file_directories (
            path_norm TEXT PRIMARY KEY,
            parent_path_norm TEXT,
            name TEXT,
            full_path TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_file_dirs_parent ON file_directories(parent_path_norm);
        CREATE TABLE IF NOT EXISTS event_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel TEXT,
            event_id INTEGER,
            provider TEXT,
            time TEXT,
            level TEXT,
            computer TEXT,
            message TEXT,
            fields TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_elog_channel ON event_logs(channel);
        CREATE INDEX IF NOT EXISTS idx_elog_eid ON event_logs(event_id);
        CREATE INDEX IF NOT EXISTS idx_elog_time ON event_logs(time);
        CREATE TABLE IF NOT EXISTS entity_lists (
            section TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            count INTEGER DEFAULT 0
        );
        """
    )
    for statement in statements.split(";"):
        if statement.strip():
            conn.execute(statement)
    existing_columns = {row[1] for row in conn.execute("PRAGMA table_info(files)")}
    for col, typ in (
        ("parent_path_norm", "TEXT"),
        ("company", "TEXT"),
        ("product", "TEXT"),
        ("description", "TEXT"),
        ("file_version", "TEXT"),
        ("signed", "INTEGER DEFAULT 0"),
        ("signer", "TEXT"),
        ("sig_status", "TEXT"),
        ("sig_type", "TEXT"),
        ("magic_hex", "TEXT"),
        ("md5", "TEXT"),
        ("sha1", "TEXT"),
        ("sha256", "TEXT"),
        ("hidden", "INTEGER DEFAULT 0"),
        ("system", "INTEGER DEFAULT 0"),
        ("mtime", "TEXT"),
        ("mode", "TEXT"),
        ("owner", "TEXT"),
        ("file_group", "TEXT"),
        ("content", "TEXT"),
    ):
        if col not in existing_columns:
            conn.execute(f"ALTER TABLE files ADD COLUMN {col} {typ}")
    for idx_sql in (
        "CREATE INDEX IF NOT EXISTS idx_files_parent_norm ON files(parent_path_norm)",
        "CREATE INDEX IF NOT EXISTS idx_files_md5 ON files(md5)",
        "CREATE INDEX IF NOT EXISTS idx_files_sha1 ON files(sha1)",
        "CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256)",
        "CREATE INDEX IF NOT EXISTS idx_files_mtime ON files(mtime)",
        # 路径归一化索引只在进程签名回查时按需建，勿塞进每次读库的 _init_schema：
        # 百万行 files 表上 CREATE INDEX 会把告警/总览首屏拖到十几秒。
    ):
        conn.execute(idx_sql)


_SCHEMA_READY: Set[str] = set()
_SCHEMA_READY_LOCK = threading.RLock()
_SCHEMA_READY_MAX = 2048


def _schema_conn_key(conn: sqlite3.Connection) -> str:
    try:
        rows = conn.execute("PRAGMA database_list").fetchall()
        for row in rows:
            name = str(row[1] if not hasattr(row, "keys") else row["name"])
            if name == "main":
                path = str(row[2] if not hasattr(row, "keys") else row["file"])
                if not path:
                    return f"conn:{id(conn)}"
                return os.path.normcase(str(Path(path).resolve()))
    except Exception:
        pass
    return f"conn:{id(conn)}"


def _schema_cache_valid(conn: sqlite3.Connection) -> bool:
    """缓存命中后再确认核心表真实存在（一次 sqlite_master 查询，走内存页，可忽略不计）。"""
    try:
        if int(conn.execute("PRAGMA user_version").fetchone()[0]) < REPORT_SCHEMA_VERSION:
            return False
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"meta", "findings_agg", "blobs", "files", "file_directories", "event_logs", "entity_lists"}.issubset(tables):
            return False
        columns = {row[1] for row in conn.execute("PRAGMA table_info(files)")}
        return {"parent_path_norm", "sha256", "mtime", "content"}.issubset(columns)
    except Exception:
        return False


def _init_schema(conn: sqlite3.Connection) -> None:
    """每个数据库/进程只执行一次 DDL 迁移，普通 GET 不重复跑整套 schema/index 检查。

    缓存 key 是库文件路径，而重新分析会删库重建：路径不变、表却没了，
    旧逻辑会跳过建表并让后续查询报 "no such table: meta"（summary 接口 500 的根因）。
    因此命中缓存时再校验一次，发现失效就重建 schema。
    """
    key = _schema_conn_key(conn)
    # The database itself is the authority across processes. Avoid holding
    # the process-wide cache lock while waiting for a database write lock.
    if not _schema_cache_valid(conn):
        _init_schema_uncached(conn)
    if key.startswith("conn:"):
        return
    with _SCHEMA_READY_LOCK:
        if key not in _SCHEMA_READY and len(_SCHEMA_READY) >= _SCHEMA_READY_MAX:
            _SCHEMA_READY.pop()
        _SCHEMA_READY.add(key)


