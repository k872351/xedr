"""Index maintenance for persisted report directories."""
from __future__ import annotations

import sqlite3

from .file_normalization import _directory_rows, _norm_file_path, _file_parent


_FILES_PATH_NORM_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_files_fullpath_norm "
    "ON files(lower(replace(full_path,'/','\\')))"
)


def _ensure_files_path_norm_index(conn: sqlite3.Connection, *, create: bool = True) -> bool:
    """保证 files 路径归一化索引存在。

    create=False：仅探测，绝不在 GET 读路径上 CREATE INDEX（大库首建可达数秒）。
    create=True：入库/分析时补建。
    """
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_files_fullpath_norm' LIMIT 1"
        ).fetchone()
        if row:
            return True
        if not create:
            return False
        conn.execute(_FILES_PATH_NORM_INDEX_SQL)
        return True
    except sqlite3.OperationalError:
        return False


def _ensure_files_hash_indexes(conn: sqlite3.Connection) -> None:
    for col in ("md5", "sha1", "sha256"):
        try:
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_files_{col} ON files({col})")
        except sqlite3.OperationalError:
            pass


def _rebuild_directory_index(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT full_path,name,path FROM files").fetchall()
    files = [
        {"full_path": r["full_path"] or "", "name": r["name"] or "", "path": r["path"] or ""}
        for r in rows
    ]
    conn.execute("DELETE FROM file_directories")
    directory_rows = _directory_rows(files)
    if directory_rows:
        conn.executemany(
            "INSERT OR REPLACE INTO file_directories(path_norm,parent_path_norm,name,full_path) "
            "VALUES(?,?,?,?)",
            directory_rows,
        )
    conn.executemany(
        "UPDATE files SET parent_path_norm=? WHERE full_path=?",
        [(_norm_file_path(_file_parent(f)), f.get("full_path") or "") for f in files],
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES('file_directory_index_count',?)",
        (str(len(directory_rows)),),
    )


def _ensure_directory_index(conn: sqlite3.Connection) -> None:
    dir_count = int(conn.execute("SELECT COUNT(1) FROM file_directories").fetchone()[0] or 0)
    need = False
    if dir_count:
        # Windows 报告无需扫描百万 files 判断 Linux 旧索引问题。
        try:
            row = conn.execute("SELECT value FROM meta WHERE key='os_family'").fetchone()
            fam = str((row["value"] if row else "") or "").strip().lower()
        except Exception:
            fam = ""
        if fam != "linux":
            return
        # Linux 路径曾错误索引为无前导 \ 的 usr\...，仅 Linux 库检查一次。
        try:
            bad = conn.execute(
                "SELECT 1 FROM file_directories "
                "WHERE path_norm NOT LIKE '\\%' AND path_norm NOT LIKE '_:\\%' LIMIT 1"
            ).fetchone()
            need = bool(bad)
        except Exception:
            need = False
    else:
        file_count = int(conn.execute("SELECT COUNT(1) FROM files").fetchone()[0] or 0)
        need = bool(file_count)
    if need:
        _rebuild_directory_index(conn)
        conn.commit()
