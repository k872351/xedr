"""Batch persistence for existing report file and event records."""
import sqlite3
from typing import Any, Iterable

from .report_file_format import _file_row_tuple
from .report_event_format import _elog_row_tuple


_FILE_INSERT_SQL = (
    "INSERT INTO files(full_path,name,path,parent_path_norm,ext,size,company,product,description,"
    "file_version,signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system,"
    "mtime,mode,owner,file_group,content) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
    "ON CONFLICT(full_path) DO UPDATE SET "
    "name=excluded.name,path=excluded.path,parent_path_norm=excluded.parent_path_norm,"
    "ext=excluded.ext,size=excluded.size,company=excluded.company,product=excluded.product,"
    "description=excluded.description,file_version=excluded.file_version,signed=excluded.signed,"
    "signer=excluded.signer,sig_status=excluded.sig_status,sig_type=excluded.sig_type,"
    "magic_hex=excluded.magic_hex,md5=excluded.md5,sha1=excluded.sha1,sha256=excluded.sha256,"
    "hidden=excluded.hidden,system=excluded.system,mtime=excluded.mtime,mode=excluded.mode,"
    "owner=excluded.owner,file_group=excluded.file_group,"
    "content=CASE WHEN excluded.content!='' THEN excluded.content ELSE files.content END"
)


_ELOG_INSERT_SQL = (
    "INSERT INTO event_logs(channel,event_id,provider,time,level,computer,message,fields) "
    "VALUES(?,?,?,?,?,?,?,?)"
)


def _insert_rows(conn: sqlite3.Connection, rows: Iterable[Any], sql: str, serialize, cancel_check=None) -> int:
    batch = []
    count = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        batch.append(serialize(row))
        count += 1
        if len(batch) >= 2000:
            if cancel_check and cancel_check():
                raise InterruptedError('job cancelled')
            conn.executemany(sql, batch)
            batch.clear()
    if batch:
        if cancel_check and cancel_check():
            raise InterruptedError('job cancelled')
        conn.executemany(sql, batch)
    return count


def _insert_file_rows(conn: sqlite3.Connection, files: Iterable[Any], cancel_check=None) -> int:
    return _insert_rows(conn, files, _FILE_INSERT_SQL, _file_row_tuple, cancel_check)


def _insert_event_log_rows(conn: sqlite3.Connection, events: Iterable[Any], cancel_check=None) -> int:
    return _insert_rows(conn, events or [], _ELOG_INSERT_SQL, _elog_row_tuple, cancel_check)
