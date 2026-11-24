"""Report index row persistence independent of backend orchestration."""
import sqlite3
from typing import Any, Dict
from .paths import report_stem


def upsert_index_row(conn: sqlite3.Connection, row: Dict[str, Any], owner: Dict[str, Any], updated_at: float) -> None:
    conn.execute(
        """
        INSERT INTO reports(file, db_path, hostname, collect_time, ip, issues, raw_issues,
                            analyzed, processes, services, files, updated_at,
                            owner_id, owner_username, os_family, os)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(file) DO UPDATE SET
          db_path=excluded.db_path, hostname=excluded.hostname, collect_time=excluded.collect_time,
          ip=excluded.ip, issues=excluded.issues, raw_issues=excluded.raw_issues,
          analyzed=excluded.analyzed, processes=excluded.processes, services=excluded.services,
          files=excluded.files, updated_at=excluded.updated_at,
          owner_id=CASE WHEN excluded.owner_id!='' THEN excluded.owner_id ELSE reports.owner_id END,
          owner_username=CASE WHEN excluded.owner_username!='' THEN excluded.owner_username ELSE reports.owner_username END,
          os_family=CASE WHEN excluded.os_family!='' THEN excluded.os_family ELSE reports.os_family END,
          os=CASE WHEN excluded.os!='' THEN excluded.os ELSE reports.os END
        """,
        (
            row["file"], row.get("db_path"), row.get("hostname"), row.get("collect_time"),
            row.get("ip"), row.get("issues", 0), row.get("raw_issues", 0),
            1 if row.get("analyzed") else 0, row.get("processes", 0), row.get("services", 0),
            row.get("files", 0), updated_at,
            owner.get("owner_id") or "", owner.get("owner_username") or "",
            str(row.get("os_family") or "").strip().lower(),
            str(row.get("os") or "").strip()[:200],
        ),
    )

def report_index_view(row) -> Dict[str, Any]:
    r = dict(row)
    rid = r["file"]
    return {
        "file": rid,
        "db": r.get("db_path") or "",
        "hostname": r.get("hostname") or "",
        "time": r.get("collect_time") or "",
        "ip": r.get("ip") or "",
        "issues": r.get("issues") or 0,
        "raw_issues": r.get("raw_issues") or 0,
        "analyzed": bool(r.get("analyzed")),
        "processes": r.get("processes") or 0,
        "services": r.get("services") or 0,
        "files": r.get("files") or 0,
        "host_id": r.get("host_id") or "",
        "folder": r.get("folder") or report_stem(rid),
        "owner_id": r.get("owner_id") or "",
        "owner_username": r.get("owner_username") or "",
        "os_family": r.get("os_family") or "",
        "os": r.get("os") or "",
    }


_row_from_sqlite = report_index_view


def list_index_rows(conn: sqlite3.Connection, limit: int, *, admin: bool, uid: str = '', uname: str = '') -> list[dict]:
    if admin:
        rows = conn.execute(
            'SELECT * FROM reports ORDER BY collect_time DESC, file DESC LIMIT ?', (limit,)
        )
    else:
        rows = conn.execute(
            '''SELECT * FROM reports
               WHERE (owner_id!='' AND owner_id=?)
                  OR (COALESCE(TRIM(owner_id),'')='' AND owner_username!='' AND owner_username=?)
               ORDER BY collect_time DESC, file DESC LIMIT ?''',
            (uid, uname, limit),
        )
    return [_row_from_sqlite(row) for row in rows]
