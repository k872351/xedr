"""Focused lookups against the file and event-log tables in a report DB."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from . import paths as P
from .report_db_connection import _connect


def load_event_logs_for_match(rid: str, limit: int = 50000) -> List[Dict[str, Any]]:
    """Load recent event logs for detection matching without loading a full report."""
    from .db_store import _ensure_event_logs_table
    from .report_event_format import _event_log_row_to_dict

    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return []
    conn = _connect(Path(dbp))
    try:
        _ensure_event_logs_table(conn)
        lim = max(1, min(int(limit or 50000), 100000))
        rows = conn.execute(
            "SELECT channel,event_id,provider,time,level,computer,message,fields "
            "FROM event_logs ORDER BY id DESC LIMIT ?",
            (lim,),
        ).fetchall()
        return [_event_log_row_to_dict(row) for row in rows]
    except Exception as exc:
        print(f"[db_store] load_event_logs_for_match: {exc}")
        return []
    finally:
        conn.close()


def lookup_file_sigs_by_paths(
    rid: str, paths: List[str],
) -> Dict[str, Dict[str, Any]]:
    """Look up signature metadata for normalized paths using bounded SQL batches."""
    from .db_store import _ensure_files_path_norm_index

    out: Dict[str, Dict[str, Any]] = {}
    wanted: List[str] = []
    seen = set()
    for value in paths or []:
        path = str(value or "").strip().replace("/", "\\")
        if not path:
            continue
        if path.startswith("\\\\?\\UNC\\"):
            path = "\\" + path[7:]
        elif path.startswith("\\\\?\\"):
            path = path[4:]
        key = path.lower()
        if key not in seen:
            seen.add(key)
            wanted.append(path)
    if not rid or not wanted:
        return out
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return out
    conn = _connect(Path(dbp))
    try:
        try:
            has_files = conn.execute("SELECT 1 FROM files LIMIT 1").fetchone()
        except Exception:
            has_files = None
        if not has_files:
            conn.close()
            try:
                from .collect_pack import ingest_pack_jsonl
                ingest_pack_jsonl(rid)
            except Exception as exc:
                print(f"[db_store] lazy ingest files for sig lookup: {exc}")
            conn = _connect(Path(dbp))
        _ensure_files_path_norm_index(conn, create=False)
        for offset in range(0, len(wanted), 400):
            chunk = wanted[offset:offset + 400]
            placeholders = ",".join("?" * len(chunk))
            lowered = [value.lower() for value in chunk]
            try:
                rows = conn.execute(
                    "SELECT full_path,signed,signer,sig_status,sig_type,company "
                    f"FROM files WHERE lower(replace(full_path,'/','\\')) IN ({placeholders})",
                    lowered,
                ).fetchall()
            except Exception:
                rows = conn.execute(
                    "SELECT full_path,signed,signer,sig_status,sig_type "
                    f"FROM files WHERE lower(replace(full_path,'/','\\')) IN ({placeholders})",
                    lowered,
                ).fetchall()
            for row in rows or []:
                full_path = str(row["full_path"] or "").strip()
                if not full_path:
                    continue
                keys = row.keys()
                out[full_path.replace("/", "\\").lower()] = {
                    "full_path": full_path,
                    "signed": bool(row["signed"]),
                    "signer": row["signer"] or "",
                    "sig_status": row["sig_status"] or "",
                    "sig_type": (row["sig_type"] if "sig_type" in keys else "") or "",
                    "company": (row["company"] if "company" in keys else "") or "",
                }
    except Exception:
        return out
    finally:
        conn.close()
    return out
