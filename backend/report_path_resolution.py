"""Resolve abbreviated task and startup executable paths from indexed files."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List

from .report_process_files import _apply_file_meta_to_items


def _lookup_files_by_basenames(conn, names: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    want = [str(n or "").strip().lower() for n in names if str(n or "").strip()]
    if not want:
        return out
    try:
        for nm in want[:80]:
            row = conn.execute(
                "SELECT full_path FROM files WHERE lower(name)=? AND full_path IS NOT NULL "
                "AND full_path != '' LIMIT 8",
                (nm,),
            ).fetchall()
            for r in row or []:
                fp = str(r["full_path"] or "").strip()
                if fp:
                    cur = out.get(nm, "")
                    low = fp.lower()
                    risky = any(x in low for x in (
                        "\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\temp\\",
                    ))
                    if not cur or (risky and not any(x in cur.lower() for x in (
                        "\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\temp\\",
                    ))):
                        out[nm] = fp
    except sqlite3.OperationalError:
        pass
    return out


def _resolve_task_paths_from_conn(conn, items: List[Any]) -> List[Any]:
    """列表页路径补全：只用 files 表 basename + 已知系统路径，不加载 processes 大 blob。"""
    if not items or not any(isinstance(x, dict) for x in items):
        return items
    try:
        from .ingest import resolve_scheduled_task_paths, _first_bare_exe
    except Exception:
        return items
    names = []
    for t in items:
        if not isinstance(t, dict):
            continue
        path = str(t.get("path") or t.get("resolved_path") or "")
        cmd = str(t.get("command") or "")
        if "\\" not in path and "/" not in path:
            b = _first_bare_exe(cmd) or _first_bare_exe(path)
            if b:
                names.append(b)
    extra = _lookup_files_by_basenames(conn, names) if names else {}
    pack = {
        "processes": [],
        "prefetch_files": [],
        "startup_items": [],
        "scheduled_tasks": items,
    }
    resolve_scheduled_task_paths(pack, extra)
    resolved = pack.get("scheduled_tasks") or items
    try:
        return _apply_file_meta_to_items(conn, resolved)
    except Exception:
        return resolved


def _resolve_startup_paths_from_conn(conn, items: List[Any]) -> List[Any]:
    """启动项列表路径补全：files basename + 系统已知路径，不读 processes/services blob。"""
    if not items or not any(isinstance(x, dict) for x in items):
        return items
    try:
        from .ingest import resolve_startup_item_paths, _first_bare_exe
    except Exception:
        return items
    names = []
    for it in items:
        if not isinstance(it, dict):
            continue
        path = str(it.get("path") or it.get("resolved_path") or "")
        cmd = str(it.get("command") or "")
        if "\\" not in path and "/" not in path:
            b = _first_bare_exe(cmd) or _first_bare_exe(path)
            if b:
                names.append(b)
    extra = _lookup_files_by_basenames(conn, names) if names else {}
    pack = {
        "startup_items": items,
        "processes": [],
        "prefetch_files": [],
        "services": [],
        "scheduled_tasks": [],
    }
    resolve_startup_item_paths(pack, extra)
    resolved = pack.get("startup_items") or items
    try:
        return _apply_file_meta_to_items(conn, resolved)
    except Exception:
        return resolved
