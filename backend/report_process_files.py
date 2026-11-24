"""File metadata joins used to enrich process and startup list rows."""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List


def _lookup_file_meta_by_paths(conn, paths: List[str]) -> Dict[str, Dict[str, Any]]:
    """按完整路径从 files 表取签名/公司等，供列表页补字段（不读 processes blob）。"""
    out: Dict[str, Dict[str, Any]] = {}
    want = []
    seen = set()
    for p in paths or []:
        fp = str(p or "").strip().replace("/", "\\")
        if not fp:
            continue
        low = fp.lower()
        if low in seen:
            continue
        seen.add(low)
        want.append(fp)
    if not want:
        return out
    try:
        for i in range(0, len(want), 200):
            chunk = want[i : i + 200]
            ph = ",".join("?" * len(chunk))
            lows = [x.lower() for x in chunk]
            rows = conn.execute(
                "SELECT full_path,signed,signer,sig_status,sig_type,company,product,description,"
                "file_version,md5,sha1,sha256 FROM files "
                f"WHERE lower(replace(full_path,'/','\\')) IN ({ph})",
                lows,
            ).fetchall()
            for r in rows or []:
                fp = str(r["full_path"] or "").strip()
                if not fp:
                    continue
                keys = r.keys()
                out[fp.replace("/", "\\").lower()] = {
                    "signed": bool(r["signed"]),
                    "signer": r["signer"] or "",
                    "sig_status": r["sig_status"] or "",
                    "sig_type": (r["sig_type"] if "sig_type" in keys else "") or "",
                    "company": (r["company"] if "company" in keys else "") or "",
                    "product": (r["product"] if "product" in keys else "") or "",
                    "description": (r["description"] if "description" in keys else "") or "",
                    "file_version": (r["file_version"] if "file_version" in keys else "") or "",
                    "md5": (r["md5"] if "md5" in keys else "") or "",
                    "sha1": (r["sha1"] if "sha1" in keys else "") or "",
                    "sha256": (r["sha256"] if "sha256" in keys else "") or "",
                }
    except sqlite3.OperationalError:
        pass
    return out


def _apply_file_meta_to_items(conn, items: List[Any]) -> List[Any]:
    paths = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        p = str(it.get("resolved_path") or it.get("path") or "").strip()
        if p and ("\\" in p or "/" in p):
            paths.append(p)
    meta = _lookup_file_meta_by_paths(conn, paths)
    if not meta:
        return items
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            out.append(it)
            continue
        row = dict(it)
        p = str(row.get("resolved_path") or row.get("path") or "").replace("/", "\\").lower()
        m = meta.get(p) if p else None
        if m:
            st = str(row.get("sig_status") or "").strip().lower()
            need = (
                not st or st in ("error", "unknown", "missing", "unchecked", "n/a", "-")
                or st.startswith("error_")
                or not (row.get("md5") or row.get("sha256") or row.get("signer"))
            )
            if need:
                for k, v in m.items():
                    if v in (None, ""):
                        continue
                    if k in ("signed", "signer", "sig_status", "sig_type") or not row.get(k):
                        row[k] = v
        out.append(row)
    return out
