# -*- coding: utf-8 -*-
"""Agent 本地 IOC CRUD 与情报库试查。从 agent_edr 拆出。"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict

from . import agent_protocol, config
from .agent_detection_analytics import match_iocs
from .agent_edr import _connect, _lock, _now, ensure
from .ioc_import_format import (
    LOCAL_IOC_TYPES,
    detect_ioc_type,
    normalize_ioc_value,
    normalize_lib_type,
    parse_ioc_import_line,
)

_IOC_TYPE_CN = {"ip": "IP", "domain": "域名", "file_hash": "文件哈希", "url": "URL", "hash": "哈希"}


def list_ioc() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM agent_ioc ORDER BY created_at DESC").fetchall()
            return {"ok": True, "items": [dict(r) for r in rows]}
        finally:
            conn.close()


def add_ioc(ioc_type: str, value: str, *, severity: str = "high", note: str = "", name: str = "") -> Dict[str, Any]:
    ensure()
    raw_type = str(ioc_type or "").strip().lower()
    mapped = normalize_lib_type(raw_type)
    if not mapped:
        # auto / 空 / 未知 → 按内容识别
        mapped = detect_ioc_type(value) if raw_type in ("", "auto", "detect") or raw_type not in LOCAL_IOC_TYPES else raw_type
    ioc_type = mapped if mapped in LOCAL_IOC_TYPES else detect_ioc_type(value)
    value = normalize_ioc_value(ioc_type, value)
    if ioc_type not in LOCAL_IOC_TYPES or not value:
        return {"ok": False, "error": "ioc_type/value 无效"}
    # name 作为可读名称写入备注前缀（匹配仍用 value）
    name_s = str(name or "").strip()[:80]
    note_s = str(note or "").strip()[:200]
    if name_s and note_s:
        note_s = f"{name_s} · {note_s}"[:200]
    elif name_s:
        note_s = name_s
    iid = uuid.uuid4().hex
    now = _now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_ioc(id, ioc_type, value, severity, note, enabled, hits, created_at, updated_at)
                   VALUES(?,?,?,?,?,1,0,?,?)""",
                (iid, ioc_type, value, severity[:16], note_s, now, now),
            )
            conn.commit()
        finally:
            conn.close()
    agent_protocol.bump_live("ioc")
    try:
        from . import agent_sync
        agent_sync.bump_sync("ioc")
    except Exception:
        pass
    return {"ok": True, "id": iid, "ioc_type": ioc_type, "value": value, "detected": ioc_type}


def import_iocs(text: str, *, ioc_type: str = "auto", severity: str = "high") -> Dict[str, Any]:
    """批量导入。纯值行可自动识别类型；亦支持 type,value[,source[,malware]]。"""
    default = str(ioc_type or "auto").strip().lower() or "auto"
    lines = [ln.strip() for ln in str(text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
    n = 0
    skipped = 0
    detected: list[str] = []
    for ln in lines[:2000]:
        parsed = parse_ioc_import_line(ln, default_type=default)
        if not parsed:
            skipped += 1
            continue
        t, v, note = parsed
        r = add_ioc(t, v, severity=severity, note=note)
        if r.get("ok"):
            n += 1
            if r.get("ioc_type"):
                detected.append(str(r["ioc_type"]))
        else:
            skipped += 1
    return {
        "ok": True,
        "imported": n,
        "skipped": skipped,
        "format": "auto | type,value[,source[,malware]]",
        "types": sorted(set(detected)),
    }
def delete_ioc(iid: str) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM agent_ioc WHERE id=?", (str(iid),))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "不存在"}
        finally:
            conn.close()
    try:
        from . import agent_sync
        agent_sync.bump_sync("ioc")
    except Exception:
        pass
    return {"ok": True}


def match_iocs_against_text(agent_id: str, hostname: str, blob: str, *, module: str = "ioc") -> int:
    """本地 agent_ioc 子串 + ioc_data.db / MySQL 情报库精确匹配。"""
    return match_iocs(agent_id, hostname, blob=blob, events=None, module=module)


def ioc_lib_status() -> Dict[str, Any]:
    """管理台展示：本地 agent_ioc + 情报库 ioc_data.db 状态。"""
    ensure()
    local_n = 0
    with _lock:
        conn = _connect()
        try:
            local_n = int(conn.execute("SELECT COUNT(*) AS c FROM agent_ioc WHERE enabled=1").fetchone()["c"])
        finally:
            conn.close()
    lib: Dict[str, Any] = {"ok": False, "path": "", "count": 0, "hint": ""}
    try:
        from . import ioc_db
        layout = ioc_db.source_layout() if hasattr(ioc_db, "source_layout") else {}
        info = ioc_db.file_info() if hasattr(ioc_db, "file_info") else {}
        st = ioc_db.stats(force=False) if hasattr(ioc_db, "stats") else {}
        by_type = (st or {}).get("by_type") or (st or {}).get("types") or {}
        if not isinstance(by_type, dict):
            by_type = {}
        lib = {
            "ok": True,
            "path": str((layout or {}).get("expected") or (info or {}).get("path") or ""),
            "count": int((st or {}).get("total") or (info or {}).get("count") or 0),
            "exists": bool((layout or {}).get("exists") or (info or {}).get("exists")),
            "mysql": (st or {}).get("mysql") if isinstance((st or {}).get("mysql"), dict) else {},
            "by_type": {str(k): int(v or 0) for k, v in by_type.items()},
            "hint": (layout or {}).get("hint") or "",
        }
    except Exception as e:
        lib = {
            "ok": False,
            "path": str(Path(getattr(config, "IOC_DIR", "") or "") / "ioc_data.db"),
            "count": 0,
            "hint": str(e),
        }
    return {"ok": True, "local_enabled": local_n, "lib": lib}


def lookup_ioc_lib(value: str, ioc_type: str = "") -> Dict[str, Any]:
    """管理台试查情报库：精确 lookup。"""
    val = str(value or "").strip()
    if not val:
        return {"ok": False, "error": "empty", "hits": []}
    kind = str(ioc_type or "").strip().lower() or None
    if kind in ("hash", "sha256", "md5", "sha1"):
        kind = "file_hash"
    try:
        from . import ioc_db
        hits = ioc_db.lookup(val, kind)
        if not hits and kind == "file_hash":
            hits = ioc_db.lookup(val, None)
    except Exception as e:
        return {"ok": False, "error": str(e), "hits": [], "value": val, "ioc_type": kind or ""}
    out_hits = []
    for h in (hits or [])[:20]:
        if not isinstance(h, dict):
            continue
        out_hits.append({
            "type": h.get("type") or h.get("ioc_type") or kind or "",
            "value": h.get("value") or val,
            "malware": h.get("malware") or h.get("family") or "",
            "source": h.get("source") or "",
        })
    return {"ok": True, "value": val, "ioc_type": kind or "", "hits": out_hits, "count": len(out_hits)}
