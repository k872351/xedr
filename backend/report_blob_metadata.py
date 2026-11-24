"""Read-only metadata and summary helpers for stored reports."""
from __future__ import annotations

from typing import Any, Dict

from .report_json import _jload


def _count_blob_fast(conn, name: str, meta: Dict[str, str]) -> int:
    """优先读 count_* meta；file_scans 用 files 表 COUNT；否则不解析大 JSON（返回 0）。"""
    ck = f"count_{name}"
    if ck in meta:
        try:
            return int(meta[ck] or 0)
        except ValueError:
            pass
    if name == "file_scans":
        try:
            row = conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()
            return int(row["c"] or 0) if row else 0
        except Exception:
            return 0
    if name == "event_logs":
        try:
            row = conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()
            n = int(row["c"] or 0) if row else 0
            if n:
                return n
        except Exception:
            pass
    # 旧库无 count_*：摘要路径绝不解析大 blob（避免热路径拖垮）
    return 0


def _nested_artifact_count(blob: Any) -> int:
    """dict 类采集块：累加列表长度 + 非空文本字段。"""
    if not isinstance(blob, dict):
        if isinstance(blob, list):
            return len(blob)
        if isinstance(blob, str) and blob.strip():
            return 1
        return 0
    n = 0
    for v in blob.values():
        if isinstance(v, list):
            n += len(v)
        elif isinstance(v, str) and v.strip():
            n += 1
        elif isinstance(v, dict) and v:
            n += 1
    return n


def _load_one_blob(conn, name: str) -> Any:
    row = conn.execute("SELECT data FROM blobs WHERE name=?", (name,)).fetchone()
    if not row:
        return None
    return _jload(row["data"])


def _conn_os_family(conn) -> str:
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='os_family'").fetchone()
        return str((row["value"] if row else "") or "").lower()
    except Exception:
        return ""
def _derive_file_scan_roots(files: List[Any]) -> Dict[str, int]:
    """从路径推断分目录计数（兼容旧报告无 file_scan_roots）。"""
    st: Dict[str, int] = {}
    for f in files or []:
        if not isinstance(f, dict):
            continue
        tag = str(f.get("root") or "").strip()
        if not tag:
            p = str(f.get("full_path") or f.get("path") or "").lower().replace("/", "\\")
            if "\\users\\" in p or p.startswith("c:\\users"):
                tag = "Users"
            elif "programdata" in p:
                tag = "ProgramData"
            elif "program files (x86)" in p:
                tag = "ProgramFilesX86"
            elif "program files" in p:
                tag = "ProgramFiles"
            elif "\\windows\\" in p or p.startswith("c:\\windows"):
                tag = "Windows"
            else:
                tag = "Other"
        st[tag] = st.get(tag, 0) + 1
    return st
