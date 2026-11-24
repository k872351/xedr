"""Shared report file metadata normalization."""
import re
from typing import Any, Dict, List


def _norm_ext(ext: Any) -> str:
    e = str(ext or "").strip().lower()
    if not e:
        return ""
    if not e.startswith("."):
        e = "." + e
    return e


def _norm_hash_field(v: Any) -> str:
    s = str(v or "").strip().lower().replace(" ", "").replace("-", "")
    if s.startswith("0x"):
        s = s[2:]
    if len(s) in (32, 40, 64) and all(c in "0123456789abcdef" for c in s):
        return s
    return ""


def _norm_file_path(value: Any) -> str:
    s = re.sub(r"\\+", r"\\", str(value or "").replace("/", "\\").strip()).rstrip("\\")
    return s.lower()


def _file_parent(f: Dict[str, Any]) -> str:
    parent = str(f.get("path") or "").strip()
    if not parent:
        full = re.sub(r"\\+", r"\\", str(f.get("full_path") or "").replace("/", "\\")).rstrip("\\")
        parent = full.rsplit("\\", 1)[0] if "\\" in full else ""
    return re.sub(r"\\+", r"\\", parent.replace("/", "\\")).rstrip("\\")


def _directory_rows(files: List[Any]) -> List[tuple]:
    """Build a compact parent/child directory index from file paths."""
    seen: Dict[str, tuple] = {}
    for item in files or []:
        if not isinstance(item, dict):
            continue
        full_raw = str(item.get("full_path") or "")
        unix = full_raw.startswith("/")
        parent = _file_parent(item)
        if not parent:
            continue
        parts = [x for x in parent.replace("/", "\\").split("\\") if x]
        if not parts:
            continue
        current = ""
        parent_current = ""
        for i, part in enumerate(parts):
            parent_current = current
            if i == 0 and unix:
                current = "\\" + part
            elif i == 0:
                current = part
            else:
                current = current + "\\" + part
            norm = _norm_file_path(current)
            parent_norm = _norm_file_path(parent_current)
            display = current.replace("\\", "/") if unix else current
            seen.setdefault(norm, (norm, parent_norm, part, display))
    return list(seen.values())
