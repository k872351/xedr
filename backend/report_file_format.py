"""Legacy report file record serialization."""
from typing import Any, Dict

from .file_normalization import _norm_ext, _norm_hash_field, _norm_file_path, _file_parent


FILE_CONTENT_MAX_CHARS = 200_000


def _file_size(value: Any):
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        return None
    try:
        size = int(value)
    except (ValueError, TypeError, OverflowError):
        return None
    if size < 0 or size > 2**63 - 1:
        return None
    if not isinstance(value, str) and size != value:
        return None
    return size


def _file_content_field(f: Dict[str, Any]) -> str:
    raw = f.get("content") or f.get("text") or f.get("script_text") or f.get("snippet") or ""
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8", errors="replace")
        except Exception:
            return ""
    s = str(raw or "")
    if not s.strip():
        return ""
    return s[:FILE_CONTENT_MAX_CHARS]


def _file_row_tuple(f: Dict[str, Any]) -> tuple:
    return (
        f.get("full_path") or "",
        f.get("name") or "",
        f.get("path") or "",
        _norm_file_path(_file_parent(f)),
        _norm_ext(f.get("ext")),
        _file_size(f.get("size")),
        f.get("company") or "",
        f.get("product") or "",
        f.get("description") or "",
        f.get("file_version") or "",
        1 if f.get("signed") else 0,
        f.get("signer") or "",
        f.get("sig_status") or "",
        f.get("sig_type") or f.get("SigType") or "",
        f.get("magic_hex") or "",
        _norm_hash_field(f.get("md5") or f.get("MD5")),
        _norm_hash_field(f.get("sha1") or f.get("SHA1")),
        _norm_hash_field(f.get("sha256") or f.get("SHA256")),
        1 if f.get("hidden") else 0,
        1 if f.get("system") else 0,
        str(f.get("mtime") or "")[:40],
        str(f.get("mode") or "")[:32],
        str(f.get("owner") or "")[:64],
        str(f.get("group") or f.get("file_group") or f.get("root") or "")[:64],
        _file_content_field(f),
    )
