"""Report event serialization helpers shared by storage readers and writers."""
from typing import Any, Dict

from .report_json import _jdump, _jload


def _elog_row_tuple(e: Dict[str, Any]) -> tuple:
    fields = e.get("fields") if isinstance(e.get("fields"), dict) else {}
    msg = str(e.get("message") or "")
    if len(msg) > 2000:
        msg = msg[:2000] + "..."
    try:
        eid = int(e.get("event_id") or 0)
        if not 0 <= eid <= 2**63 - 1:
            eid = 0
    except (TypeError, ValueError, OverflowError):
        eid = 0
    return (
        str(e.get("channel") or ""),
        eid,
        str(e.get("provider") or ""),
        str(e.get("time") or ""),
        str(e.get("level") or ""),
        str(e.get("computer") or ""),
        msg,
        _jdump(fields) if fields else "",
    )


def _event_log_row_to_dict(r) -> Dict[str, Any]:
    fields = _jload(r["fields"]) if r["fields"] else {}
    if not isinstance(fields, dict):
        fields = {}
    try:
        from .text_fix import fix_mojibake, fix_tree
        fields = fix_tree(fields) if fields else {}
        msg = fix_mojibake(r["message"] or "")
    except Exception:
        msg = r["message"] or ""
    return {
        "channel": r["channel"] or "",
        "event_id": int(r["event_id"] or 0),
        "provider": r["provider"] or "",
        "time": r["time"] or "",
        "level": r["level"] or "",
        "computer": r["computer"] or "",
        "message": msg,
        "fields": fields,
    }
