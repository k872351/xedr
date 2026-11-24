"""Formatting helpers for existing report findings."""
from __future__ import annotations

import json
from typing import Any, Dict


def _finding_search_blob(item: Dict[str, Any], hostname: str = "", rid: str = "") -> str:
    ev = item.get("evidence")
    ev_s = " ".join(str(x) for x in ev) if isinstance(ev, list) else str(ev or "")
    extra = item.get("extra")
    extra_s = json.dumps(extra, ensure_ascii=False) if isinstance(extra, dict) else str(extra or "")
    fields = ("title", "name", "category", "type", "rule_id", "matcher", "reason", "severity")
    return " ".join([*(str(item.get(key) or "") for key in fields), ev_s, extra_s,
                     hostname or "", rid or ""]).lower()
