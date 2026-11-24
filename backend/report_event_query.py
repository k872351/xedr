"""Filtering helpers for report event query results."""
from __future__ import annotations

from typing import Any, Dict

from .report_search_query import _token_in_blob


def _event_matches_q(event: Dict[str, Any], query: str) -> bool:
    if not query:
        return True
    blob = " ".join(
        str(event.get(key) or "")
        for key in ("channel", "provider", "message", "event_id", "level", "computer", "fields")
    ).lower()
    tokens = [token for token in query.split() if token]
    return all(_token_in_blob(token, blob) for token in tokens)
