"""Pure startup readiness classification, independent of service initialization."""

from __future__ import annotations

from typing import Any, Dict, Optional


def readiness(
    critical_ok: bool,
    degraded: bool,
    *,
    components: Optional[Dict[str, Any]] = None,
) -> tuple[dict, int]:
    if not critical_ok:
        body: dict = {"status": "not_ready"}
        if components:
            body["components"] = components
        return body, 503
    body = {"status": "ready", "degraded": bool(degraded)}
    if components:
        body["components"] = components
    return body, 200


def storage_degraded(status: dict) -> bool:
    """An intentional SQLite configuration is not a failure."""
    return bool(status.get("enabled", True) and not status.get("ok"))
