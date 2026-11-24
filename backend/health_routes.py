"""Process health endpoints, separate from application business routes."""
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .startup_health import readiness


router = APIRouter()
_logger = logging.getLogger(__name__)


def _public_components(components: dict) -> dict:
    """Expose operational status, not raw exceptions or connection details."""
    result = {}
    for name, value in components.items():
        if not isinstance(value, dict):
            continue
        item = {}
        for key in ("ok", "enabled", "shared", "eql_loop", "event_queue"):
            if isinstance(value.get(key), bool):
                item[key] = value[key]
        if isinstance(value.get("steps"), int):
            item["steps"] = value["steps"]
        # Startup MySQL status historically nests internal details. Only expose
        # an explicit backend enum and the enabled flag from that structure.
        detail = value.get("detail") if name == "mysql" else None
        if isinstance(detail, dict):
            if isinstance(detail.get("enabled"), bool):
                item.setdefault("enabled", detail["enabled"])
            backend = value.get("backend", detail.get("backend"))
        else:
            backend = value.get("backend")
        if backend in ("mysql", "sqlite", "mysql-unavailable"):
            item["backend"] = backend
        if item:
            result[name] = item
    return result


def no_cache() -> dict:
    return {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    }


@router.get("/health/live")
def health_live():
    return JSONResponse({"status": "alive"}, headers=no_cache())


@router.get("/health/ready")
def health_ready(request: Request):
    ready = bool(getattr(request.app.state, "startup_ready", False))
    startup_components = getattr(request.app.state, "startup_components", None)
    components = dict(startup_components) if isinstance(startup_components, dict) else {}
    if ready:
        try:
            from .mysql_db import mysql_ready, strict_storage_required
            if strict_storage_required():
                ready = bool(mysql_ready())
                components["mysql"] = {"ok": ready, "backend": "mysql" if ready else "mysql-unavailable"}
        except Exception as exc:
            # A failed readiness check must not be mistaken for readiness or
            # expose connection/configuration exceptions on the public route.
            ready = False
            components["mysql"] = {"ok": False, "backend": "mysql-unavailable"}
            _logger.warning("Storage readiness check failed (%s)", type(exc).__name__)
    body, status = readiness(
        ready,
        getattr(request.app.state, "startup_degraded", False),
        components=_public_components(components),
    )
    return JSONResponse(body, status_code=status, headers=no_cache())
