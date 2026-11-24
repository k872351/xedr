"""Agent release and downloadable installation package routes."""
from __future__ import annotations

import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response

from .agent_public_url import public_base_url
from .edr_session_routes import _audit, _require_admin

router = APIRouter()


@router.get("/api/agent/install-package")
def api_agent_install_package(request: Request, require_latest: bool = Query(True), arch: str = Query("amd64")):
    user = _require_admin(request)
    from . import agent_release
    from .agent_package_builder import build_install_package

    try:
        target = str(arch or "amd64").strip().lower()
        exe = agent_release.windows_agent_path(target)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    rel = agent_release.release_status(exe)
    if not rel.get("integrity_verified") or rel.get("status") not in ("latest", "stale"):
        raise HTTPException(409, detail="Agent release integrity cannot be verified; rebuild required")
    expected_latest = rel.get("status") == "latest"
    if rel.get("is_latest") is not expected_latest:
        raise HTTPException(409, detail="Agent release metadata is inconsistent; independent verification required")
    if require_latest and not rel.get("is_latest"):
        reasons = "；".join(rel.get("reasons") or [rel.get("status", "")])
        raise HTTPException(409, detail="Current Windows Agent release is not latest: " + reasons)
    try:
        data, filename = build_install_package(server_url=public_base_url(request), goarch=target)
    except FileNotFoundError as e:
        raise HTTPException(404, detail=str(e))
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("agent_install_package", user, detail=f"{filename} arch={target} status={rel.get('status')} sha={str(rel.get('exe_sha256', ''))[:12]}")
    headers = {
        "Cache-Control": "no-store",
        "X-Agent-Status": str(rel.get("status", "")),
        "X-Agent-Is-Latest": "1" if rel.get("is_latest") else "0",
        "X-Agent-Version": str(rel.get("version") or rel.get("source_version") or ""),
        "X-Agent-Build-Id": str(rel.get("build_id") or ""),
        "X-Agent-Build-Time": str(rel.get("build_time") or ""),
        "X-Agent-Sha256": str(rel.get("exe_sha256") or ""),
        "Access-Control-Expose-Headers": "X-Agent-Status,X-Agent-Is-Latest,X-Agent-Version,X-Agent-Build-Id,X-Agent-Build-Time,X-Agent-Sha256",
    }
    if isinstance(data, Path):
        return FileResponse(path=str(data), media_type="application/zip", filename=filename, headers=headers)
    return Response(content=data, media_type="application/zip", headers={**headers, "Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/api/agent/linux-package")
def api_agent_linux_package(request: Request, arch: str = Query("amd64")):
    user = _require_admin(request)
    from .agent_linux_package import build_linux_package

    try:
        archive, filename, manifest = build_linux_package(
            server_url=public_base_url(request), arch=str(arch or "amd64").lower()
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(503, detail=str(e))
    except OSError as e:
        raise HTTPException(500, detail=f"Linux Agent package creation failed: {e}")
    _audit(
        "agent_linux_package", user,
        detail=f"{filename} arch={manifest.get('goarch')} sha={str(manifest.get('binary_sha256') or '')[:12]}",
    )
    return FileResponse(
        path=archive, media_type="application/gzip", filename=filename,
        headers={
            "Cache-Control": "no-store",
            "X-Agent-Version": str(manifest.get("version") or ""),
            "X-Agent-Build-Id": str(manifest.get("build_id") or ""),
            "X-Agent-Sha256": str(manifest.get("binary_sha256") or ""),
            "Access-Control-Expose-Headers": "X-Agent-Version,X-Agent-Build-Id,X-Agent-Sha256",
        },
    )


@router.get("/api/agent/release")
def api_agent_release(request: Request, arch: str = Query("amd64")):
    _require_admin(request)
    from . import agent_release
    try:
        exe = agent_release.windows_agent_path(arch)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    from .agent_public_url import _meta_get, deployment_address_status
    result = agent_release.release_status(exe)
    result.update(deployment_address_status(_meta_get("edr_server_url")))
    return result


@router.post("/api/agent/release/build")
def api_agent_release_build(request: Request, arch: str = Query("amd64")):
    user = _require_admin(request)
    from . import agent_release

    if agent_release._build_state.get("running"):
        raise HTTPException(409, detail="Agent build is already running")
    if not agent_release._find_go():
        raise HTTPException(400, detail="Go toolchain was not found on the backend")
    try:
        target = str(arch or "amd64").strip().lower()
        agent_release.windows_agent_path(target)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    threading.Thread(
        target=lambda: agent_release.run_build(goarch=target),
        daemon=True,
        name=f"agent-build-{target}",
    ).start()
    _audit("agent_release_build", user, detail=f"arch={target}")
    return {"ok": True, "started": True, "goarch": target}
