# -*- coding: utf-8 -*-
"""IOC / 情报库相关 HTTP 路由（从 edr_api 拆出）。"""
from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query, Request

from .edr_session_routes import _require_admin, _require_user

router = APIRouter(tags=["agent-ioc"])


@router.get("/api/agent/ioc")
def api_agent_ioc_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_ioc()


@router.post("/api/agent/ioc")
def api_agent_ioc_add(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    p = payload or {}
    out = agent_edr.add_ioc(
        str(p.get("ioc_type") or p.get("kind") or "auto"),
        str(p.get("value") or ""),
        severity=str(p.get("severity") or "high"),
        note=str(p.get("note") or ""),
        name=str(p.get("name") or p.get("label") or ""),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "添加失败")
    return out


@router.post("/api/agent/ioc/import")
def api_agent_ioc_import(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    p = payload or {}
    return agent_edr.import_iocs(
        str(p.get("text") or ""),
        ioc_type=str(p.get("ioc_type") or "auto"),
        severity=str(p.get("severity") or "high"),
    )


@router.post("/api/agent/ioc/detect")
def api_agent_ioc_detect(request: Request, payload: dict = Body(...)):
    """试识别：输入值 → 建议类型（不落库）。"""
    _require_user(request)
    from .ioc_import_format import detect_ioc_type, normalize_ioc_value
    p = payload or {}
    value = str(p.get("value") or "").strip()
    kind = detect_ioc_type(value) if value else ""
    return {
        "ok": True,
        "value": normalize_ioc_value(kind, value) if kind else value,
        "ioc_type": kind,
        "label": {
            "hash": "文件哈希", "ip": "IP", "domain": "域名",
            "path": "路径/URL", "process": "进程名", "cmdline": "命令行",
        }.get(kind, kind),
    }


@router.get("/api/agent/ioc/lib-status")
def api_agent_ioc_lib_status(request: Request):
    """本地 agent_ioc + 情报库 ioc_data.db 状态。"""
    _require_user(request)
    from . import agent_edr
    return agent_edr.ioc_lib_status()


@router.get("/api/agent/ioc/lookup")
def api_agent_ioc_lookup(
    request: Request,
    value: str = Query("", min_length=1),
    ioc_type: str = Query(""),
):
    """情报库试查（精确匹配）。"""
    _require_user(request)
    from . import agent_edr
    return agent_edr.lookup_ioc_lib(value, ioc_type)


@router.get("/api/agent/ioc/lib-preview")
def api_agent_ioc_lib_preview(
    request: Request,
    limit: int = Query(40, ge=1, le=100),
    offset: int = Query(0, ge=0, le=99),
    ioc_type: str = Query(""),
):
    """情报库样例浏览：只允许前 100 条（分页 + 类型过滤）。"""
    _require_user(request)
    from . import ioc_db
    return ioc_db.sample_preview(limit, ioc_type=ioc_type, offset=offset)


@router.delete("/api/agent/ioc/{iid}")
def api_agent_ioc_del(iid: str, request: Request):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.delete_ioc(iid)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    return out
