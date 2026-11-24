"""Agent inventory snapshots, telemetry, and investigation API routes."""
from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query, Request

from .agent_auth import _agent_auth
from .edr_session_routes import _audit, _require_admin, _require_user

router = APIRouter()


@router.post("/api/agent/snapshot")
def api_agent_snapshot(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from .agent_protocol import upsert_snapshot
    out = upsert_snapshot(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "snapshot 失败")
    return out


@router.get("/api/agent/events/{event_id}")
def api_agent_event_get(event_id: int, request: Request):
    _require_user(request)
    from .agent_protocol import get_event
    r = get_event(event_id)
    if not r.get("ok"):
        raise HTTPException(404, r.get("error") or "事件不存在")
    return r


@router.get("/api/agent/events/{event_id}/related")
def api_agent_event_related(event_id: int, request: Request, limit: int = Query(20, ge=1, le=50)):
    _require_user(request)
    from .agent_protocol import related_events_by_payload
    return related_events_by_payload(event_id, limit=limit)


@router.post("/api/agent/event")
def api_agent_event(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from .agent_protocol import report_event
    out = report_event(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "事件写入失败")
    return out


@router.post("/api/edr/events/enrich-details")
def api_edr_events_enrich_details(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from .agent_protocol import enrich_event_details, get_event
    body = payload or {}
    eid = body.get("event_id")
    if eid is not None:
        get_event(int(eid))
        return get_event(int(eid))
    limit = int(body.get("limit") or 500)
    return enrich_event_details(limit=max(1, min(limit, 2000)))


@router.get("/api/agent/events")
def api_agent_events(
    request: Request,
    status: str = Query(""),
    agent_id: str = Query(""),
    limit: int = Query(100, ge=1, le=500),
    sync: int = Query(0, ge=0, le=1),
    severity: str = Query("", max_length=32),
    module: str = Query("", max_length=64),
    start_at: str = Query("", max_length=32),
    end_at: str = Query("", max_length=32),
    before_id: int | None = Query(None, gt=0),
    anchor_id: int | None = Query(None, ge=0),
):
    _require_user(request)
    from .agent_protocol import list_events
    from . import agent_edr
    # 先返回列表，避免 sync 晋升拖慢首屏；sync 在列表之后后台式执行（同请求末尾）
    filters = dict(status=status, agent_id=agent_id, limit=limit, severity=severity, module=module,
                   start_at=start_at, end_at=end_at, before_id=before_id, anchor_id=anchor_id)
    out = list_events(**filters)
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "Invalid event filters")
    if int(sync or 0) == 1 and before_id is None and anchor_id is None:
        try:
            synced = agent_edr.sync_threats_from_timeline(limit=400)
            out["sync"] = synced
            # 晋升后若有新增，再补一刀轻量列表
            if isinstance(synced, dict) and int(synced.get("promoted") or 0) > 0:
                out = list_events(**filters)
                out["sync"] = synced
        except Exception as e:
            out["sync"] = {"ok": False, "error": str(e)}
    return out


@router.patch("/api/agent/events/{event_id}")
def api_agent_event_update(event_id: int, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from .agent_protocol import update_event
    out = update_event(event_id, status=str((payload or {}).get("status") or ""))
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "更新失败")
    return out


@router.delete("/api/agent/events")
def api_agent_events_delete_bulk(
    request: Request,
    status: str = Query(""),
    agent_id: str = Query(""),
    severity: str = Query(""),
):
    user = _require_admin(request)
    from .agent_protocol import delete_events
    out = delete_events(status=status, agent_id=agent_id, severity=severity)
    _audit("events_delete_bulk", user, agent_id=agent_id,
           detail=f"status={status or '*'} severity={severity or '*'} deleted={out.get('deleted', 0)}")
    return out


@router.delete("/api/agent/events/{event_id}")
def api_agent_event_delete(event_id: int, request: Request):
    _require_admin(request)
    from .agent_protocol import delete_event
    out = delete_event(event_id)
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "删除失败")
    return out


@router.post("/api/agent/commands/poll")
def api_agent_commands_poll(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from . import agent_edr
    return agent_edr.poll_commands(str((payload or {}).get("agent_id") or ""))


@router.post("/api/agent/commands/ack")
def api_agent_commands_ack(request: Request, payload: dict = Body(...)):
    from . import agent_edr
    p = payload or {}
    cid = str(p.get("id") or p.get("command_id") or "")
    # 命令所属 Agent 即"声称身份"：独立凭据只能回执自己的命令，已升级 Agent 的命令不能用共享密钥回执
    try:
        owner = agent_edr.command_owner(cid)
    except Exception:
        owner = ""
    who = _agent_auth(request, owner)
    out = agent_edr.ack_command(
        cid,
        ok=bool(p.get("ok", True)),
        result=p.get("result") if isinstance(p.get("result"), dict) else {},
        caller_agent_id=who.get("agent_id", "") if who.get("cred") == "secret" else "",
    )
    if not out.get("ok"):
        raise HTTPException(403 if out.get("forbidden") else 400, detail=out.get("error") or "回执失败")
    return out


@router.post("/api/agent/timeline")
def api_agent_timeline_ingest(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from . import agent_edr
    out = agent_edr.ingest_timeline(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "写入失败")
    return out


@router.get("/api/agent/timeline")
def api_agent_timeline_list(
    request: Request,
    agent_id: str = Query(""),
    etype: str = Query(""),
    q: str = Query(""),
    kind: str = Query(""),
    source: str = Query(""),
    event_id: str = Query(""),
    limit: int = Query(100, ge=1, le=500),
):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_timeline(
        agent_id, etype=etype, q=q, kind=kind, source=source, event_id=event_id, limit=limit,
    )


@router.get("/api/agent/dns")
def api_agent_dns_hunt(
    request: Request,
    q: str = Query(""),
    agent_id: str = Query(""),
    nx_only: int = Query(0),
    match_ioc: int = Query(1),
    range: str = Query("24h"),
    online_only: int = Query(1),
    limit: int = Query(200, ge=1, le=1000),
):
    """DNS 域名聚合；默认近 24h + 仅在线终端；指定 agent_id 时不过滤在线。"""
    _require_user(request)
    from . import agent_telemetry
    return agent_telemetry.list_dns(
        agent_id,
        q=q.strip(),
        nx_only=bool(nx_only),
        limit=limit,
        match_ioc=bool(match_ioc),
        range_key=range,
        online_only=bool(int(online_only if online_only is not None else 1)),
    )


@router.get("/api/agent/{agent_id}/processes")
def api_agent_processes(
    agent_id: str,
    request: Request,
    q: str = Query(""),
    alive: str = Query(""),
    limit: int = Query(200, ge=1, le=1000),
):
    _require_user(request)
    from . import agent_telemetry
    flag = {"1": True, "true": True, "0": False, "false": False}.get(alive.strip().lower())
    return agent_telemetry.list_processes(agent_id, q=q.strip(), alive=flag, limit=limit)


@router.get("/api/agent/{agent_id}/process/{entity_id}")
def api_agent_process_detail(agent_id: str, entity_id: str, request: Request, events_limit: int = Query(200, ge=1, le=1000)):
    """进程实体：祖先链、子进程、按实体归属的全部事件（网络/DNS/文件/DLL…）。"""
    _require_user(request)
    from . import agent_telemetry
    out = agent_telemetry.process_detail(agent_id, entity_id.strip(), events_limit=events_limit)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "进程实体不存在")
    return out


@router.get("/api/agent/investigate")
def api_agent_investigate(
    request: Request,
    q: str = Query(""),
    agent_id: str = Query(""),
    hostname: str = Query(""),
    etype: str = Query(""),
    nature: str = Query(""),
    path: str = Query(""),
    hash_q: str = Query(""),
    source: str = Query(""),
    event_id: str = Query(""),
    topic: str = Query(""),
    range: str = Query("today"),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    hide_proc_noise: int = Query(1),
):
    """日志调查：实时时间线检索。"""
    _require_user(request)
    from . import agent_edr
    return agent_edr.investigate_logs(
        q=q, agent_id=agent_id, hostname=hostname, etype=etype, nature=nature,
        path=path, hash_q=hash_q, source=source, event_id=event_id, topic=topic,
        range_key=range, limit=limit, offset=offset,
        hide_proc_noise=bool(int(hide_proc_noise if hide_proc_noise is not None else 1)),
    )


@router.get("/api/agent/investigate/{log_id}")
def api_agent_investigate_detail(request: Request, log_id: int):
    _require_user(request)
    from . import agent_edr
    out = agent_edr.get_log_detail(log_id)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "日志不存在")
    return out


@router.get("/api/agent/hunt")
def api_agent_hunt(request: Request, q: str = Query(...), limit: int = Query(100, ge=1, le=300)):
    _require_user(request)
    from . import agent_edr
    out = agent_edr.hunt(q, limit=limit)
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "狩猎失败")
    return out


@router.get("/api/agent/{agent_id}/snapshot/{module}")
def api_agent_snapshot_get(agent_id: str, module: str, request: Request,
                           offset: int | None = Query(None, ge=0),
                           limit: int | None = Query(None, ge=1, le=500),
                           snapshot_version: str | None = Query(None, max_length=64)):
    _require_user(request)
    from .agent_protocol import get_snapshot
    out = get_snapshot(agent_id, module, offset=offset, limit=limit, snapshot_version=snapshot_version)
    if out.get("error") == "snapshot_version_changed":
        raise HTTPException(409, detail="snapshot_version_changed")
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "无快照")
    return out
