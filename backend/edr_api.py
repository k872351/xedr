"""EDR 后台 API（独立进程 edr_server.py 挂载）。

- /api/edr/*   ：EDR 自己的登录、账号、配置
- /api/agent/* ：终端上报（接入密钥）+ 管理台接口（EDR 会话）
与分析平台账号完全隔离：只认 edr_sid 会话，不认分析平台的 forensic_sid。
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from . import edr_auth
from .http_security import client_ip
from .edr_session_routes import router as session_router, _token, _require_user, _require_admin, _actor, _audit, _set_cookie
from .edr_ai_api import router as ai_router
from .agent_release_api import router as release_router
from .agent_auth import _agent_auth, _bearer, _require_agent_or_user
from .agent_rules_api import router as rules_router
from .agent_telemetry_api import router as telemetry_router
from .edr_agent_ioc_routes import router as ioc_router

router = APIRouter()
router.include_router(session_router)
router.include_router(ai_router)
router.include_router(release_router)
router.include_router(rules_router)
router.include_router(telemetry_router)
router.include_router(ioc_router)

SERVER_URL_META_KEY = "edr_server_url"


# ---------- 鉴权 ----------


























































def _meta_get(key: str) -> str:
    from . import agent_protocol
    agent_protocol.ensure_db()
    with agent_protocol._lock:
        conn = agent_protocol._connect()
        try:
            row = conn.execute("SELECT value FROM agent_meta WHERE key=?", (key,)).fetchone()
            return str(row["value"] or "") if row else ""
        finally:
            conn.close()


def _meta_set(key: str, value: str) -> None:
    from . import agent_protocol
    agent_protocol.ensure_db()
    with agent_protocol._lock:
        conn = agent_protocol._connect()
        try:
            conn.execute(
                """INSERT INTO agent_meta(key, value) VALUES(?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()


def _is_loopback_url(url: str) -> bool:
    from .agent_public_url import is_loopback_url
    return is_loopback_url(url)


def _normalize_server_url(url: str) -> str:
    return str(url or "").strip().rstrip("/")[:400]


def _public_base_url(request: Request) -> str:
    from .agent_public_url import public_base_url
    return public_base_url(request)

@router.get("/api/edr/settings")
def edr_settings_get(request: Request):
    _require_user(request)
    from .agent_public_url import deployment_address_status
    configured = _meta_get(SERVER_URL_META_KEY)
    return {"agent_server_url": configured, **deployment_address_status(configured)}


@router.get("/api/edr/overview")
def api_edr_overview(request: Request, online_within_sec: int = Query(45)):
    _require_user(request)
    from .edr_overview import get_overview
    return get_overview(online_within_sec=max(12, min(int(online_within_sec or 45), 3600)))


@router.put("/api/edr/settings")
def edr_settings_set(request: Request, data: dict = Body(...)):
    user = _require_admin(request)
    from .agent_public_url import normalize_server_url, deployment_address_status
    url = normalize_server_url((data or {}).get("agent_server_url") or "")
    _meta_set(SERVER_URL_META_KEY, url)
    _audit("edr_settings", user, detail=f"agent_server_url={url}")
    return {"ok": True, "agent_server_url": url, **deployment_address_status(url)}


# ---------- 终端接入 / 管理 ----------

@router.get("/api/agent/protocol")
def api_agent_protocol(request: Request):
    _require_user(request)
    from .agent_protocol import protocol_info
    return protocol_info()


@router.get("/api/agent/list")
def api_agent_list(request: Request, online_within_sec: int = Query(45, ge=12, le=3600),
                   offset: Optional[int] = Query(None, ge=0), limit: Optional[int] = Query(None, ge=1, le=500),
                   online: Optional[bool] = Query(None), include_health: bool = Query(True)):
    _require_user(request)
    from .agent_protocol import list_agents
    return list_agents(online_within_sec=online_within_sec, offset=offset, limit=limit, online=online, include_health=include_health)


@router.get("/api/agent/stream")
async def api_agent_stream(request: Request, last_rev: int = Query(0, ge=0)):
    """SSE：Agent 心跳/快照/事件变更时推送，供管理台静默刷新。"""
    _require_user(request)
    from .agent_protocol import async_iter_live_sse
    return StreamingResponse(
        async_iter_live_sse(request, last_rev),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.post("/api/agent/register")
def api_agent_register(request: Request, payload: dict = Body(...)):
    p = payload or {}
    who = _agent_auth(request, str(p.get("agent_id") or ""), register=True)
    if who.get("cred") == "secret":
        p = dict(p, agent_id=who["agent_id"])
    from .agent_protocol import register_agent
    out = register_agent(p, cred=who.get("cred", "user"))
    if not out.get("ok"):
        raise HTTPException(403, detail=out.get("error") or "注册被拒绝")
    # 用独立凭据注册时，agent_id 必须与凭据一致（防止凭据 A 改写 B 的记录）
    if who.get("cred") == "secret" and out.get("agent_id") != who.get("agent_id"):
        raise HTTPException(403, detail="agent_id 与凭据不匹配")
    return out


@router.post("/api/agent/heartbeat")
def api_agent_heartbeat(request: Request, payload: dict = Body(...)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from .agent_protocol import heartbeat
    out = heartbeat(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "heartbeat 失败")
    return out












@router.post("/api/agent/v2/events/batch")
def api_agent_v2_batch(request: Request, payload: dict = Body(...)):
    """v2 幂等批量上报（见 agent_ingest_v2）。身份以凭据为准。"""
    p = payload or {}
    who = _agent_auth(request, str(p.get("agent_id") or ""))
    aid = who.get("agent_id") or str(p.get("agent_id") or "")
    if not aid:
        raise HTTPException(400, detail="缺少 agent_id")
    from . import agent_ingest_v2
    out = agent_ingest_v2.ingest_batch(aid, p.get("events") or [], stream=str(p.get("stream") or "main"))
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "批量上报失败")
    return out


@router.post("/api/agent/credential/rotate")
def api_agent_credential_rotate(request: Request, payload: dict = Body(default={})):
    """Agent 自助轮换凭据（须用现有独立凭据调用）。"""
    who = _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    if who.get("cred") != "secret":
        raise HTTPException(403, detail="仅持有独立凭据的 Agent 可轮换")
    from .agent_protocol import rotate_agent_secret
    out = rotate_agent_secret(who["agent_id"])
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "轮换失败")
    return out


@router.post("/api/agent/{agent_id}/revoke")
def api_agent_revoke(agent_id: str, request: Request, payload: dict = Body(default={})):
    """管理员吊销/恢复某 Agent：吊销后其凭据与共享密钥都无法再接入。"""
    user = _require_admin(request)
    from .agent_protocol import set_agent_revoked
    revoked = bool((payload or {}).get("revoked", True))
    out = set_agent_revoked(agent_id, revoked)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "失败")
    _audit("agent_revoke" if revoked else "agent_restore", user, agent_id=agent_id)
    return out


@router.get("/api/agent/credentials")
def api_agent_credentials(request: Request):
    _require_admin(request)
    from .agent_protocol import credential_summary
    return {"ok": True, **credential_summary()}


@router.post("/api/agent/credentials/policy")
def api_agent_credentials_policy(request: Request, payload: dict = Body(...)):
    """是否仍接受共享接入密钥访问已注册 Agent 的业务端点（register 始终允许）。"""
    user = _require_admin(request)
    from .agent_protocol import credential_summary, set_shared_key_allowed
    allowed = bool((payload or {}).get("allow_shared_key", True))
    set_shared_key_allowed(allowed)
    _audit("agent_shared_key_policy", user, detail=f"allow_shared_key={allowed}")
    return {"ok": True, **credential_summary()}


@router.post("/api/agent/enroll-key/rotate")
def api_agent_enroll_rotate(request: Request):
    """轮换接入密钥（已装 Agent 需重新下载安装包）。"""
    user = _require_admin(request)
    from .agent_protocol import get_or_create_enroll_key
    key = get_or_create_enroll_key(rotate=True)
    _audit("agent_enroll_rotate", user)
    return {"ok": True, "rotated": True, "hint": key[:6] + "…" + key[-4:]}

































































































































































































































































































































































































































































































































# ---------- 处置 / 时间线 / 策略 / 狩猎 ----------





























































































































































@router.get("/api/agent/policy")
def api_agent_policy_get(request: Request, scope: str = Query("global")):
    _require_user(request)
    from . import agent_edr
    return agent_edr.get_policy(scope)


@router.put("/api/agent/policy")
def api_agent_policy_set(request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import agent_edr
    p = payload or {}
    out = agent_edr.set_policy(
        str(p.get("scope") or "global"),
        p.get("policy") if isinstance(p.get("policy"), dict) else {},
        actor=_actor(user),
        note=str(p.get("note") or "")[:200],
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "保存失败")
    return out


@router.get("/api/agent/driver-keys")
def api_driver_keys_status(request: Request):
    _require_admin(request)
    from . import xedr_keys
    out = xedr_keys.status()
    out["encryption_enabled"] = xedr_keys.encryption_enabled()
    return out


@router.post("/api/agent/driver-keys/rotate")
def api_driver_keys_rotate(request: Request):
    user = _require_admin(request)
    from . import xedr_keys
    out = xedr_keys.rotate(_actor(user))
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "轮换失败")
    return out


@router.post("/api/agent/driver-keys/export")
def api_driver_keys_export(request: Request):
    # 托管导出：xedr-decrypt -keys 的输入；POST 避免被预取/缓存，且记审计
    user = _require_admin(request)
    from . import xedr_keys
    if not xedr_keys.status().get("keys"):
        xedr_keys.ensure_active_key(_actor(user))
    return JSONResponse(xedr_keys.export_keys(_actor(user)), headers={"Cache-Control": "no-store"})


@router.get("/api/agent/policy/history")
def api_agent_policy_history(request: Request, scope: str = Query("global"), limit: int = Query(50, ge=1, le=200)):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_policy_history(scope, limit=limit)


@router.post("/api/agent/policy/rollback")
def api_agent_policy_rollback(request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import agent_edr
    p = payload or {}
    try:
        rev = int(p.get("rev") or 0)
    except (TypeError, ValueError):
        rev = 0
    out = agent_edr.rollback_policy(str(p.get("scope") or "global"), rev, actor=_actor(user))
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "回滚失败")
    _audit("policy_rollback", user, detail=f"to rev {rev} -> new rev {out.get('rev')}")
    return out


@router.get("/api/agent/policy/rollout")
def api_agent_policy_rollout(request: Request, scope: str = Query("global")):
    _require_user(request)
    from . import agent_edr
    return agent_edr.policy_rollout(scope)


@router.get("/api/agent/whitelist")
def api_agent_whitelist_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_whitelist()


@router.post("/api/agent/whitelist")
def api_agent_whitelist_add(request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import agent_edr
    p = payload or {}
    try:
        src_eid = int(p.get("source_event_id") or 0)
    except (TypeError, ValueError):
        src_eid = 0
    # 未显式传 apply_existing 时默认 True：路径加白后立刻压制已有未处置告警
    apply_existing = True if "apply_existing" not in p else bool(p.get("apply_existing"))
    out = agent_edr.add_whitelist(
        str(p.get("kind") or ""), str(p.get("value") or ""), note=str(p.get("note") or ""),
        agent_id=str(p.get("agent_id") or ""),
        rule=str(p.get("rule") or ""),
        created_by=str(user.get("username") or ""),
        source_event_id=src_eid,
        apply_existing=apply_existing,
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "添加失败")
    return out


@router.patch("/api/agent/whitelist/{wid}")
def api_agent_whitelist_patch(wid: str, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    p = payload or {}
    kwargs = {}
    for key in ("kind", "value", "note", "rule", "agent_id"):
        if key in p:
            kwargs[key] = p.get(key)
    if "enabled" in p:
        kwargs["enabled"] = bool(p.get("enabled"))
    if p.get("apply_existing"):
        kwargs["apply_existing"] = True
    if not kwargs:
        raise HTTPException(400, detail="无更新字段")
    # 仅启停时走原路径语义；有其它字段则统一 update
    if set(kwargs.keys()) == {"enabled"}:
        out = agent_edr.set_whitelist_enabled(wid, bool(kwargs["enabled"]))
    else:
        out = agent_edr.update_whitelist(wid, **kwargs)
    if not out.get("ok"):
        code = 404 if out.get("error") == "不存在" else 400
        raise HTTPException(code, detail=out.get("error") or "更新失败")
    return out


@router.get("/api/agent/events/{event_id}/allow-candidates")
def api_agent_event_allow_candidates(event_id: int, request: Request):
    _require_user(request)
    from . import alert_allow
    from .agent_protocol import get_event
    r = get_event(event_id)
    if not r.get("ok"):
        raise HTTPException(404, r.get("error") or "事件不存在")
    ev = r["item"]
    items = alert_allow.candidates(ev)
    return {
        "ok": True,
        "items": items,
        "default_picks": alert_allow.default_allow_pick_indices(items, ev),
        "rule_prefix": alert_allow.rule_prefix(ev.get("title") or ""),
        "agent_id": ev.get("agent_id") or "",
        "hostname": ev.get("hostname") or "",
    }


@router.delete("/api/agent/whitelist/{wid}")
def api_agent_whitelist_del(wid: str, request: Request):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.delete_whitelist(wid)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    return out


@router.get("/api/agent/groups")
def api_agent_groups_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_groups()


@router.put("/api/agent/groups")
def api_agent_groups_upsert(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    p = payload or {}
    return agent_edr.upsert_group(
        str(p.get("id") or ""), str(p.get("name") or ""),
        list(p.get("agent_ids") or []), note=str(p.get("note") or ""),
    )


@router.post("/api/agent/groups/assign")
def api_agent_groups_assign(request: Request, payload: dict = Body(...)):
    """终端列表：把主机移入某一分组（或清空为未分组）。在线/离线均可。"""
    _require_admin(request)
    from . import agent_edr
    p = payload or {}
    out = agent_edr.assign_agent_to_group(str(p.get("agent_id") or ""), str(p.get("group_id") or ""))
    if not out.get("ok"):
        from fastapi import HTTPException
        code = 404 if out.get("error") in ("group_not_found",) else 400
        raise HTTPException(status_code=code, detail=out.get("error") or "assign failed")
    return out


@router.delete("/api/agent/groups/{gid}")
def api_agent_groups_delete(request: Request, gid: str):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.delete_group(gid)
    if not out.get("ok"):
        from fastapi import HTTPException
        raise HTTPException(status_code=404 if out.get("error") == "not_found" else 400, detail=out.get("error") or "delete failed")
    return out


@router.get("/api/agent/audit")
def api_agent_audit_list(request: Request, limit: int = Query(100, ge=1, le=500)):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_audit(limit=limit)


# IOC 路由 → edr_agent_ioc_routes

@router.get("/api/edr/logrules/diagnose")
def api_edr_logrules_diagnose(
    request: Request,
    agent_id: str = Query(""),
    limit: int = Query(300, ge=50, le=500),
):
    """日志规则命中诊断：EventID / 级别 / 加白。"""
    _require_user(request)
    from . import agent_edr
    return agent_edr.diagnose_log_rules(agent_id, limit=limit)


@router.get("/api/agent/tags")
def api_agent_tags_get(request: Request, agent_id: str = Query("")):
    _require_user(request)
    from . import agent_edr
    return agent_edr.get_agent_tags(agent_id)


@router.get("/api/agent/seq-rules")
def api_agent_seq_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_seq_rules()


@router.put("/api/agent/seq-rules")
def api_agent_seq_upsert(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.upsert_seq_rule(payload or {})
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "保存失败")
    return out


@router.delete("/api/agent/seq-rules/{rule_id}")
def api_agent_seq_delete(request: Request, rule_id: str):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.delete_seq_rule(rule_id)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    return out


@router.get("/api/agent/attck-board")
def api_agent_attck_board(request: Request, agent_id: str = Query(""), days: int = Query(0)):
    _require_user(request)
    from . import agent_edr
    return agent_edr.attck_board(agent_id=agent_id, days=days)


@router.get("/api/agent/notify")
def api_agent_notify_get(request: Request):
    _require_admin(request)
    from . import agent_notify
    return agent_notify.get_notify_config()


@router.put("/api/agent/notify")
def api_agent_notify_set(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_notify
    return agent_notify.set_notify_config(payload or {})


@router.post("/api/agent/notify/test")
def api_agent_notify_test(request: Request):
    _require_admin(request)
    from . import agent_notify
    return agent_notify.test_notify()


@router.get("/api/agent/store/stats")
def api_agent_store_stats(request: Request):
    _require_user(request)
    from . import agent_store
    return agent_store.store_stats()


@router.post("/api/agent/store/purge")
def api_agent_store_purge(request: Request):
    _require_admin(request)
    from . import agent_store
    rc = agent_store.retention_config()
    return agent_store.purge(timeline_days=rc["timeline_days"], events_days=rc["events_days"])


@router.get("/api/agent/store/search")
def api_agent_store_search(request: Request, q: str = Query(""), agent_id: str = Query(""), limit: int = Query(200)):
    _require_user(request)
    from . import agent_store
    return {"ok": True, "items": agent_store.search_mysql_timeline(q, agent_id=agent_id, limit=limit)}


@router.get("/api/agent/attack-story")
def api_agent_attack_story(request: Request, agent_id: str = Query(""), event_id: int = Query(0), limit: int = Query(80)):
    _require_user(request)
    from . import agent_edr
    return agent_edr.attack_story(agent_id, event_id=event_id, limit=limit)


@router.get("/api/agent/threat-process-tree")
def api_agent_threat_process_tree(
    request: Request,
    agent_id: str = Query(""),
    event_id: int = Query(0),
    max_nodes: int = Query(56, ge=8, le=120),
):
    _require_user(request)
    from . import agent_edr
    out = agent_edr.threat_process_tree(agent_id, event_id=event_id, max_nodes=max_nodes)
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "无法构建进程树")
    return out


@router.get("/api/agent/upgrade-pubkey")
def api_agent_upgrade_pubkey(request: Request):
    """升级验签公钥（可嵌入 Agent 构建 ldflags / agent.json）。"""
    _require_user(request)
    from . import agent_edr
    out = agent_edr.get_upgrade_pubkey()
    if not out.get("ok"):
        raise HTTPException(500, detail=out.get("error") or "密钥不可用")
    return out


@router.get("/api/agent/policy-pubkey")
def api_agent_policy_pubkey(request: Request):
    """策略验签公钥（写入 agent.json 的 policy_pubkey，或构建 ldflags）。"""
    _require_user(request)
    from . import policy_sign
    out = policy_sign.get_policy_pubkey()
    if not out.get("ok"):
        raise HTTPException(500, detail=out.get("error") or "策略密钥不可用")
    return out


@router.get("/api/agent/upgrade-packages")
def api_agent_upgrade_list(request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_upgrade_packages()


@router.post("/api/agent/upgrade-packages")
async def api_agent_upgrade_upload(request: Request):
    """上传灰度升级包（multipart: file + version + note）。"""
    user = _require_admin(request)
    from . import agent_edr
    form = await request.form()
    up = form.get("file")
    if up is None:
        raise HTTPException(400, detail="缺少 file")
    content = await up.read()
    out = agent_edr.save_upgrade_package(
        content,
        version=str(form.get("version") or ""),
        filename=str(getattr(up, "filename", None) or "forensic-agent.exe"),
        note=str(form.get("note") or ""),
        actor=_actor(user),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "上传失败")
    return out


@router.delete("/api/agent/upgrade-packages/{pid}")
def api_agent_upgrade_delete(pid: str, request: Request):
    _require_admin(request)
    from . import agent_edr
    out = agent_edr.delete_upgrade_package(pid)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    return out


@router.get("/api/agent/upgrade-packages/{pid}/download")
def api_agent_upgrade_download(pid: str, request: Request):
    """Agent 拉取升级包：独立凭据 / 接入密钥 / EDR 登录用户均可。"""
    _agent_auth(request, str(request.headers.get("x-agent-id") or "") if _bearer(request).startswith("fa_") else "")
    from . import agent_edr
    meta, data = agent_edr.read_upgrade_package_bytes(pid)
    if not meta or data is None:
        raise HTTPException(404, detail="升级包不存在")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{meta.get("filename") or "forensic-agent.exe"}"',
            "X-Package-Sha256": meta.get("sha256") or "",
            "X-Package-Version": meta.get("version") or "",
            "X-Package-Sig-Ed25519": meta.get("sig_ed25519") or "",
            "Cache-Control": "no-store",
        },
    )


@router.get("/api/agent/artifacts/sysmon/status")
def api_sysmon_artifact_status(request: Request):
    _require_user(request)
    from . import agent_sysmon_artifact as asa
    return asa.sysmon_status()


@router.get("/api/agent/artifacts/sysmon/{name}")
def api_sysmon_artifact_download(name: str, request: Request):
    """Agent / 管理员下载托管的 Sysmon 二进制（默认仓库 Sysmon/）。"""
    tok = _bearer(request)
    if tok.startswith("fa_"):
        _agent_auth(request, str(request.headers.get("x-agent-id") or ""))
    else:
        _require_agent_or_user(request)
    from . import agent_sysmon_artifact as asa
    data, filename, err = asa.read_sysmon_bytes(name)
    if err or data is None:
        raise HTTPException(404, detail=err or "not found")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename or name}"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/api/agent/upgrade-packages/{pid}/push")
def api_agent_upgrade_push(pid: str, request: Request, payload: dict = Body(...)):
    """灰度推送：选择终端下发 upgrade 指令。"""
    user = _require_admin(request)
    from . import agent_edr
    out = agent_edr.push_upgrade(
        pid,
        list((payload or {}).get("agent_ids") or []),
        actor=_actor(user),
        base_url=_public_base_url(request),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "推送失败")
    return out


# 带 {agent_id} 通配的路由放最后，避免吞掉上面的固定路径

@router.delete("/api/agent/{agent_id}")
def api_agent_delete(agent_id: str, request: Request):
    user = _require_admin(request)
    from .agent_protocol import delete_agent
    out = delete_agent(agent_id)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "删除失败")
    _audit("agent_delete", user, agent_id=agent_id, detail="删除终端记录及其时间线 / 告警")
    return out












@router.post("/api/agent/{agent_id}/commands")
def api_agent_command_create(agent_id: str, request: Request, payload: dict = Body(...)):
    # 管理员直接下发；分析员可提交高危处置进审批；只读禁止
    user = _require_user(request)
    role = str(user.get("role") or "")
    if role not in ("admin", "analyst"):
        raise HTTPException(403, detail="需要管理员或分析员权限")
    from . import response_approval as ra
    p = payload or {}
    # 仅管理员可强制跳过；管理员默认也不需要审批
    skip = False
    if role == "admin":
        skip = True
    elif bool(p.get("skip_approval") or p.get("force")):
        raise HTTPException(403, detail="普通用户不能跳过审批")
    out = ra.request_action(
        agent_id,
        str(p.get("action") or ""),
        p.get("params") if isinstance(p.get("params"), dict) else {},
        actor=_actor(user),
        reason=str(p.get("reason") or ""),
        skip_approval=skip,
        actor_role=role,
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "创建指令失败")
    return out


@router.get("/api/agent/response/approvals")
def api_response_approvals_list(request: Request, status: str = "pending", agent_id: str = "", limit: int = 50):
    _require_user(request)
    from . import response_approval as ra
    return ra.list_approvals(status=status, agent_id=agent_id, limit=limit)


@router.post("/api/agent/response/approvals/{approval_id}/decide")
def api_response_approval_decide(approval_id: str, request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import response_approval as ra
    p = payload or {}
    approve = bool(p.get("approve", True))
    if "approve" not in p and str(p.get("decision") or "").lower() in ("reject", "rejected", "deny"):
        approve = False
    out = ra.decide_approval(
        approval_id, approve=approve, actor=_actor(user), note=str(p.get("note") or ""),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "审批失败")
    return out


@router.get("/api/agent/commands/{command_id}/rollback")
def api_command_rollback_suggest(command_id: str, request: Request):
    _require_user(request)
    from . import response_approval as ra
    out = ra.suggest_rollback(command_id)
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "无法回滚")
    return out


@router.post("/api/agent/commands/{command_id}/rollback")
def api_command_rollback_create(command_id: str, request: Request, payload: dict = Body(None)):
    user = _require_admin(request)
    from . import response_approval as ra
    p = payload or {}
    out = ra.create_rollback(
        command_id, actor=_actor(user), skip_approval=bool(p.get("skip_approval") or p.get("force")),
    )
    if not out.get("ok"):
        raise HTTPException(400, detail=out.get("error") or "回滚失败")
    return out


@router.get("/api/agent/commands")
def api_agent_commands_list_all(request: Request, agent_id: str = "", limit: int = 80):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_commands(agent_id, limit=limit)


@router.get("/api/agent/fleet/drift")
def api_agent_fleet_drift(request: Request, online_within_sec: int = 45):
    _require_user(request)
    from . import agent_fleet

    return agent_fleet.fleet_drift_summary(
        online_within_sec=max(12, min(int(online_within_sec or 45), 3600))
    )


@router.get("/api/agent/{agent_id}/baseline")
def api_host_baseline(agent_id: str, request: Request, days: int = 7):
    _require_user(request)
    from . import host_baseline as hb
    return hb.build_host_baseline(agent_id, days=days)


@router.post("/api/agent/{agent_id}/baseline/score")
def api_host_baseline_score(agent_id: str, request: Request, payload: dict = Body(...)):
    _require_user(request)
    from . import host_baseline as hb
    p = payload or {}
    return hb.score_against_baseline(
        agent_id,
        process_name=str(p.get("process_name") or ""),
        remote_port=str(p.get("remote_port") or p.get("port") or ""),
        dest=str(p.get("dest") or p.get("host") or ""),
    )


@router.get("/api/agent/prevalence")
def api_fleet_prevalence(request: Request, value: str = Query(...)):
    _require_user(request)
    from . import host_baseline as hb
    return hb.fleet_prevalence(value)


@router.get("/api/edr/lineage-risk")
def api_lineage_risk(request: Request, agent_id: str = "", hours: int = 24, limit: int = 50, min_score: float = 20):
    _require_user(request)
    from . import lineage_risk as lr
    return lr.list_lineage_risk(agent_id=agent_id, hours=hours, limit=limit, min_score=min_score)


@router.get("/api/edr/lineage-risk/{agent_id}/{root_entity_id}")
def api_lineage_detail(agent_id: str, root_entity_id: str, request: Request, hours: int = 24):
    _require_user(request)
    from . import lineage_risk as lr
    return lr.lineage_detail(agent_id, root_entity_id, hours=hours)


@router.get("/api/edr/network-awareness")
def api_network_awareness(
    request: Request,
    agent_id: str = "",
    hours: int = 24,
    baseline_hours: int = 168,
    only_new: bool = True,
    only_external: bool = True,
    only_http: bool = False,
    proto: str = "",
    geo: str = "",
    cloud_only: bool = False,
    risk: str = "",
    q: str = "",
    limit: int = 100,
):
    _require_user(request)
    from . import network_awareness as na
    return na.analyze_network(
        agent_id=agent_id, hours=hours, baseline_hours=baseline_hours,
        only_new=only_new, only_external=only_external, only_http=only_http,
        proto=proto, geo=geo, cloud_only=cloud_only, risk=risk, q=q, limit=limit,
    )


@router.get("/api/edr/abnormal-files")
def api_abnormal_files(
    request: Request,
    agent_id: str = "",
    hours: int = 0,
    q: str = "",
    only_rule_hit: int = 0,
    ext: str = "",
    unsigned_only: int = 0,
    limit: int = 300,
):
    """调查分析 · 异常文件：当天（或近 N 小时）新增文件列表。"""
    _require_user(request)
    from . import abnormal_files as af
    return af.list_abnormal_files(
        agent_id=agent_id,
        hours=hours,
        q=q,
        only_rule_hit=bool(int(only_rule_hit or 0)),
        ext=ext,
        unsigned_only=bool(int(unsigned_only or 0)),
        limit=limit,
    )


@router.get("/api/hunt/jobs")
def api_hunt_jobs_list(request: Request):
    _require_user(request)
    from . import hunt_jobs as hj
    return hj.list_jobs()


@router.post("/api/hunt/jobs")
def api_hunt_jobs_upsert(request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import hunt_jobs as hj
    p = payload or {}
    return hj.upsert_job(
        name=str(p.get("name") or ""),
        query=str(p.get("query") or ""),
        cron_min=int(p.get("cron_min") or 60),
        enabled=p.get("enabled", True) is not False,
        actor=_actor(user),
        job_id=str(p.get("id") or ""),
    )


@router.post("/api/hunt/jobs/{job_id}/run")
def api_hunt_jobs_run(job_id: str, request: Request):
    _require_admin(request)
    from . import hunt_jobs as hj
    return hj.run_job(job_id)


@router.post("/api/hunt/jobs/tick")
def api_hunt_jobs_tick(request: Request):
    _require_admin(request)
    from . import hunt_jobs as hj
    return hj.tick_due_jobs()


@router.post("/api/agent/{agent_id}/investigation-pack")
def api_investigation_pack(agent_id: str, request: Request, payload: dict = Body(None)):
    _require_user(request)
    from . import hunt_jobs as hj
    p = payload or {}
    return hj.build_investigation_pack(
        agent_id, hours=int(p.get("hours") or 24), event_id=int(p.get("event_id") or 0),
    )


@router.get("/api/cases")
def api_cases_list(request: Request, status: str = "open", agent_id: str = "", limit: int = 50):
    _require_user(request)
    from . import alert_cases as ac
    return ac.list_cases(status=status, agent_id=agent_id, limit=limit)


@router.post("/api/cases/merge")
def api_cases_merge(request: Request, payload: dict = Body(None)):
    _require_admin(request)
    from . import alert_cases as ac
    p = payload or {}
    return ac.merge_open_alerts(str(p.get("agent_id") or ""), window_min=int(p.get("window_min") or 60))


@router.post("/api/cases/{case_id}/status")
def api_cases_status(case_id: str, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import alert_cases as ac
    p = payload or {}
    return ac.set_case_status(case_id, str(p.get("status") or ""), note=str(p.get("note") or ""))


@router.post("/api/persist/daily/run")
def api_persist_daily_run(request: Request, payload: dict = Body(None)):
    _require_admin(request)
    from . import persist_daily as pd
    p = payload or {}
    return pd.capture_and_diff(str(p.get("agent_id") or ""))


@router.post("/api/persist/daily/{diff_id}/explain")
def api_persist_daily_explain(diff_id: str, request: Request):
    _require_user(request)
    from . import persist_daily as pd
    return pd.explain_diff(diff_id)


@router.get("/api/ai/rule-drafts")
def api_ai_rule_drafts_list(request: Request, status: str = "pending"):
    _require_user(request)
    from . import ai_rule_draft as ard
    return ard.list_drafts(status=status)


@router.post("/api/ai/rule-drafts")
def api_ai_rule_drafts_create(request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import ai_rule_draft as ard
    return ard.create_draft(str((payload or {}).get("prompt") or ""), actor=_actor(user))


@router.post("/api/ai/rule-drafts/{draft_id}/review")
def api_ai_rule_drafts_review(draft_id: str, request: Request, payload: dict = Body(...)):
    user = _require_admin(request)
    from . import ai_rule_draft as ard
    p = payload or {}
    return ard.review_draft(
        draft_id, approve=bool(p.get("approve", True)), actor=_actor(user), note=str(p.get("note") or ""),
    )


@router.get("/api/telemetry/archive/search")
def api_telemetry_archive_search(
    request: Request,
    q: str = "",
    agent_id: str = "",
    etype: str = "",
    hours: int = 24,
    limit: int = 50,
):
    _require_user(request)
    from . import elastic_detection_es as edes
    return edes.search_archived_events(q=q, agent_id=agent_id, etype=etype, hours=hours, limit=limit)


@router.post("/api/ai/investigate/{agent_id}")
def api_ai_investigate(agent_id: str, request: Request, payload: dict = Body(None)):
    user = _require_user(request)
    from .ai import investigate_loop as iloop
    p = payload or {}
    return iloop.run_investigation(
        agent_id,
        event_id=int(p.get("event_id") or 0),
        hours=int(p.get("hours") or 24),
        allow_active=bool(p.get("allow_active")),
        actor=_actor(user),
        question=str(p.get("question") or ""),
    )


@router.get("/api/agent/diagnostics")
def api_agent_diagnostics_list(request: Request, agent_id: str = "", limit: int = 50):
    _require_admin(request)
    from . import agent_diagnostics as adiag
    if agent_id and not adiag.valid_identifier(agent_id):
        raise HTTPException(400, detail="Invalid agent identifier")
    return adiag.list_diagnostics(agent_id=agent_id, limit=limit)


@router.get("/api/agent/{agent_id}/diagnostics/{command_id}/download")
def api_agent_diagnostics_download(agent_id: str, command_id: str, request: Request):
    _require_admin(request)
    from . import agent_diagnostics as adiag
    if not adiag.valid_identifier(agent_id) or not adiag.valid_identifier(command_id):
        raise HTTPException(400, detail="Invalid diagnostic identifier")

    meta = adiag.get_command_result_meta(agent_id, command_id)
    if not meta.get("ok"):
        raise HTTPException(404 if meta.get("error") == "指令不存在" else 403, detail=meta.get("error"))
    if meta.get("action") != "collect_diagnostics":
        raise HTTPException(400, detail="非诊断指令")
    if meta.get("status") != "done":
        raise HTTPException(409, detail="诊断尚未完成")
    data, filename, err = adiag.read_download_bytes(agent_id, command_id)
    if err or not data:
        raise HTTPException(404, detail=err or "文件不存在")
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/agent/{agent_id}/samples/{command_id}/download")
def api_agent_sample_download(agent_id: str, command_id: str, request: Request):
    """下载远程采集的恶意样本（pull_file）。仅管理员。"""
    _require_admin(request)
    from . import agent_samples as asamp
    if not asamp.valid_identifier(agent_id) or not asamp.valid_identifier(command_id):
        raise HTTPException(400, detail="Invalid sample identifier")
    meta = asamp.get_command_result_meta(agent_id, command_id)
    if not meta.get("ok"):
        raise HTTPException(404 if meta.get("error") == "指令不存在" else 403, detail=meta.get("error"))
    if meta.get("action") != "pull_file":
        raise HTTPException(400, detail="非样本采集指令")
    if meta.get("status") != "done":
        raise HTTPException(409, detail="样本尚未回传完成")
    data, filename, err = asamp.read_download_bytes(agent_id, command_id)
    if err or data is None:
        raise HTTPException(404, detail=err or "文件不存在")
    safe = filename or "sample.bin"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/api/agent/{agent_id}/commands")
def api_agent_commands_list(agent_id: str, request: Request):
    _require_user(request)
    from . import agent_edr
    return agent_edr.list_commands(agent_id)


@router.put("/api/agent/{agent_id}/tags")
def api_agent_tags_set(agent_id: str, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_edr
    return agent_edr.set_agent_tags(agent_id, list((payload or {}).get("tags") or []))
