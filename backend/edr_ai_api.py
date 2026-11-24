"""AI administration and host analysis API routes."""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Body, HTTPException, Query, Request

from .edr_session_routes import _require_user, _require_admin, _audit

router = APIRouter()


@router.get("/api/edr/ai/status")
def api_edr_ai_status(request: Request):
    user = _require_user(request)
    from . import config as cfg
    from .ai import host_analyze, skills_loader
    creds = host_analyze.resolve_creds(user)
    cfg.reload_ai_config()
    pub = cfg.ai_public_status()
    sk = skills_loader.skills_stats()
    return {
        "ok": True,
        "configured": bool((creds.get("api_key") or "").strip()) or bool(pub.get("configured")),
        "base_url": creds.get("base_url") or cfg.AI_BASE_URL,
        "model": creds.get("model") or cfg.AI_MODEL,
        "timeout": creds.get("timeout") or cfg.AI_TIMEOUT,
        "source": creds.get("source") or "none",
        "provider_mode": pub.get("provider_mode") or "online",
        "api_key_masked": pub.get("api_key_masked") or "",
        "has_api_key": bool(pub.get("has_api_key")),
        "name": pub.get("name") or "",
        "active_id": pub.get("active_id") or "",
        "profiles": pub.get("profiles") or [],
        "profile_count": pub.get("profile_count") or 0,
        "skills_root": str(skills_loader.skills_root()),
        "skills_total": int(sk.get("total_indexed") or 0),
        "skills_edr": int(sk.get("edr_relevant") or 0),
        "skills_priority": int(sk.get("priority") or 0),
    }


def _save_platform_ai(user: Dict[str, Any], body: dict, *, sync_user: bool = True) -> Dict[str, Any]:
    """保存平台模型配置（可多套）；可选同步到当前管理员个人配置。"""
    from . import config as cfg
    from . import user_ai
    base_url = str(body.get("base_url") or "").strip().rstrip("/")
    api_key = str(body.get("api_key") or "").strip()
    model = str(body.get("model") or "").strip()
    name = str(body.get("name") or "").strip()
    provider_mode = str(body.get("provider_mode") or "").strip().lower()
    if provider_mode not in ("local", "online"):
        provider_mode = "local" if any(
            x in base_url.lower() for x in ("127.0.0.1", "localhost", "192.168.", "10.", "172.")
        ) else "online"
    try:
        timeout = float(body.get("timeout") or 120)
    except (TypeError, ValueError):
        timeout = 120.0
    if not base_url:
        raise HTTPException(400, detail="请填写 Base URL")
    if not model:
        raise HTTPException(400, detail="请填写模型名")
    if not name:
        name = "本地模型" if provider_mode == "local" else model
    payload = {
        "id": str(body.get("id") or "").strip(),
        "as_new": bool(body.get("as_new")),
        "activate": body.get("activate", True) is not False,
        "name": name,
        "base_url": base_url,
        "model": model,
        "timeout": timeout,
        "provider_mode": provider_mode,
    }
    if api_key and not set(api_key) <= {"*", "•"} and "****" not in api_key:
        payload["api_key"] = api_key
    try:
        status = cfg.save_ai_config(payload)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(400, detail=str(e))
    if sync_user and payload.get("activate", True):
        try:
            profile = {
                "name": name,
                "base_url": base_url,
                "model": model,
                "timeout": timeout,
            }
            if payload.get("api_key"):
                profile["api_key"] = payload["api_key"]
            user_ai.upsert_profile(str(user.get("id") or ""), profile, activate=True)
        except Exception as e:
            status["user_sync_error"] = str(e)[:200]
    return {
        "ok": True,
        "platform": status,
        "user": user_ai.public_status(str(user.get("id") or "")),
    }


@router.put("/api/edr/ai/config")
def api_edr_ai_config_save(request: Request, payload: dict = Body(None)):
    """平台模型配置：支持多套本地/在线；as_new=true 新增。"""
    user = _require_admin(request)
    body = payload or {}
    out = _save_platform_ai(user, body, sync_user=True)
    _audit(
        "edr_ai_config_save",
        user,
        detail=f"{body.get('provider_mode') or ''} {body.get('name') or ''} {body.get('base_url') or ''} / {body.get('model') or ''}",
    )
    return out


@router.post("/api/edr/ai/profiles/{profile_id}/activate")
def api_edr_ai_profile_activate(request: Request, profile_id: str):
    user = _require_admin(request)
    from . import config as cfg
    from . import user_ai
    try:
        status = cfg.activate_ai_profile(profile_id)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    try:
        active = next((p for p in (status.get("profiles") or []) if p.get("active")), None)
        if active:
            creds = cfg.resolve_platform_profile_creds(str(active.get("id") or ""))
            profile = {
                "name": str(active.get("name") or active.get("model") or ""),
                "base_url": creds.get("base_url") or "",
                "model": creds.get("model") or "",
                "timeout": creds.get("timeout") or 60,
            }
            if creds.get("api_key"):
                profile["api_key"] = creds["api_key"]
            user_ai.upsert_profile(str(user.get("id") or ""), profile, activate=True)
    except Exception as e:
        status["user_sync_error"] = str(e)[:200]
    _audit("edr_ai_profile_activate", user, detail=profile_id)
    return {"ok": True, "platform": status}


@router.delete("/api/edr/ai/profiles/{profile_id}")
def api_edr_ai_profile_delete(request: Request, profile_id: str):
    user = _require_admin(request)
    from . import config as cfg
    try:
        status = cfg.delete_ai_profile(profile_id)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_ai_profile_delete", user, detail=profile_id)
    return {"ok": True, "platform": status}


@router.post("/api/edr/ai/test")
def api_edr_ai_test(request: Request, payload: dict = Body(None)):
    """测试模型连通性：可传 profile_id，或直接传表单字段（未保存也可测）。"""
    _require_admin(request)
    from . import config as cfg
    from .ai import analyzer
    body = payload or {}
    creds: Dict[str, Any] = {}
    pid = str(body.get("profile_id") or "").strip()
    if pid and not str(body.get("base_url") or "").strip():
        creds = cfg.resolve_platform_profile_creds(pid)
    else:
        base_url = str(body.get("base_url") or "").strip().rstrip("/")
        model = str(body.get("model") or "").strip()
        api_key = str(body.get("api_key") or "").strip()
        if not base_url or not model:
            # 回退当前启用
            creds = cfg.resolve_platform_profile_creds(pid)
        else:
            if (not api_key or set(api_key) <= {"*", "•"} or "****" in api_key):
                # 表单留空 Key：用已保存同 id / 当前启用的密钥
                saved = cfg.resolve_platform_profile_creds(str(body.get("id") or pid or ""))
                api_key = str(saved.get("api_key") or "")
            try:
                timeout = float(body.get("timeout") or 30)
            except (TypeError, ValueError):
                timeout = 30.0
            creds = {
                "base_url": base_url,
                "model": model,
                "api_key": api_key,
                "timeout": timeout,
            }
    try:
        result = analyzer.test_ai_connection(creds)
    except Exception as e:
        raise HTTPException(400, detail=str(e)[:400])
    return {"ok": True, **result}


@router.post("/api/edr/ai/setup-local")
def api_edr_ai_setup_local(request: Request, payload: dict = Body(None)):
    """兼容旧入口：写入本地模型（无参时用当前平台配置，不再内置默认密钥）。"""
    user = _require_admin(request)
    body = dict(payload or {})
    from . import config as cfg
    cfg.reload_ai_config()
    if not str(body.get("base_url") or "").strip():
        body["base_url"] = cfg.AI_BASE_URL or "http://127.0.0.1:8085/v1"
    if not str(body.get("model") or "").strip():
        body["model"] = cfg.AI_MODEL or "local-model"
    if not str(body.get("api_key") or "").strip() and not cfg.AI_API_KEY:
        # 本地常见网关可用任意占位 Key
        body["api_key"] = "local-no-key"
    body["provider_mode"] = "local"
    body["name"] = str(body.get("name") or "本地模型")
    body["as_new"] = bool(body.get("as_new", False))
    out = _save_platform_ai(user, body, sync_user=True)
    _audit("edr_ai_setup_local", user, detail=f"{body.get('base_url')} / {body.get('model')}")
    return out


@router.get("/api/edr/ai/skills")
def api_edr_ai_skills(
    request: Request,
    q: str = Query(""),
    limit: int = Query(200, ge=1, le=500),
    edr_only: int = Query(1, ge=0, le=1),
):
    _require_user(request)
    from .ai import skills_loader
    return skills_loader.list_skills(q=q, limit=limit, edr_only=bool(edr_only))


@router.get("/api/edr/ai/skills/{skill_id}")
def api_edr_ai_skill_detail(skill_id: str, request: Request):
    _require_user(request)
    from .ai import skills_loader
    out = skills_loader.load_skill_body(skill_id)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "skill 不存在")
    return out


@router.get("/api/edr/ai/hosts")
def api_edr_ai_hosts(request: Request, online_within_sec: int = Query(90, ge=12, le=3600)):
    """AI 分析页：在线终端列表（附威胁数，SQL 聚合，避免拉全量事件）。"""
    _require_user(request)
    from . import agent_protocol
    agents = agent_protocol.list_agents(online_within_sec=online_within_sec)
    by_agent: Dict[str, int] = {}
    open_by_agent: Dict[str, int] = {}
    try:
        agent_protocol.ensure_db()
        with agent_protocol._lock:
            conn = agent_protocol._connect()
            try:
                # 轻量计数，不解析 detail
                for row in conn.execute(
                    "SELECT agent_id, COUNT(*) AS c FROM agent_events "
                    "WHERE agent_id IS NOT NULL AND agent_id != '' "
                    "GROUP BY agent_id"
                ).fetchall():
                    aid = str(row["agent_id"] or "")
                    if aid:
                        by_agent[aid] = int(row["c"] or 0)
                for row in conn.execute(
                    "SELECT agent_id, COUNT(*) AS c FROM agent_events "
                    "WHERE agent_id IS NOT NULL AND agent_id != '' "
                    "AND lower(COALESCE(status,'')) IN ('','open','new','alerted','active') "
                    "GROUP BY agent_id"
                ).fetchall():
                    aid = str(row["agent_id"] or "")
                    if aid:
                        open_by_agent[aid] = int(row["c"] or 0)
            finally:
                conn.close()
    except Exception:
        pass
    items = []
    for a in (agents.get("items") or []):
        if not isinstance(a, dict):
            continue
        aid = str(a.get("agent_id") or "")
        items.append({
            **{k: a.get(k) for k in (
                "agent_id", "hostname", "ip", "last_ip", "online", "status",
                "os", "platform", "version", "last_seen", "group",
            )},
            "threat_count": by_agent.get(aid, 0),
            "open_threat_count": open_by_agent.get(aid, 0),
        })
    items.sort(key=lambda x: (0 if x.get("online") else 1, -(x.get("open_threat_count") or 0), str(x.get("hostname") or "")))
    return {"ok": True, "items": items, "online_within_sec": online_within_sec}


@router.post("/api/edr/ai/analyze-host")
def api_edr_ai_analyze_host(request: Request, payload: dict = Body(...)):
    """点击在线终端后一键分析（快照 + 威胁 + 日志）。可传 focus_event_id 聚焦某条告警。"""
    user = _require_user(request)
    body = payload or {}
    agent_id = str(body.get("agent_id") or "").strip()
    if not agent_id:
        raise HTTPException(400, detail="缺少 agent_id")
    skill_ids = body.get("skill_ids") if isinstance(body.get("skill_ids"), list) else None
    use_llm = body.get("use_llm") is not False
    focus_raw = body.get("focus_event_id") if body.get("focus_event_id") is not None else body.get("event_id")
    focus_event_id = None
    if focus_raw not in (None, ""):
        try:
            focus_event_id = int(focus_raw)
        except (TypeError, ValueError):
            focus_event_id = str(focus_raw)
    from .ai import host_analyze
    out = host_analyze.analyze_agent(
        agent_id,
        user=user,
        skill_ids=skill_ids,
        use_llm=bool(use_llm),
        focus_event_id=focus_event_id,
    )
    if not out.get("ok") and out.get("error"):
        raise HTTPException(400, detail=out.get("error"))
    _audit("edr_ai_analyze_host", user, detail=f"{agent_id} focus={focus_event_id or '-'}")
    return out
