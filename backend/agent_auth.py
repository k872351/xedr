"""Shared authentication helpers for Agent-facing API routers."""
from __future__ import annotations

from typing import Any, Dict

from fastapi import HTTPException, Request

from .edr_session_routes import _require_user


def _require_agent_or_user(request: Request) -> Dict[str, Any]:
    """终端 Agent 用接入密钥；管理台用 EDR 会话。"""
    from .agent_protocol import verify_enroll_key
    auth = str(request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        auth = auth[7:].strip()
    if verify_enroll_key(auth):
        return {"id": "agent-enroll", "username": "agent", "role": "agent", "agent": True}
    return _require_user(request)


def _bearer(request: Request) -> str:
    auth = str(request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        auth = auth[7:].strip()
    return auth


def _agent_auth(request: Request, agent_id: str = "", *, register: bool = False) -> Dict[str, Any]:
    """Agent 端点鉴权，返回 {cred, agent_id, ...}。

    1) 每 Agent 凭据（fa_ 前缀 + X-Agent-Id）：身份固定，payload 里的 agent_id 必须一致；
    2) 共享接入密钥：仅用于首次注册；若该 Agent 已有独立凭据或被吊销，共享密钥不再能冒充它；
       管理员关闭 allow_shared_key 后，共享密钥只能 register；
    3) 管理台会话：沿用原行为。
    """
    from . import agent_protocol as ap
    tok = _bearer(request)
    claimed = str(agent_id or "").strip()
    if tok.startswith(ap.SECRET_PREFIX):
        hdr = str(request.headers.get("x-agent-id") or "").strip()
        aid = hdr or claimed
        st = ap.verify_agent_secret(aid, tok)
        if st == "revoked":
            raise HTTPException(403, detail="该 Agent 已被吊销")
        if st != "ok":
            raise HTTPException(401, detail="Agent 凭据无效")
        if claimed and claimed != aid:
            raise HTTPException(403, detail="agent_id 与凭据不匹配")
        return {"id": f"agent:{aid}", "username": "agent", "role": "agent", "agent": True,
                "cred": "secret", "agent_id": aid}
    if ap.verify_enroll_key(tok):
        if not register:
            if not ap.shared_key_allowed():
                raise HTTPException(401, detail="共享接入密钥已停用，请使用 Agent 独立凭据")
            if claimed:
                st = ap.agent_auth_state(claimed)
                if st["revoked"]:
                    raise HTTPException(403, detail="该 Agent 已被吊销")
                if st["has_secret"]:
                    raise HTTPException(403, detail="该 Agent 已启用独立凭据，共享密钥不再接受")
        return {"id": "agent-enroll", "username": "agent", "role": "agent", "agent": True,
                "cred": "enroll", "agent_id": claimed}
    user = _require_user(request)
    return {**user, "cred": "user", "agent_id": claimed}
