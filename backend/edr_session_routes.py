"""EDR console account and session routes."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from . import edr_auth
from .http_security import client_ip, is_trusted_proxy

router = APIRouter()


def _private_json(content: dict) -> JSONResponse:
    """Session and account information must not be stored by intermediaries."""
    return JSONResponse(content, headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"})


def _token(request: Request) -> str:
    return edr_auth.token_from_request(
        request.headers.get("cookie") or "", request.headers.get("authorization") or ""
    )


def _require_user(request: Request, *, allow_must_change: bool = False) -> Dict[str, Any]:
    user = edr_auth.me(_token(request))
    if not user:
        raise HTTPException(401, detail="未登录或会话已过期")
    if user.get("must_change") and not allow_must_change:
        raise HTTPException(403, detail="首次登录请先修改密码")
    return user


def _require_admin(request: Request) -> Dict[str, Any]:
    user = _require_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, detail="需要管理员权限")
    return user


def _actor(user: Dict[str, Any]) -> str:
    return str(user.get("username") or "admin")


def _validate_account_fields(data: dict, *, booleans=(), strings=()) -> None:
    # Reject ambiguous JSON types before applying account-state changes.
    for field in booleans:
        if field in data and type(data[field]) is not bool:
            raise HTTPException(422, detail=f"{field} must be a boolean")
    for field in strings:
        if field in data and not isinstance(data[field], str):
            raise HTTPException(422, detail=f"{field} must be a string")


def _audit(action: str, user: Optional[Dict[str, Any]] = None, *, detail: str = "", agent_id: str = "") -> None:
    try:
        from . import agent_edr
        agent_edr.ensure()
        agent_edr._audit(action, agent_id=agent_id, detail=detail, actor=_actor(user or {}) if user else "")
    except Exception as e:
        print("[edr-audit]", e)


def _set_cookie(resp: Response, request: Request, token: str) -> None:
    proto = request.url.scheme
    if is_trusted_proxy(request):
        forwarded = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
        if forwarded in ("http", "https"):
            proto = forwarded
    resp.set_cookie(
        edr_auth.COOKIE_NAME, token, max_age=edr_auth.SESSION_TTL,
        httponly=True, samesite="strict", path="/", secure=(proto == "https"),
    )


# ---------- EDR 自身：登录 / 账号 ----------

@router.post("/api/edr/auth/login")
def edr_login(request: Request, data: dict = Body(...)):
    from .ratelimit import check_login_allowed, record_login_failure, record_login_success
    ip = client_ip(request)
    uname = str((data or {}).get("username") or "").strip()
    rl_key = "edr:" + uname
    try:
        check_login_allowed(ip, rl_key)
    except ValueError as e:
        raise HTTPException(429, detail=str(e))
    try:
        out = edr_auth.login(uname, str((data or {}).get("password") or ""), ip=ip)
    except ValueError as e:
        record_login_failure(ip, rl_key)
        _audit("edr_login_failed", None, detail=f"{uname} @ {ip}")
        msg = str(e)
        raise HTTPException(400, detail=msg if "禁用" in msg else "用户名或密码错误")
    record_login_success(ip, rl_key)
    _audit("edr_login", out["user"], detail=f"@ {ip}")
    resp = _private_json({"user": out["user"]})
    _set_cookie(resp, request, out["token"])
    return resp


@router.post("/api/edr/auth/logout")
def edr_logout(request: Request):
    tok = _token(request)
    user = edr_auth.me(tok)
    edr_auth.logout(tok)
    if user:
        _audit("edr_logout", user)
    resp = _private_json({"ok": True})
    resp.delete_cookie(edr_auth.COOKIE_NAME, path="/")
    return resp


@router.get("/api/edr/auth/session")
def edr_session(request: Request):
    user = _require_user(request, allow_must_change=True)
    return _private_json({"user": user})


@router.post("/api/edr/auth/change-password")
def edr_change_password(request: Request, data: dict = Body(...)):
    user = _require_user(request, allow_must_change=True)
    try:
        edr_auth.change_own_password(
            user["id"],
            str((data or {}).get("current_password") or ""),
            str((data or {}).get("new_password") or ""),
            keep_token=_token(request),
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_change_password", user)
    return _private_json({"ok": True, "user": edr_auth.me(_token(request))})


@router.get("/api/edr/users")
def edr_users_list(request: Request):
    _require_admin(request)
    return _private_json({"items": edr_auth.list_users(), "roles": edr_auth.ROLE_LABELS})


@router.post("/api/edr/users")
def edr_users_create(request: Request, data: dict = Body(...)):
    user = _require_admin(request)
    d = data or {}
    _validate_account_fields(d, booleans=("must_change",), strings=("username", "password", "role", "display_name"))
    try:
        out = edr_auth.create_user(
            str(d.get("username") or ""), str(d.get("password") or ""),
            role=str(d.get("role") or "analyst"), display_name=str(d.get("display_name") or ""),
            must_change=bool(d.get("must_change", True)),
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_user_create", user, detail=f"{out['username']} ({out['role']})")
    return _private_json(out)


@router.patch("/api/edr/users/{uid}")
def edr_users_update(uid: str, request: Request, data: dict = Body(...)):
    user = _require_admin(request)
    d = data or {}
    _validate_account_fields(d, booleans=("enabled",), strings=("role", "display_name"))
    if uid == user["id"] and (d.get("enabled") is False or (d.get("role") and d.get("role") != "admin")):
        raise HTTPException(400, detail="不能禁用或降级自己")
    try:
        out = edr_auth.update_user(
            uid,
            role=d.get("role"),
            enabled=d.get("enabled") if "enabled" in d else None,
            display_name=d.get("display_name"),
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_user_update", user, detail=f"{out['username']} role={out['role']} enabled={out['enabled']}")
    return _private_json(out)


@router.post("/api/edr/users/{uid}/reset-password")
def edr_users_reset(uid: str, request: Request, data: dict = Body(...)):
    user = _require_admin(request)
    _validate_account_fields(data or {}, strings=("password",))
    try:
        edr_auth.reset_password(uid, str((data or {}).get("password") or ""), must_change=True)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_user_reset_password", user, detail=uid)
    return _private_json({"ok": True})


@router.delete("/api/edr/users/{uid}")
def edr_users_delete(uid: str, request: Request):
    user = _require_admin(request)
    if uid == user["id"]:
        raise HTTPException(400, detail="不能删除自己")
    try:
        edr_auth.delete_user(uid)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("edr_user_delete", user, detail=uid)
    return _private_json({"ok": True})

