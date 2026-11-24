"""Resolve the externally reachable EDR URL used in generated Agent packages."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from fastapi import HTTPException, Request


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


def normalize_server_url(url: str) -> str:
    value = str(url or "").strip().rstrip("/")
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if (
            len(value) > 400 or any(ch.isspace() for ch in value)
            or parsed.scheme not in ("http", "https")
            or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or "\\" in value
            or (port is not None and port == 0)
        ):
            raise ValueError
    except ValueError:
        raise HTTPException(400, detail="请输入有效的 HTTP(S) 平台地址，不能含账号、查询参数或片段")
    while urlsplit(value).path.lower().endswith(("/app", "/a")):
        suffix = "/app" if urlsplit(value).path.lower().endswith("/app") else "/a"
        value = value[:-len(suffix)].rstrip("/")
    if is_loopback_url(value):
        raise HTTPException(400, detail="平台地址不能指向回环或未指定地址")
    return value


def is_loopback_url(url: str) -> bool:
    value = str(url or "").strip()
    try:
        host = (urlsplit(value).hostname or "").lower().rstrip(".")
        if not host:
            return True
        if host == "localhost" or host.endswith(".localhost"):
            return True
        address = ipaddress.ip_address(host)
        return address.is_loopback or address.is_unspecified
    except ValueError:
        return False


def deployment_address_status(configured: str) -> dict:
    try:
        effective = normalize_server_url(configured)
    except HTTPException as exc:
        return {"effective_server_url": "", "server_url_source": "invalid", "server_url_error": exc.detail}
    return {"effective_server_url": effective, "server_url_source": "configured" if effective else "missing",
            "server_url_error": "" if effective else "请先保存终端可以访问的平台地址"}


def public_base_url(request: Request) -> str:
    configured = normalize_server_url(_meta_get("edr_server_url"))
    if not configured:
        raise HTTPException(
            400,
            detail="The public EDR URL must be configured before generating an Agent package.",
        )
    return configured
