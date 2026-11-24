"""出站 URL 安全约束：阻止 SSRF 访问内网、链路本地与元数据地址。"""
from __future__ import annotations

import ipaddress
import os
import socket
from typing import Optional, Set
from urllib.parse import urlparse

_BLOCKED_HOSTS = frozenset({
    "localhost", "metadata", "metadata.google.internal",
    "instance-data", "kubernetes.default", "kubernetes.default.svc",
})


def _extra_allow_hosts() -> Set[str]:
    raw = (os.environ.get("EDR_SSRF_ALLOW_HOSTS") or "").strip()
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _is_public_ip(ip: ipaddress._BaseAddress) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return False
    if ip.is_reserved or ip.is_unspecified:
        return False
    # 云厂商链路本地元数据
    if ip.version == 4 and str(ip) in ("169.254.169.254", "169.254.170.2"):
        return False
    if ip.version == 6 and ip in ipaddress.ip_network("fd00::/8"):
        return False
    return True


def validate_outbound_url(url: str, *, allow_http: bool = False) -> str:
    """校验并返回规范化 URL；非法则抛 ValueError。"""
    raw = str(url or "").strip()
    if not raw or len(raw) > 2048:
        raise ValueError("URL 无效或过长")
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in (("http", "https") if allow_http else ("https",)):
        if scheme == "http" and not allow_http:
            # 默认允许 http 仅当显式开启（兼容钉钉/飞书部分环境）
            if (os.environ.get("EDR_SSRF_ALLOW_HTTP") or "").strip() not in ("1", "true", "yes"):
                raise ValueError("仅允许 HTTPS 出站地址")
        elif scheme not in ("http", "https"):
            raise ValueError("仅允许 http/https")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("缺少主机名")
    if host in _BLOCKED_HOSTS and host not in _extra_allow_hosts():
        raise ValueError("禁止访问该主机")
    if host.endswith(".local") or host.endswith(".internal"):
        raise ValueError("禁止访问内网域名")
    # 字面量 IP
    try:
        ip = ipaddress.ip_address(host)
        if not _is_public_ip(ip) and host not in _extra_allow_hosts():
            raise ValueError("禁止访问内网或保留地址")
        return raw
    except ValueError as e:
        if "禁止" in str(e):
            raise
    # 解析 DNS，防止 DNS rebinding 到内网（尽力而为）
    if (os.environ.get("EDR_SSRF_SKIP_DNS") or "").strip() in ("1", "true", "yes"):
        return raw
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"主机名无法解析: {e}") from e
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if not _is_public_ip(ip) and host not in _extra_allow_hosts():
            raise ValueError("主机名解析到内网地址，已拒绝")
    return raw
