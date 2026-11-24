"""Extract normalized IOC candidates from endpoint event evidence."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional


def _extract_ioc_candidates(events: List[Any], blob: str = "") -> List[Dict[str, Any]]:
    """从时间线事件 / 文本提取可查 IOC 候选（hash/ip/domain）。"""
    import re

    import ipaddress

    out: List[Dict[str, Any]] = []
    seen = set()

    def add(kind: str, value: str, src: str = "", ctx: Optional[Dict[str, Any]] = None) -> None:
        v = str(value or "").strip().lower().rstrip(".")
        if not v:
            return
        # ip 可能带端口
        if kind == "ip" and ":" in v:
            v = v.split(":", 1)[0]
        if kind == "ip":
            try:
                ip = ipaddress.ip_address(v)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                    return
            except ValueError:
                return
        key = f"{kind}|{v}"
        if key in seen or len(v) < 4:
            return
        seen.add(key)
        out.append({"ioc_type": kind, "value": v, "src": src, "ctx": ctx or {}})

    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
        ctx = {"etype": ev.get("etype"), "summary": str(ev.get("summary") or "")[:200]}
        for ck in ("pid", "process_name", "name", "path", "command_line", "remote", "domain", "query", "sha256"):
            if detail.get(ck) not in (None, ""):
                ctx[ck] = detail.get(ck)
        for hk in ("sha256", "sha1", "md5", "hash", "file_hash"):
            hv = str(detail.get(hk) or "").strip()
            if hv and re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", hv):
                add("file_hash", hv, hk, ctx)
        for ik in ("remote", "remote_ip", "ip", "dst", "dest"):
            rv = str(detail.get(ik) or "").strip()
            if not rv:
                continue
            # remote 常为 ip:port
            m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$", rv)
            if m:
                add("ip", m.group(1), ik, ctx)
            elif "." in rv and not rv.replace(".", "").isdigit():
                host = rv.split(":")[0].split("/")[0]
                if host and not host.replace(".", "").isdigit():
                    add("domain", host, ik, ctx)
        for dk in ("query", "domain"):
            dv = str(detail.get(dk) or "").strip()
            if "." in dv and not dv.replace(".", "").isdigit():
                add("domain", dv, dk, ctx)
        path = str(detail.get("path") or "")
        for m in re.finditer(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b", path):
            add("file_hash", m.group(1), "path", ctx)

    text = blob or ""
    for m in re.finditer(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b", text):
        add("file_hash", m.group(1), "blob")
    for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text):
        add("ip", m.group(1), "blob")
    return out[:80]
