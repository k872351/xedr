# -*- coding: utf-8 -*-
"""本地 IOC 导入行解析（与情报库 ioc_records 字段对齐，无 DB 依赖）。"""
from __future__ import annotations

import re
from typing import Optional, Tuple

LOCAL_IOC_TYPES = ("hash", "domain", "ip", "path", "process", "cmdline")
LIB_TYPE_MAP = {
    "file_hash": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "hash": "hash",
    "ip": "ip",
    "domain": "domain",
    "url": "path",
    "path": "path",
    "process": "process",
    "cmdline": "cmdline",
    "name": "process",
    "proc": "process",
    "exe": "process",
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?$"
)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$"
)
_PROC_EXT = (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".scr", ".com")
# 自动识别时与域名后缀冲突的短扩展（.com）单独处理
_PROC_EXT_DETECT = (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".scr")


def normalize_lib_type(raw: str) -> str:
    t = str(raw or "").strip().lower()
    if t in ("auto", "detect", ""):
        return ""
    return LIB_TYPE_MAP.get(t, "")


def normalize_ioc_value(ioc_type: str, value: str) -> str:
    v = str(value or "").strip()
    if ioc_type == "ip" and v.count(":") == 1:
        host, _, port = v.partition(":")
        if host.count(".") == 3 and port.isdigit():
            v = host
    if ioc_type == "process":
        # 允许填完整路径时仍按进程名匹配：取 basename
        s = v.replace("/", "\\")
        if "\\" in s:
            s = s.rsplit("\\", 1)[-1]
        v = s
    return v[:800]


def detect_ioc_type(value: str) -> str:
    """根据内容自动识别本地 IOC 类型。"""
    v = str(value or "").strip().strip('"').strip("'")
    if not v:
        return "process"
    low = v.lower()
    if _HEX_RE.fullmatch(v) and len(v) in (32, 40, 64):
        return "hash"
    if _IPV4_RE.fullmatch(v):
        return "ip"
    if low.startswith(("http://", "https://", "ftp://")):
        return "path"
    if ("\\" in v or (v.startswith("/") and "/" in v[1:])) and " " not in v.strip():
        # 路径里带扩展名的可执行文件 → 进程名更实用
        base = v.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if any(base.endswith(ext) for ext in _PROC_EXT):
            return "process"
        return "path"
    if " " in v or any(x in low for x in (" -", "/c ", "powershell", "cmd.exe", "wscript", "cscript")):
        if any(x in low for x in ("\\", "/", ".exe", "powershell", "cmd ")):
            return "cmdline"
    if any(low.endswith(ext) for ext in _PROC_EXT_DETECT):
        return "process"
    if _DOMAIN_RE.fullmatch(v.rstrip(".")) and not _IPV4_RE.fullmatch(v):
        return "domain"
    if re.fullmatch(r"[A-Za-z0-9._\-]+", v):
        return "process"
    return "process"


def parse_ioc_import_line(ln: str, *, default_type: str) -> Optional[Tuple[str, str, str]]:
    """支持 type,value[,source[,malware]] / Tab / type:value / 纯值（可自动识别）。"""
    raw = str(ln or "").strip()
    if not raw or raw.startswith("#"):
        return None
    low = raw.lower().replace(" ", "")
    if low in (
        "type,value", "type,value,source", "type,value,source,malware",
        "type\tvalue", "type\tvalue\tsource", "type\tvalue\tsource\tmalware",
    ):
        return None

    parts: list[str] = []
    if "\t" in raw:
        parts = [p.strip() for p in raw.split("\t")]
    elif "," in raw and normalize_lib_type(raw.split(",", 1)[0].strip()):
        parts = [p.strip() for p in raw.split(",", 3)]
    elif ":" in raw:
        head, rest = raw.split(":", 1)
        if normalize_lib_type(head) or head.strip().lower() in LOCAL_IOC_TYPES:
            parts = [head.strip(), rest.strip()]

    if len(parts) >= 2:
        t = normalize_lib_type(parts[0]) or parts[0].strip().lower()
        if t not in LOCAL_IOC_TYPES:
            t = detect_ioc_type(parts[1])
        v = parts[1]
        note_bits = [p for p in parts[2:4] if p]
        note = " · ".join(note_bits)
        return t, v, note

    default = normalize_lib_type(default_type) or str(default_type or "").strip().lower()
    if default in ("auto", "detect", "") or default not in LOCAL_IOC_TYPES:
        return detect_ioc_type(raw), raw, ""
    return default, raw, ""
