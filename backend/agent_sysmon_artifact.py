# -*- coding: utf-8 -*-
"""平台托管的 Sysmon 二进制（默认取仓库根目录 Sysmon/）。"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config


def sysmon_dir() -> Path:
    return Path(config.ROOT) / "Sysmon"


CONFIG_NAME = "sysmonconfig-export.xml"
_ALLOWED = {"sysmon64.exe", "sysmon.exe", "sysmon64a.exe", "eula.txt", CONFIG_NAME.lower()}
_BUNDLE = ("Sysmon64.exe", "Sysmon64a.exe", "Sysmon.exe", "Eula.txt", CONFIG_NAME)


def resolve_sysmon_exe(name: str = "Sysmon64.exe") -> Optional[Path]:
    safe = Path(name or "Sysmon64.exe").name
    if safe.lower() not in _ALLOWED:
        return None
    d = sysmon_dir()
    if d.is_dir():
        for p in d.iterdir():
            if p.is_file() and p.name.lower() == safe.lower() and p.stat().st_size > 0:
                return p
    return None


def sysmon_status() -> Dict[str, Any]:
    d = sysmon_dir()
    items: List[Dict[str, Any]] = []
    if d.is_dir():
        for p in sorted(d.iterdir()):
            if not p.is_file():
                continue
            items.append({"name": p.name, "size": p.stat().st_size})
    exe = resolve_sysmon_exe("Sysmon64.exe")
    cfg = resolve_sysmon_exe(CONFIG_NAME)
    return {
        "ok": True,
        "dir": str(d),
        "available": bool(exe),
        "sysmon64": exe.name if exe else None,
        "config": cfg.name if cfg else None,
        "items": items,
        "hint": "Sysmon/ 下放 Sysmon64.exe 与 sysmonconfig-export.xml；安装包会带上，终端安装时自动装 Sysmon。",
    }


def read_sysmon_bytes(name: str = "Sysmon64.exe") -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    p = resolve_sysmon_exe(name)
    if not p:
        return None, None, "Sysmon 二进制不存在：请将 Sysmon64.exe 放到 Sysmon/ 目录"
    try:
        return p.read_bytes(), p.name, None
    except OSError as e:
        return None, None, str(e)


def iter_sysmon_bundle_files() -> List[Path]:
    """安装包打进 ForensicAgent/sysmon/ 的文件列表。"""
    d = sysmon_dir()
    if not d.is_dir():
        return []
    out: List[Path] = []
    for name in _BUNDLE:
        p = resolve_sysmon_exe(name)
        if p:
            out.append(p)
    return out
