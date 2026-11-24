# -*- coding: utf-8 -*-
"""Agent 发布管理：构建清单（build-manifest.json）、源码指纹、是否最新版判定、触发构建。

判定逻辑（不靠文件时间猜）：
  1. EXE 实际 SHA256 必须与清单一致，否则 mismatch（被替换/损坏）。
  2. 清单记录的 source_rev 必须等于当前 agent/ 源码指纹，否则 stale（源码比 EXE 新）。
  3. 没有清单时退化为 mtime 比较，并标记 unverified，不会被当成“最新版”。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

MANIFEST_NAME = "build-manifest.json"
MANIFEST_SCHEMA = 1

_hash_cache: Dict[str, Any] = {}
_rev_cache: Dict[str, Any] = {}
_build_lock = threading.Lock()
_build_state: Dict[str, Any] = {"running": False, "last": None}


def agent_src_dir() -> Path:
    return Path(config.ROOT) / "agent"


def _source_files(src: Optional[Path] = None) -> List[Path]:
    src = src or agent_src_dir()
    files = [p for p in src.glob("*.go") if not p.name.endswith("_test.go")]
    for extra in ("go.mod", "go.sum"):
        p = src / extra
        if p.is_file():
            files.append(p)
    return sorted(files, key=lambda p: p.name)


def compute_source_rev(src: Optional[Path] = None) -> str:
    """agent 源码指纹：文件名 + 内容（统一换行）的 SHA256 前 16 位。"""
    files = _source_files(src)
    try:
        sig = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in files)
    except OSError:
        sig = None
    if sig is not None and _rev_cache.get("sig") == sig:
        return _rev_cache["rev"]
    h = hashlib.sha256()
    for p in files:
        h.update(p.name.encode("utf-8") + b"\0")
        try:
            data = p.read_bytes().replace(b"\r\n", b"\n")
        except OSError:
            data = b""
        h.update(data + b"\0")
    rev = h.hexdigest()[:16]
    if sig is not None:
        _rev_cache.update(sig=sig, rev=rev)
    return rev


def source_version(src: Optional[Path] = None) -> str:
    p = (src or agent_src_dir()) / "config.go"
    try:
        m = re.search(r'const\s+agentVersion\s*=\s*"([^"]+)"', p.read_text(encoding="utf-8", errors="ignore"))
        return m.group(1) if m else ""
    except OSError:
        return ""


def newest_source_mtime(src: Optional[Path] = None) -> float:
    try:
        return max((p.stat().st_mtime for p in _source_files(src)), default=0.0)
    except OSError:
        return 0.0


def file_sha256(path: Path) -> str:
    """带 (路径, mtime, size) 缓存的 SHA256，避免每次下载都重算大文件。"""
    st = path.stat()
    key = str(path.resolve())
    c = _hash_cache.get(key)
    if c and c[0] == st.st_mtime_ns and c[1] == st.st_size:
        return c[2]
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    _hash_cache[key] = (st.st_mtime_ns, st.st_size, digest)
    return digest


def manifest_path_for(exe: Path) -> Path:
    return exe.with_name(MANIFEST_NAME)


def load_manifest(exe: Path) -> Optional[Dict[str, Any]]:
    p = manifest_path_for(exe)
    if not p.is_file():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def windows_agent_path(goarch: str = "amd64") -> Path:
    arch = str(goarch or "amd64").strip().lower()
    if arch not in {"amd64", "386", "arm64"}:
        raise ValueError("Windows architecture must be amd64, 386, or arm64")
    base = agent_src_dir()
    if arch == "amd64":
        return base / "forensic-agent.exe"
    return base / "releases" / "windows" / arch / "forensic-agent.exe"


def release_status(exe: Optional[Path] = None) -> Dict[str, Any]:
    """返回当前可下发 Agent 产物的发布状态。status ∈ latest|stale|mismatch|unverified|missing"""
    if exe is None:
        from .agent_protocol import agent_binary_path
        exe = agent_binary_path()
    cur_rev = compute_source_rev()
    cur_ver = source_version()
    out: Dict[str, Any] = {
        "ok": True,
        "status": "missing",
        "is_latest": False,
        "integrity_verified": False,
        "reasons": [],
        "source_rev": cur_rev,
        "source_version": cur_ver,
        "building": bool(_build_state.get("running")),
        "last_build": _build_state.get("last"),
        "go_available": bool(_find_go()),
    }
    if not exe or not exe.is_file():
        out["reasons"].append("缺少 forensic-agent.exe，请先构建")
        return out

    st = exe.stat()
    sha = file_sha256(exe)
    man = load_manifest(exe)
    out.update({
        "exe_path": str(exe),
        "exe_size": st.st_size,
        "exe_sha256": sha,
        "exe_mtime": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(st.st_mtime)),
    })
    if not man:
        out["status"] = "unverified"
        out["reasons"].append("缺少 build-manifest.json，无法证明该 EXE 对应当前源码")
        if newest_source_mtime() > st.st_mtime + 1:
            out["status"] = "stale"
            out["reasons"].append("源码修改时间晚于 EXE")
        return out

    out.update({
        "version": man.get("version", ""),
        "build_id": man.get("build_id", ""),
        "build_time": man.get("build_time", ""),
        "manifest_source_rev": man.get("source_rev", ""),
        "protocol_min": man.get("protocol_min", 1),
        "protocol_max": man.get("protocol_max", 1),
        "capabilities": man.get("capabilities", []),
        "go_version": man.get("go_version", ""),
    })
    if str(man.get("exe_sha256") or "").lower() != sha.lower():
        out["status"] = "mismatch"
        out["reasons"].append("EXE 与清单 SHA256 不一致（被替换或构建不完整）")
        return out
    out["integrity_verified"] = True
    if man.get("source_rev") != cur_rev:
        out["status"] = "stale"
        out["reasons"].append("agent/ 源码已变化，当前 EXE 不是最新构建")
        return out
    out["status"] = "latest"
    out["is_latest"] = True
    return out


def agent_outdated(agent: Dict[str, Any], rel: Dict[str, Any]) -> bool:
    """某终端是否落后于当前发布（rel 须为 latest/stale 以外也可比较清单版本）。"""
    want = str(rel.get("build_id") or "")
    have = str((agent.get("build_id") or ""))
    if want and have:
        return want != have
    wv, hv = str(rel.get("version") or ""), str(agent.get("version") or "")
    return bool(wv and hv and wv != hv)


def _find_go() -> str:
    from shutil import which
    p = which("go")
    if p:
        return p
    for cand in (r"C:\Program Files\Go\bin\go.exe", r"C:\Go\bin\go.exe"):
        if os.path.isfile(cand):
            return cand
    return ""


def run_build(timeout_sec: int = 900, goarch: str = "amd64") -> Dict[str, Any]:
    """Build the selected Windows Agent architecture and retain failures for the UI."""
    arch = str(goarch or "amd64").strip().lower()
    if arch not in {"amd64", "386", "arm64"}:
        return {"ok": False, "error": f"Unsupported Windows architecture: {arch}"}
    if not _build_lock.acquire(blocking=False):
        return {"ok": False, "error": "Agent build is already running"}
    _build_state["running"] = True
    t0 = time.time()
    try:
        script = Path(config.ROOT) / "scripts" / "build_agent.py"
        if not script.is_file():
            res = {"ok": False, "error": "Missing scripts/build_agent.py", "goarch": arch}
        elif not _find_go():
            res = {"ok": False, "error": "Go toolchain was not found on the backend", "goarch": arch}
        else:
            out_path = windows_agent_path(arch)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                cp = subprocess.run(
                    [sys.executable, str(script), "--goarch", arch, "--out", str(out_path)],
                    cwd=str(config.ROOT), capture_output=True, timeout=timeout_sec,
                )
                log = (cp.stdout or b"").decode("utf-8", "replace") + (cp.stderr or b"").decode("utf-8", "replace")
                res = {
                    "ok": cp.returncode == 0, "code": cp.returncode, "log": log[-4000:],
                    "seconds": round(time.time() - t0, 1), "goarch": arch,
                    "release": release_status(out_path) if cp.returncode == 0 else None,
                }
                if cp.returncode != 0:
                    res["error"] = "Agent build failed"
                else:
                    try:
                        from .agent_protocol import clear_install_package_cache
                        res["install_cache_cleared"] = clear_install_package_cache()
                    except Exception as exc:
                        res["cache_warning"] = str(exc)[:300]
            except subprocess.TimeoutExpired as exc:
                stdout = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else str(exc.stdout or "")
                stderr = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else str(exc.stderr or "")
                res = {
                    "ok": False, "error": f"Agent build timed out after {timeout_sec}s",
                    "log": (stdout + stderr)[-4000:], "seconds": round(time.time() - t0, 1),
                    "goarch": arch,
                }
    except Exception as exc:
        res = {
            "ok": False, "error": f"Agent build failed: {type(exc).__name__}: {exc}",
            "seconds": round(time.time() - t0, 1), "goarch": arch,
        }
    finally:
        _build_state["running"] = False
        _build_lock.release()
    _build_state["last"] = {**res, "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "goarch": arch}
    return res
