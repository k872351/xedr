"""Build, cache and package signed Windows Agent installation bundles."""
from __future__ import annotations

import hashlib
import json
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Optional, Tuple, Union

from . import config


_pkg_lock = threading.Lock()


def agent_binary_path(goarch: str = "amd64") -> Optional[Path]:
    """Resolve a Windows Agent release by target architecture."""
    arch = str(goarch or "amd64").strip().lower()
    if arch not in {"amd64", "386", "arm64"}:
        raise ValueError("Windows architecture must be amd64, 386, or arm64")
    if arch == "amd64":
        candidates = [
            Path(config.ROOT) / "agent" / "forensic-agent.exe",
            Path(config.ROOT) / "tools" / "agent" / "forensic-agent.exe",
            Path(getattr(config, "REPORTS_DIR", config.ROOT / "reports")) / "agent" / "forensic-agent.exe",
        ]
    else:
        candidates = [
            Path(config.ROOT) / "agent" / "releases" / "windows" / arch / "forensic-agent.exe",
            Path(config.ROOT) / "tools" / "agent" / "releases" / "windows" / arch / "forensic-agent.exe",
            Path(getattr(config, "REPORTS_DIR", config.ROOT / "reports")) / "agent" / "releases" / "windows" / arch / "forensic-agent.exe",
        ]
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_size > 100_000:
            return candidate
    return None


def _ensure_setup_exe(agent_dir: Path, goarch: str = "amd64") -> Optional[Path]:
    """返回 ForensicAgent-Setup.exe；缺失时尝试用 Go 现编。"""
    setup = agent_dir / "ForensicAgent-Setup.exe"
    if setup.is_file() and setup.stat().st_size > 50_000:
        return setup
    try:
        import os
        import subprocess
        from . import agent_release as _ar
        go = _ar._find_go()
        if not go:
            return None
        env = os.environ.copy()
        env["CGO_ENABLED"] = "0"
        env["GOOS"] = "windows"
        env["GOARCH"] = str(goarch or "amd64")
        env.setdefault("GOPROXY", "https://goproxy.cn,direct")
        cp = subprocess.run(
            [go, "build", "-trimpath", "-ldflags=-s -w -H windowsgui",
             "-o", str(setup), "./cmd/setup"],
            cwd=str(agent_dir), env=env, capture_output=True, text=True, timeout=120,
        )
        if cp.returncode == 0 and setup.is_file():
            return setup
    except Exception:
        return None
    return None


def _package_cache_dir() -> Path:
    d = Path(config.REPORTS_DIR) / "agent_packages"
    d.mkdir(parents=True, exist_ok=True)
    return d


def clear_install_package_cache() -> int:
    """删除已缓存的安装 zip（Agent/驱动更新后需重新打包容）。"""
    n = 0
    for p in _package_cache_dir().glob("pkg_*.zip"):
        try:
            p.unlink()
            n += 1
        except OSError:
            pass
    return n


def build_install_package(*, server_url: str, goarch: str = "amd64") -> Tuple[Union[bytes, Path], str]:
    """生成开箱即用安装包：exe + agent.json + install 脚本。

    优化：
    - exe 用 ZIP_STORED（已压缩 PE，再 DEFLATE 又慢又几乎不缩小）
    - 按 exe mtime + 接入密钥 + 平台地址 磁盘缓存，二次下载近乎秒开
    返回 (Path 缓存文件 | bytes, 下载文件名)。
    """
    from .agent_protocol import AGENT_MODULES, MODULE_INTERVAL_SEC, get_or_create_enroll_key

    arch = str(goarch or "amd64").strip().lower()
    exe = agent_binary_path(arch)
    if not exe:
        raise FileNotFoundError(
            "缺少 forensic-agent.exe，请先在服务器编译 agent/ 或放到 tools/agent/"
        )
    base = str(server_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("server_url 为空")
    # 去掉前端 path（/app、/a）
    for suf in ("/app", "/a"):
        if base.lower().endswith(suf):
            base = base[: -len(suf)].rstrip("/")
    key = get_or_create_enroll_key()
    from . import agent_release
    rel = agent_release.release_status(exe)
    if not rel.get("integrity_verified") or rel.get("status") not in ("latest", "stale"):
        raise ValueError("Agent release integrity cannot be verified; rebuild required")
    manifest = agent_release.load_manifest(exe)
    from .agent_install_scripts import install_bat, install_gui_ps1, install_vbs, readme_text, uninstall_bat

    try:
        from . import agent_sysmon_artifact as _asa
        sm_sig = ";".join(
            f"{p.name}:{p.stat().st_size}:{int(p.stat().st_mtime)}" for p in _asa.iter_sysmon_bundle_files()
        )
    except Exception:
        sm_sig = ""
    cache_key = hashlib.sha1(
        f"{arch}|{rel['exe_sha256']}|{base}|{key}|{rel.get('build_id','')}|v15-identity-preserving-config|{sm_sig}".encode("utf-8")
    ).hexdigest()[:20]
    tag = str(rel.get("build_id") or rel.get("source_version") or "unverified").replace("+", "-")
    name = f"ForensicAgent_{tag}_windows_{arch}_{time.strftime('%Y%m%d')}.zip"
    cache_path = _package_cache_dir() / f"pkg_{cache_key}.zip"

    with _pkg_lock:
        if cache_path.is_file() and cache_path.stat().st_size > 100_000:
            return cache_path, name

        cfg = {
            "server_url": base,
            "token": key,
            "modules": list(AGENT_MODULES),
            "intervals_sec": dict(MODULE_INTERVAL_SEC),
        }
        bat_main = install_bat()
        bat_vbs = install_vbs()
        bat_un = uninstall_bat()
        gui_ps1 = install_gui_ps1()
        readme = readme_text(base=base, rel=rel)

        cfg_text = json.dumps(cfg, ensure_ascii=False, indent=2)
        # The optional native installer has no independently verified release
        # manifest. Do not distribute it (or an MSI embedding it) until verified.
        setup_exe = None
        msi: Optional[Path] = None
        if arch == "amd64" and setup_exe and setup_exe.is_file():
            try:
                from . import agent_msi
                msi = agent_msi.build_msi(
                    setup_exe=setup_exe, agent_exe=Path(exe), agent_json_text=cfg_text,
                    server_url=base, version=str(rel.get("version") or "1.0.0"),
                    out_msi=cache_path.with_suffix(".msi"),
                )
            except Exception as e:
                print(f"[agent-pkg] MSI 构建跳过: {e}", flush=True)
                msi = None

        tmp = cache_path.with_suffix(".tmp")
        if msi and msi.is_file():
            # MSI 已内含 Agent、配置、安装程序与驱动：下载包只放 MSI + 说明
            try:
                from .agent_install_scripts import msi_readme_text
                with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
                    zf.write(msi, arcname="ForensicAgent.msi", compress_type=zipfile.ZIP_STORED)
                    zf.writestr("安装说明.txt", msi_readme_text(base=base, rel=rel))
                tmp.replace(cache_path)
            finally:
                msi.unlink(missing_ok=True)
                tmp.unlink(missing_ok=True)
            return cache_path, name

        try:
            with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
                zf.writestr("ForensicAgent/agent.json", cfg_text)
                zf.writestr("ForensicAgent/install.bat", bat_main)
                zf.writestr("ForensicAgent/install.vbs", bat_vbs)
                zf.writestr("ForensicAgent/Install-GUI.ps1", gui_ps1)
                zf.writestr("ForensicAgent/uninstall.bat", bat_un)
                zf.writestr("ForensicAgent/README.txt", readme)
                if manifest:
                    zf.writestr("ForensicAgent/build-manifest.json",
                                json.dumps(manifest, ensure_ascii=False, indent=2))
                # PE 再压缩收益极低，STORE 可把打包从数百毫秒～数秒降到接近拷贝
                zf.write(exe, arcname="ForensicAgent/forensic-agent.exe", compress_type=zipfile.ZIP_STORED)
                if arch == "amd64":
                    try:
                        from . import agent_msi as _am
                        for p in _am.driver_files():
                            zf.write(p, arcname=f"ForensicAgent/driver/{p.name}", compress_type=zipfile.ZIP_STORED)
                    except Exception:
                        pass
                try:
                    from . import agent_sysmon_artifact as _asa
                    for p in _asa.iter_sysmon_bundle_files():
                        zf.write(p, arcname=f"ForensicAgent/sysmon/{p.name}", compress_type=zipfile.ZIP_STORED)
                except Exception:
                    pass
                if setup_exe and setup_exe.is_file():
                    zf.write(setup_exe, arcname="ForensicAgent/ForensicAgent-Setup.exe",
                             compress_type=zipfile.ZIP_STORED)
            tmp.replace(cache_path)
        except Exception:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            raise

        # 只保留最近几个缓存，避免占盘
        try:
            pkgs = sorted(_package_cache_dir().glob("pkg_*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
            for old in pkgs[8:]:
                try:
                    old.unlink()
                except Exception:
                    pass
        except Exception:
            pass

        return cache_path, name
