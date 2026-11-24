"""Build and package Linux Agent releases for backend downloads."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import threading
import time
from pathlib import Path
from typing import Any

from . import config

_lock = threading.Lock()
_SUPPORTED_ARCHES = {"amd64", "arm64", "loong64", "riscv64"}


def _output_dir() -> Path:
    path = Path(config.REPORTS_DIR) / "agent_linux"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _manifest_path(binary: Path) -> Path:
    return binary.with_name(binary.name + ".manifest.json")


def _build_binary(arch: str) -> tuple[Path, dict[str, Any]]:
    from . import agent_release

    if arch not in _SUPPORTED_ARCHES:
        raise ValueError("Linux architecture must be one of amd64, arm64, loong64, riscv64")
    go = agent_release._find_go()
    if not go:
        raise RuntimeError("Go toolchain is unavailable on the backend")
    src = Path(config.ROOT) / "agent"
    source_rev = agent_release.compute_source_rev(src)
    version = agent_release.source_version(src) or "0.0.0"
    build_id = f"{version}+{source_rev[:8]}"
    directory = _output_dir()
    binary = directory / f"forensic-agent-linux-{arch}"
    manifest_path = _manifest_path(binary)
    with _lock:
        manifest: dict[str, Any] = {}
        if binary.is_file() and manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                manifest = {}
        if (
            manifest.get("source_rev") == source_rev
            and manifest.get("goarch") == arch
            and manifest.get("goos") == "linux"
            and binary.is_file()
        ):
            try:
                if (binary.stat().st_size == manifest.get("binary_size")
                        and hashlib.sha256(binary.read_bytes()).hexdigest() == manifest.get("binary_sha256")):
                    return binary, manifest
            except OSError:
                pass

        temp_binary = binary.with_name(binary.name + ".new")
        build_time = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        ldflags = f"-s -w -X main.buildID={build_id} -X main.buildTime={build_time} -X main.sourceRev={source_rev}"
        env = os.environ.copy()
        env["GOOS"] = "linux"
        env["GOARCH"] = arch
        env["CGO_ENABLED"] = "0"
        env.setdefault("GOPROXY", "https://goproxy.cn,direct")
        try:
            cp = subprocess.run(
                [go, "build", "-trimpath", f"-ldflags={ldflags}", "-o", str(temp_binary), "."],
                cwd=str(src), env=env, capture_output=True, timeout=600,
            )
        except subprocess.TimeoutExpired as exc:
            temp_binary.unlink(missing_ok=True)
            raise RuntimeError("Linux Agent build timed out after 600 seconds") from exc
        if cp.returncode:
            temp_binary.unlink(missing_ok=True)
            details = ((cp.stdout or b"") + (cp.stderr or b"")).decode("utf-8", "replace")
            raise RuntimeError("Linux Agent build failed: " + details[-3000:])
        os.replace(temp_binary, binary)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        manifest = {
            "schema": 1,
            "version": version,
            "build_id": build_id,
            "build_time": build_time,
            "source_rev": source_rev,
            "binary_name": binary.name,
            "binary_size": binary.stat().st_size,
            "binary_sha256": digest,
            "protocol_min": 1,
            "protocol_max": 2,
            "goos": "linux",
            "goarch": arch,
            "capabilities": [
                "snapshot.v1", "timeline.v1", "command.ack.v1", "ingest.v2", "health.v1",
                "inventory.delta", "policy.lkg", "fleet.checkin.v1", "diagnostics.v2",
                "composable.host.v1", "event.schema.v1", "dns.aggregate", "fim.polling.v1",
                "inventory.kernel_module.v1", "inventory.software.linux.v1",
                "inventory.package_updates.linux.v1", "inventory.process.procfs.v1",
                "inventory.network.procfs.v1", "rules.linux.process_snapshot.v1",
                "inventory.services.systemd_units.linux.v1",
                "inventory.tasks.cron_systemd.linux.v1", "inventory.startup.linux.v1",
                "rootcheck.linux.v1", "sca.linux.v1",
                "response.kill_process.linux.v1", "response.quarantine_file.linux.v1",
                "sensor.linux.journal.v1",
            ],
        }
        temp_manifest = manifest_path.with_suffix(".tmp")
        temp_manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp_manifest, manifest_path)
        return binary, manifest


def build_linux_package(*, server_url: str, arch: str = "amd64") -> tuple[Path, str, dict[str, Any]]:
    from .agent_protocol import AGENT_MODULES, MODULE_INTERVAL_SEC, get_or_create_enroll_key

    base = str(server_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("server_url is required")
    for suffix in ("/app", "/a"):
        if base.lower().endswith(suffix):
            base = base[:-len(suffix)].rstrip("/")
    binary, manifest = _build_binary(arch)
    directory = _output_dir()
    key = get_or_create_enroll_key()
    package_key = hashlib.sha256(
        f"{base}|{key}|{manifest['build_id']}|{arch}".encode("utf-8")
    ).hexdigest()[:16]
    archive = directory / f"pkg-{package_key}-linux-{arch}.tar.gz"
    config_json = json.dumps({
        "server_url": base,
        "token": key,
        "modules": list(AGENT_MODULES),
        "intervals_sec": dict(MODULE_INTERVAL_SEC),
        "state_dir": "/var/lib/forensic-agent",
    }, ensure_ascii=False, indent=2)
    install_script = """#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo: sudo ./install.sh" >&2; exit 1; fi
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEST=/opt/forensic-agent
if [ -e "$DEST/agent.json" ]; then
    if ! command -v python3 >/dev/null 2>&1; then echo "Cannot validate existing configuration; use an explicit migration procedure" >&2; exit 1; fi
    python3 - "$DEST/agent.json" "$BASE/agent.json" <<'PYCFG'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8-sig') as f: old = json.load(f)
    with open(sys.argv[2], encoding='utf-8-sig') as f: new = json.load(f)
    a = old.get('server_url', '').strip().rstrip('/')
    b = new.get('server_url', '').strip().rstrip('/')
    if not a or a != b: raise ValueError()
except (OSError, ValueError, TypeError, AttributeError):
    sys.exit('Existing configuration differs or is invalid; explicit migration required')
PYCFG
    echo "Existing agent.json will be preserved; changing servers requires an explicit migration."
fi
systemctl stop forensic-agent.service 2>/dev/null || true
install -d -m 0750 "$DEST"
install -m 0755 "$BASE/forensic-agent" "$DEST/forensic-agent"
if [ ! -e "$DEST/agent.json" ]; then
    install -m 0600 "$BASE/agent.json" "$DEST/agent.json"
fi
install -m 0644 "$BASE/forensic-agent.service" /etc/systemd/system/forensic-agent.service
systemctl daemon-reload
systemctl enable --now forensic-agent.service
echo "Forensic Agent installed and started. Check: systemctl status forensic-agent"
"""
    uninstall_script = """#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo: sudo ./uninstall.sh" >&2; exit 1; fi
systemctl disable --now forensic-agent.service || true
rm -f /etc/systemd/system/forensic-agent.service
systemctl daemon-reload
rm -rf /opt/forensic-agent
if [ "${PURGE_STATE:-0}" = "1" ]; then rm -rf /var/lib/forensic-agent; fi
echo "Forensic Agent removed. State is preserved under /var/lib/forensic-agent; set PURGE_STATE=1 to delete it."
"""
    unit = """[Unit]
Description=Forensic Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/forensic-agent/forensic-agent -config /opt/forensic-agent/agent.json
Restart=on-failure
RestartSec=10s
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
    readme = """Forensic Agent for Linux

Supported architectures: Linux x86_64 (amd64), ARM64 (arm64), LoongArch64 (loong64), and RISC-V64 (riscv64).
Install: extract this archive and run `sudo ./install.sh`.
Service: systemctl status|restart|stop forensic-agent
Uninstall: sudo ./uninstall.sh
Linux collectors include procfs process/network snapshots, asset/package inventory,
polling FIM, rootcheck and SCA. Initial snapshots are staggered over the first minute.
Remote response supports process SIGTERM and file quarantine/restore.
Windows-only ETW, Event Log, registry and kernel-driver sensors are not included.
The package config contains an enrollment key. Keep the archive private.
"""
    temp_archive = archive.with_suffix(archive.suffix + ".tmp")
    with _lock:
        with tarfile.open(temp_archive, mode="w:gz", compresslevel=1) as tf:
            tf.add(binary, arcname="forensic-agent-linux/forensic-agent")
            tf.add(_manifest_path(binary), arcname="forensic-agent-linux/build-manifest.json")
            for name, contents, mode in (
                ("agent.json", config_json, 0o600),
                ("install.sh", install_script, 0o750),
                ("uninstall.sh", uninstall_script, 0o750),
                ("forensic-agent.service", unit, 0o644),
                ("README.txt", readme, 0o644),
            ):
                import io
                data = contents.encode("utf-8")
                info = tarfile.TarInfo(f"forensic-agent-linux/{name}")
                info.size = len(data)
                info.mode = mode
                tf.addfile(info, io.BytesIO(data))
    os.replace(temp_archive, archive)
    filename = f"ForensicAgent_{manifest['build_id']}_linux_{arch}.tar.gz"
    return archive, filename, manifest
