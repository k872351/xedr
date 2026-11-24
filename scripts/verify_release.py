"""Check an existing local release against its manifest without executing it."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


PE_ARCHITECTURES = {0x014C: "386", 0x8664: "amd64", 0xAA64: "arm64"}


def read_pe_architecture(source) -> str:
    header = source.read(64)
    if len(header) != 64 or header[:2] != b"MZ":
        raise ValueError("Invalid DOS header")
    offset = struct.unpack_from("<I", header, 60)[0]
    if offset < 64:
        raise ValueError("Invalid PE header offset")
    source.seek(offset)
    pe = source.read(6)
    if len(pe) != 6 or pe[:4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")
    machine = struct.unpack_from("<H", pe, 4)[0]
    if machine not in PE_ARCHITECTURES:
        raise ValueError(f"Unsupported PE machine: 0x{machine:04x}")
    return PE_ARCHITECTURES[machine]


def verify_release(manifest: Path) -> bool:
    manifest = manifest.resolve(strict=True)
    data = json.loads(manifest.read_text(encoding="utf-8-sig"))
    name = data["exe_name"]
    if not isinstance(name, str) or not name or Path(name).name != name or name in (".", ".."):
        raise ValueError("Invalid artifact filename")
    artifact = (manifest.parent / name).resolve(strict=True)
    if artifact.parent != manifest.parent or not artifact.is_file():
        raise ValueError("Artifact must be a file alongside the manifest")
    digest = hashlib.sha256()
    with artifact.open("rb") as source:
        if data.get("goos") == "windows":
            if read_pe_architecture(source) != data.get("goarch"):
                return False
            source.seek(0)
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return artifact.stat().st_size == data["exe_size"] and digest.hexdigest() == data["exe_sha256"].lower()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        ok = verify_release(args.manifest)
    except (OSError, KeyError, ValueError, TypeError, AttributeError) as exc:
        print(f"Manifest verification failed: {exc}")
        return 1
    print("Release integrity: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
