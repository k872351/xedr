"""服务端策略 Ed25519 签名，与 agent/policy_sign.go 的 FA-POLICY-V1 口径一致。"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

_SIG_KEYS = frozenset({"_sig", "sig", "sig_ed25519", "policy_sig"})


def _data_root() -> Path:
    try:
        from . import config
        root = Path(getattr(config, "DATA_ROOT", None) or getattr(config, "ROOT", Path(".")))
    except Exception:
        root = Path(".")
    return root


def _key_paths() -> tuple[Path, Path]:
    d = _data_root() / "data" / "agent_policy_keys"
    d.mkdir(parents=True, exist_ok=True)
    return d / "ed25519_priv.pem", d / "ed25519_pub.b64"


def _canon_value(v: Any) -> Any:
    """规范化以便与 Go encoding/json 对 map[string]any 的输出对齐。"""
    if isinstance(v, dict):
        return {str(k): _canon_value(v[k]) for k in v}
    if isinstance(v, list):
        return [_canon_value(x) for x in v]
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, float):
        if v.is_integer() and abs(v) < 2**53:
            return int(v)
        return v
    if isinstance(v, int):
        return v
    return v


def policy_sign_message(rev: int, pol: Dict[str, Any]) -> bytes:
    clean: Dict[str, Any] = {}
    for k, v in (pol or {}).items():
        if str(k).lower() in _SIG_KEYS:
            continue
        clean[str(k)] = _canon_value(v)
    body = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"FA-POLICY-V1\n{int(rev)}\n{body}".encode("utf-8")


def ensure_policy_keypair() -> Dict[str, Any]:
    """首次生成策略密钥对；可用 EDR_POLICY_PRIV_PEM / EDR_POLICY_PUB_B64 覆盖。"""
    env_priv = (os.environ.get("EDR_POLICY_PRIV_PEM") or "").strip()
    env_pub = (os.environ.get("EDR_POLICY_PUB_B64") or "").strip()
    if env_priv and env_pub:
        return {"ok": True, "pubkey": env_pub, "created": False, "source": "env"}

    priv_path, pub_path = _key_paths()
    if priv_path.is_file() and pub_path.is_file():
        return {
            "ok": True,
            "pubkey": pub_path.read_text(encoding="utf-8").strip(),
            "created": False,
            "source": "file",
        }
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except Exception as e:
        return {"ok": False, "error": f"缺少 cryptography: {e}"}

    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    priv_path.write_bytes(priv_pem)
    try:
        priv_path.chmod(0o600)
    except Exception:
        pass
    pub_path.write_text(pub_b64 + "\n", encoding="utf-8")
    return {"ok": True, "pubkey": pub_b64, "created": True, "source": "generated"}


def get_policy_pubkey() -> Dict[str, Any]:
    out = ensure_policy_keypair()
    if not out.get("ok"):
        return out
    return {"ok": True, "pubkey": out["pubkey"], "alg": "Ed25519", "capability": "policy.sign.v1"}


def _load_private_key():
    env_priv = (os.environ.get("EDR_POLICY_PRIV_PEM") or "").strip()
    if env_priv:
        pem = env_priv.encode("utf-8") if "BEGIN" in env_priv else base64.b64decode(env_priv)
    else:
        priv_path, _ = _key_paths()
        if not priv_path.is_file():
            ensure_policy_keypair()
        priv_path, _ = _key_paths()
        pem = priv_path.read_bytes()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise TypeError("策略私钥不是 Ed25519")
    return priv


def sign_policy_body(rev: int, pol: Dict[str, Any]) -> str:
    """返回 base64 签名；失败返回空串。"""
    out = ensure_policy_keypair()
    if not out.get("ok"):
        return ""
    try:
        priv = _load_private_key()
        sig = priv.sign(policy_sign_message(int(rev), pol or {}))
        return base64.b64encode(sig).decode("ascii")
    except Exception as e:
        print("[policy_sign] sign failed:", e)
        return ""


def attach_policy_signature(pol: Optional[Dict[str, Any]], rev: int) -> Dict[str, Any]:
    """复制策略正文并写入 `_sig`；签名失败时仍返回正文（Agent 生产路径会拒收）。"""
    body = dict(pol or {})
    for k in list(body.keys()):
        if str(k).lower() in _SIG_KEYS:
            body.pop(k, None)
    sig = sign_policy_body(int(rev or 0), body)
    if sig:
        body["_sig"] = sig
    return body
