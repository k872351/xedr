# -*- coding: utf-8 -*-
"""XEDR 驱动文件加密的主密钥（KEK）管理与托管。

- 主密钥只在平台库中保存，并只在下发给已认证终端时随心跳/同步一起带出，
  不进入策略 JSON（策略会在管理台展示、审计、版本化）。
- 驱动只在内存里持有主密钥；文件里只存随机 nonce + 密钥 ID，丢了主密钥文件就无法解密，
  所以必须能导出（托管/离线恢复用 agent/xedr-decrypt.exe），且导出要审计。
- 轮换：新建一把设为当前，旧钥保留在环里（最多 8 把）以便旧文件仍可读。
"""
from __future__ import annotations

import base64
import json
import secrets
from typing import Any, Dict, List, Optional

from . import agent_edr

MAX_KEYS = 8

_SCHEMA = """
CREATE TABLE IF NOT EXISTS xedr_crypto_keys (
    id INTEGER PRIMARY KEY,
    key_b64 TEXT NOT NULL,
    active INTEGER DEFAULT 0,
    created_at TEXT DEFAULT '',
    created_by TEXT DEFAULT ''
);
"""


def _ensure() -> None:
    agent_edr.ensure()
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


def _rows() -> List[Dict[str, Any]]:
    _ensure()
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            rows = conn.execute("SELECT * FROM xedr_crypto_keys ORDER BY id").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def _create(actor: str) -> int:
    key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) AS m FROM xedr_crypto_keys").fetchone()
            new_id = int(row["m"] or 0) + 1
            conn.execute("UPDATE xedr_crypto_keys SET active=0")
            conn.execute(
                "INSERT INTO xedr_crypto_keys(id, key_b64, active, created_at, created_by) VALUES(?,?,1,?,?)",
                (new_id, key, agent_edr._now(), actor[:64]),
            )
            conn.commit()
            return new_id
        finally:
            conn.close()


def ensure_active_key(actor: str = "system") -> int:
    rows = _rows()
    for r in rows:
        if r.get("active"):
            return int(r["id"])
    if rows:
        # 有钥但无当前：把最新一把设为当前
        latest = int(rows[-1]["id"])
        with agent_edr._lock:
            conn = agent_edr._connect()
            try:
                conn.execute("UPDATE xedr_crypto_keys SET active=CASE WHEN id=? THEN 1 ELSE 0 END", (latest,))
                conn.commit()
            finally:
                conn.close()
        return latest
    kid = _create(actor)
    agent_edr._audit("xedr_key_create", actor=actor, detail=json.dumps({"key_id": kid}))
    return kid


def rotate(actor: str) -> Dict[str, Any]:
    _ensure()
    if len(_rows()) >= MAX_KEYS:
        return {"ok": False, "error": f"最多保留 {MAX_KEYS} 把主密钥（驱动密钥环上限），请先确认旧文件已重新加密"}
    kid = _create(actor)
    agent_edr._audit("xedr_key_rotate", actor=actor, detail=json.dumps({"key_id": kid}))
    _bump()
    return {"ok": True, "active_key_id": kid}


def status() -> Dict[str, Any]:
    rows = _rows()
    return {
        "ok": True,
        "keys": [
            {"id": int(r["id"]), "active": bool(r.get("active")), "created_at": r.get("created_at") or "",
             "created_by": r.get("created_by") or ""}
            for r in rows
        ],
        "active_key_id": next((int(r["id"]) for r in rows if r.get("active")), 0),
    }


def export_keys(actor: str) -> Dict[str, Any]:
    """托管导出（xedr-decrypt -keys 的输入格式）。必须审计。"""
    rows = _rows()
    agent_edr._audit("xedr_key_export", actor=actor, detail=json.dumps({"key_ids": [int(r["id"]) for r in rows]}))
    return {"keys": [{"id": int(r["id"]), "key": r["key_b64"]} for r in rows]}


def encryption_enabled() -> bool:
    pol = agent_edr.get_policy("global").get("policy") or {}
    d = pol.get("dp_driver") if isinstance(pol.get("dp_driver"), dict) else {}
    return bool(d.get("enabled", True)) and bool(d.get("encryption_enabled", False))


def crypto_bundle_for_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    """下发给终端驱动的密钥环。

    一旦生成过主密钥就始终下发：关闭加密只表示不再保护新文件，
    已加密的文件仍要能读，否则终端重启后驱动无钥、文件全部打不开。
    从未开启过加密（库里无钥）时返回 None，终端不持有任何主密钥。
    """
    if not agent_id:
        return None
    rows = _rows()
    if not rows and not encryption_enabled():
        return None
    active = ensure_active_key()
    rows = _rows()[-MAX_KEYS:]
    return {
        "active_key_id": active,
        "keys": [{"id": int(r["id"]), "key": r["key_b64"]} for r in rows],
    }


def _bump() -> None:
    try:
        from . import agent_sync
        agent_sync.bump_sync("policy")
    except Exception:
        pass
