"""AI 生成检测规则草案 → 人工审核后写入 agent_rules。"""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from typing import Any, Dict, List

from . import agent_edr

_lock = threading.RLock()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_rule_drafts (
    id TEXT PRIMARY KEY,
    title TEXT DEFAULT '',
    draft_json TEXT DEFAULT '{}',
    prompt TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    reviewer TEXT DEFAULT '',
    note TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def _conn():
    agent_edr.ensure()
    conn = agent_edr._connect()
    conn.executescript(_SCHEMA)
    return conn


def _heuristic_draft(prompt: str) -> Dict[str, Any]:
    p = str(prompt or "")
    low = p.lower()
    rid = "ai-" + uuid.uuid4().hex[:10]
    title = p.strip().splitlines()[0][:80] or "AI 草案规则"
    modules = ["process"]
    severity = "medium"
    fields = ["path", "name", "command_line"]
    pattern = ""
    if any(x in low for x in ("外联", "beacon", "c2", "network", "http")):
        modules = ["network"]
        fields = ["remote", "domain", "process_name"]
        severity = "high"
    if any(x in low for x in ("注册表", "persist", "启动", "run key")):
        modules = ["registry", "persist"]
        fields = ["key", "value", "path"]
        severity = "high"
    if any(x in low for x in ("powershell", "编码", "encoded")):
        modules = ["process"]
        severity = "high"
        pattern = "powershell"
    m = re.findall(r"[\"'`]([^\"'`]{3,40})[\"'`]", p)
    if m and not pattern:
        pattern = m[0]
    if not pattern:
        # 取较长的词作特征
        toks = re.findall(r"[\w.\\-]{4,}", p)
        pattern = toks[0] if toks else "suspicious"
    return {
        "id": rid,
        "title": title,
        "severity": severity,
        "modules": modules,
        "fields": fields,
        "patterns": [pattern],
        "match": "substring",
        "enabled": False,
        "source": "ai_draft",
        "note": "AI/启发式草案，需人工审核后启用",
        "prompt": p[:500],
    }


def create_draft(prompt: str, *, actor: str = "") -> Dict[str, Any]:
    prompt = str(prompt or "").strip()
    if len(prompt) < 4:
        return {"ok": False, "error": "描述太短"}
    draft = _heuristic_draft(prompt)
    # 可选：调用本地模型润色
    try:
        from .ai import analyzer
        if hasattr(analyzer, "draft_detection_rule"):
            ai = analyzer.draft_detection_rule(prompt)
            if isinstance(ai, dict) and ai.get("title"):
                draft.update({k: ai[k] for k in ("title", "severity", "etype", "pattern", "note") if ai.get(k)})
    except Exception:
        pass
    did = uuid.uuid4().hex
    now = _now()
    with _lock:
        conn = _conn()
        try:
            conn.execute(
                """INSERT INTO ai_rule_drafts(id, title, draft_json, prompt, status, created_at, updated_at)
                   VALUES(?,?,?,?, 'pending', ?, ?)""",
                (did, draft.get("title") or "", json.dumps(draft, ensure_ascii=False), prompt[:2000], now, now),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "id": did, "draft": draft, "status": "pending"}


def list_drafts(*, status: str = "pending", limit: int = 50) -> Dict[str, Any]:
    with _lock:
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT * FROM ai_rule_drafts WHERE (?='' OR status=?) ORDER BY created_at DESC LIMIT ?",
                (status, status, max(1, min(limit, 200))),
            ).fetchall()
            return {"ok": True, "items": [dict(r) for r in rows]}
        finally:
            conn.close()


def review_draft(draft_id: str, *, approve: bool, actor: str = "", note: str = "") -> Dict[str, Any]:
    with _lock:
        conn = _conn()
        try:
            row = conn.execute("SELECT * FROM ai_rule_drafts WHERE id=?", (draft_id,)).fetchone()
            if not row:
                return {"ok": False, "error": "草案不存在"}
            if row["status"] != "pending":
                return {"ok": False, "error": f"状态不可审: {row['status']}"}
            draft = json.loads(row["draft_json"] or "{}")
            now = _now()
            if not approve:
                conn.execute(
                    "UPDATE ai_rule_drafts SET status='rejected', reviewer=?, note=?, updated_at=? WHERE id=?",
                    (actor[:64], note[:500], now, draft_id),
                )
                conn.commit()
                return {"ok": True, "id": draft_id, "status": "rejected"}
        finally:
            conn.close()

    from . import agent_rules
    draft["enabled"] = True
    draft.setdefault("source", "ai_draft")
    try:
        agent_rules.create_rule(draft)
    except Exception as e:
        # ID 冲突则覆盖导入
        try:
            agent_rules.upsert_imported_rule(draft)
        except Exception as e2:
            return {"ok": False, "error": f"写入规则失败: {e}; {e2}"}

    with _lock:
        conn = _conn()
        try:
            conn.execute(
                "UPDATE ai_rule_drafts SET status='approved', reviewer=?, note=?, updated_at=? WHERE id=?",
                (actor[:64], note[:500], _now(), draft_id),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "id": draft_id, "status": "approved", "rule_id": draft.get("id")}
