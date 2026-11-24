"""Agent whitelist and endpoint group management."""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from . import agent_protocol
from .agent_edr import _audit, _connect, _lock, _now, ensure


def list_whitelist() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM agent_whitelist ORDER BY created_at DESC").fetchall()
            return {"ok": True, "items": [dict(r) for r in rows]}
        finally:
            conn.close()


def add_whitelist(
    kind: str,
    value: str,
    *,
    note: str = "",
    agent_id: str = "",
    rule: str = "",
    created_by: str = "",
    source_event_id: int = 0,
    apply_existing: bool = True,
) -> Dict[str, Any]:
    from . import alert_allow

    ensure()
    kind = str(kind or "").strip().lower()[:32]
    value = str(value or "").strip()[:500]
    kind, value = alert_allow.coerce_kind_value(kind, value)
    value = value[:500]
    rule = alert_allow.normalize_rule(rule)[:300]
    agent_id = str(agent_id or "").strip()[:64]
    if kind not in alert_allow.KINDS or not value:
        return {"ok": False, "error": "kind/value 无效"}
    if kind == "title" and value.strip("*? ") == "":
        return {"ok": False, "error": "标题通配过宽，会屏蔽全部告警"}
    wid = uuid.uuid4().hex
    entry = {"id": wid, "kind": kind, "value": value, "agent_id": agent_id, "rule": rule, "enabled": 1}
    ignored = 0
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_whitelist(id, kind, value, note, enabled, created_at,
                                               agent_id, rule, hits, last_hit_at, created_by, source_event_id)
                   VALUES(?,?,?,?,1,?,?,?,0,'',?,?)""",
                (wid, kind, value, note[:200], _now(), agent_id, rule, created_by[:64], int(source_event_id or 0)),
            )
            conn.commit()
            # 默认回溯：路径/进程加白后，已有未处置同类告警立刻标为无需处置
            if apply_existing:
                ignored = alert_allow.apply_to_open_events(conn, entry)
        finally:
            conn.close()
    _audit("whitelist_add", agent_id=agent_id, actor=created_by,
           detail=json.dumps({"kind": kind, "value": value, "rule": rule, "ignored": ignored}, ensure_ascii=False))
    agent_protocol.bump_live("whitelist")
    try:
        from . import agent_sync
        agent_sync.bump_sync("whitelist")
    except Exception:
        pass
    if ignored:
        agent_protocol.bump_live("event")
    return {"ok": True, "id": wid, "ignored": ignored}


def set_whitelist_enabled(wid: str, enabled: bool) -> Dict[str, Any]:
    return update_whitelist(wid, enabled=bool(enabled))


def update_whitelist(
    wid: str,
    *,
    kind: Optional[str] = None,
    value: Optional[str] = None,
    note: Optional[str] = None,
    rule: Optional[str] = None,
    agent_id: Optional[str] = None,
    enabled: Optional[bool] = None,
    apply_existing: bool = False,
) -> Dict[str, Any]:
    """更新加白条目字段；仅传入的字段会改动。"""
    from . import alert_allow

    ensure()
    wid = str(wid or "").strip()
    if not wid:
        return {"ok": False, "error": "id 无效"}

    fields: Dict[str, Any] = {}
    if kind is not None or value is not None:
        # 改类型/值时需成对校验；缺省则读库补齐
        pass
    if note is not None:
        fields["note"] = str(note)[:200]
    if rule is not None:
        from . import alert_allow as _aa
        fields["rule"] = _aa.normalize_rule(rule)[:300]
    if agent_id is not None:
        fields["agent_id"] = str(agent_id or "").strip()[:64]
    if enabled is not None:
        fields["enabled"] = 1 if enabled else 0

    ignored = 0
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM agent_whitelist WHERE id=?", (wid,)).fetchone()
            if not row:
                return {"ok": False, "error": "不存在"}
            cur_kind = str(row["kind"] or "")
            cur_value = str(row["value"] or "")
            if kind is not None or value is not None:
                new_kind = str(kind if kind is not None else cur_kind or "").strip().lower()[:32]
                new_value = str(value if value is not None else cur_value or "").strip()[:500]
                new_kind, new_value = alert_allow.coerce_kind_value(new_kind, new_value)
                new_value = new_value[:500]
                if new_kind not in alert_allow.KINDS or not new_value:
                    return {"ok": False, "error": "kind/value 无效"}
                if new_kind == "title" and new_value.strip("*? ") == "":
                    return {"ok": False, "error": "标题通配过宽，会屏蔽全部告警"}
                fields["kind"] = new_kind
                fields["value"] = new_value
            if not fields:
                return {"ok": True, "id": wid, "unchanged": True}
            sets = ", ".join(f"{k}=?" for k in fields)
            conn.execute(
                f"UPDATE agent_whitelist SET {sets} WHERE id=?",
                (*fields.values(), wid),
            )
            conn.commit()
            if apply_existing and ("kind" in fields or "value" in fields or "rule" in fields or "agent_id" in fields):
                entry = {
                    "id": wid,
                    "kind": fields.get("kind", cur_kind),
                    "value": fields.get("value", cur_value),
                    "agent_id": fields.get("agent_id", row["agent_id"] if "agent_id" in row.keys() else ""),
                    "rule": fields.get("rule", row["rule"] if "rule" in row.keys() else ""),
                    "enabled": fields.get("enabled", row["enabled"]),
                }
                ignored = alert_allow.apply_to_open_events(conn, entry)
        finally:
            conn.close()

    _audit(
        "whitelist_update",
        agent_id=str(fields.get("agent_id") or ""),
        detail=json.dumps({"id": wid, **{k: fields[k] for k in fields}, "ignored": ignored}, ensure_ascii=False),
    )
    agent_protocol.bump_live("whitelist")
    try:
        from . import agent_sync
        agent_sync.bump_sync("whitelist")
    except Exception:
        pass
    if ignored:
        agent_protocol.bump_live("event")
    return {"ok": True, "id": wid, "ignored": ignored}


def delete_whitelist(wid: str) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM agent_whitelist WHERE id=?", (str(wid),))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "不存在"}
        finally:
            conn.close()
    agent_protocol.bump_live("whitelist")
    try:
        from . import agent_sync
        agent_sync.bump_sync("whitelist")
    except Exception:
        pass
    return {"ok": True}


def list_groups() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM agent_groups ORDER BY name").fetchall()
            items = []
            for r in rows:
                d = dict(r)
                try:
                    d["agent_ids"] = json.loads(d.pop("agent_ids_json") or "[]")
                except Exception:
                    d["agent_ids"] = []
                items.append(d)
            return {"ok": True, "items": items}
        finally:
            conn.close()


def upsert_group(gid: str, name: str, agent_ids: List[str], *, note: str = "") -> Dict[str, Any]:
    ensure()
    gid = str(gid or "").strip() or uuid.uuid4().hex
    name = str(name or "").strip()[:64] or gid
    ids = [str(x) for x in (agent_ids or []) if x][:500]
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_groups(id, name, agent_ids_json, note, updated_at) VALUES(?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name,
                     agent_ids_json=excluded.agent_ids_json,
                     note=excluded.note,
                     updated_at=excluded.updated_at""",
                (gid, name, json.dumps(ids, ensure_ascii=False), note[:200], _now()),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "id": gid, "name": name, "agent_ids": ids, "note": note[:200]}


def assign_agent_to_group(agent_id: str, group_id: str = "") -> Dict[str, Any]:
    """把主机移入指定分组（互斥：先从其它组移除）。group_id 为空表示未分组。"""
    ensure()
    aid = str(agent_id or "").strip()
    gid = str(group_id or "").strip()
    if not aid:
        return {"ok": False, "error": "missing agent_id"}
    with _lock:
        conn = _connect()
        try:
            if gid:
                hit = conn.execute("SELECT id FROM agent_groups WHERE id=?", (gid,)).fetchone()
                if not hit:
                    return {"ok": False, "error": "group_not_found"}
            rows = conn.execute("SELECT id, agent_ids_json FROM agent_groups").fetchall()
            changed = 0
            for r in rows:
                rid = str(r["id"])
                try:
                    ids = [str(x) for x in json.loads(r["agent_ids_json"] or "[]") if x]
                except Exception:
                    ids = []
                has = aid in ids
                want = rid == gid
                if want and not has:
                    ids.append(aid)
                elif has and not want:
                    ids = [x for x in ids if x != aid]
                else:
                    continue
                conn.execute(
                    "UPDATE agent_groups SET agent_ids_json=?, updated_at=? WHERE id=?",
                    (json.dumps(ids, ensure_ascii=False), _now(), rid),
                )
                changed += 1
            conn.commit()
            return {"ok": True, "agent_id": aid, "group_id": gid, "changed": changed}
        finally:
            conn.close()


def delete_group(gid: str) -> Dict[str, Any]:
    ensure()
    gid = str(gid or "").strip()
    if not gid:
        return {"ok": False, "error": "missing id"}
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM agent_groups WHERE id=?", (gid,))
            conn.commit()
            if not cur.rowcount:
                return {"ok": False, "error": "not_found"}
            return {"ok": True, "id": gid}
        finally:
            conn.close()
