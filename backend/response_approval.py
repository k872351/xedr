"""高危处置审批流：请求 → 待审 → 批准下发 / 驳回；支持常见回滚动作。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from . import agent_edr

_lock = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS response_approvals (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    params_json TEXT DEFAULT '{}',
    status TEXT DEFAULT 'pending',
    reason TEXT DEFAULT '',
    requested_by TEXT DEFAULT '',
    reviewed_by TEXT DEFAULT '',
    review_note TEXT DEFAULT '',
    command_id TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_resp_appr_status ON response_approvals(status, created_at);
CREATE INDEX IF NOT EXISTS idx_resp_appr_agent ON response_approvals(agent_id, created_at);
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def _connect() -> sqlite3.Connection:
    agent_edr.ensure()
    conn = agent_edr._connect()
    conn.executescript(_SCHEMA)
    return conn


def approval_required(action: str, *, force: bool = False) -> bool:
    act = str(action or "").strip().lower()
    if force:
        return False
    # 策略开关：agent_policy.response_approval_required，默认 True
    try:
        pack = agent_edr.get_policy()
        pol = pack.get("policy") if isinstance(pack, dict) else {}
        if isinstance(pol, dict) and pol.get("response_approval_required") is False:
            return False
    except Exception:
        pass
    return act in agent_edr.HIGH_RISK_ACTIONS


def _resolve_agent_id(conn: sqlite3.Connection, agent_id: str) -> Optional[str]:
    """按 agent_id 精确匹配；失败则尝试按主机名解析。"""
    aid = str(agent_id or "").strip()
    if not aid:
        return None
    if conn.execute("SELECT 1 FROM agents WHERE agent_id=?", (aid,)).fetchone():
        return aid
    return None


def request_action(
    agent_id: str,
    action: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    actor: str = "",
    reason: str = "",
    skip_approval: bool = False,
    actor_role: str = "",
) -> Dict[str, Any]:
    """创建处置：管理员/显式跳过 → 直接下发；普通用户高危动作进审批。"""
    act = str(action or "").strip().lower()
    aid = str(agent_id or "").strip()
    if not aid or act not in agent_edr.ACTIONS:
        return {"ok": False, "error": "agent_id 或 action 无效"}
    # 管理员处置直接下发，无需审批
    role = str(actor_role or "").strip().lower()
    if role == "admin":
        skip_approval = True
    if not approval_required(act, force=skip_approval):
        return agent_edr.create_command(aid, act, params or {}, actor=actor)

    rid = uuid.uuid4().hex
    now = _now()
    blob = json.dumps(params or {}, ensure_ascii=False)
    with _lock:
        conn = _connect()
        try:
            resolved = _resolve_agent_id(conn, aid)
            if not resolved:
                return {"ok": False, "error": "终端不存在"}
            aid = resolved
            conn.execute(
                """INSERT INTO response_approvals(id, agent_id, action, params_json, status, reason,
                   requested_by, created_at, updated_at)
                   VALUES(?,?,?,?, 'pending', ?, ?, ?, ?)""",
                (rid, aid, act, blob, str(reason or "")[:500], str(actor or "")[:64], now, now),
            )
            conn.commit()
        finally:
            conn.close()
    agent_edr._audit(f"response_approval:request:{act}", agent_id=aid, detail=blob, actor=actor)
    return {"ok": True, "approval_id": rid, "status": "pending", "action": act, "needs_approval": True}


def list_approvals(*, status: str = "pending", agent_id: str = "", limit: int = 50) -> Dict[str, Any]:
    try:
        recover_stuck_approvals()
    except Exception:
        pass
    with _lock:
        conn = _connect()
        try:
            clauses = ["1=1"]
            args: List[Any] = []
            if status:
                clauses.append("status=?")
                args.append(status)
            if agent_id:
                clauses.append("agent_id=?")
                args.append(agent_id)
            args.append(max(1, min(int(limit or 50), 200)))
            rows = conn.execute(
                f"""SELECT * FROM response_approvals WHERE {' AND '.join(clauses)}
                    ORDER BY created_at DESC LIMIT ?""",
                args,
            ).fetchall()
            items = [dict(r) for r in rows]
            # 附带主机名 / 是否仍在册，便于审批页展示
            for it in items:
                aid = str(it.get("agent_id") or "")
                row = conn.execute(
                    "SELECT hostname, last_seen, last_heartbeat_at, heartbeat_period_sec, revoked FROM agents WHERE agent_id=?", (aid,)
                ).fetchone()
                if row:
                    it["hostname"] = row["hostname"] or ""
                    from .agent_protocol import is_agent_online
                    it["agent_online"] = is_agent_online(row["last_heartbeat_at"], row["heartbeat_period_sec"], revoked=bool(row["revoked"]))
                    it["last_seen"] = row["last_seen"] or ""
                else:
                    it["hostname"] = ""
                    it["agent_online"] = False
                    it["last_seen"] = ""
                    it["agent_missing"] = True
                if it.get("command_id"):
                    command = conn.execute("SELECT status, acked_at FROM agent_commands WHERE id=? AND agent_id=?",
                                           (it["command_id"], aid)).fetchone()
                    it["command_status"] = command["status"] if command else "unknown"
                    it["command_acked_at"] = command["acked_at"] if command else ""
        finally:
            conn.close()
    return {"ok": True, "items": items}


def recover_stuck_approvals(*, older_than_sec: int = 120) -> Dict[str, Any]:
    """将异常中断卡在 dispatching 的审批单恢复为 pending，保证可再次审批。

    批准流程在抢占为 dispatching 后若进程崩溃，单会永久卡死；启动与列表时调用本函数。
    """
    cutoff_sec = max(30, min(int(older_than_sec or 120), 3600))
    now = _now()
    recovered: List[str] = []
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT id, updated_at FROM response_approvals WHERE status='dispatching'"
            ).fetchall()
            for row in rows:
                updated = str(row["updated_at"] or "")
                stuck = True
                if updated:
                    try:
                        import datetime as _dt
                        ts = _dt.datetime.strptime(updated[:19], "%Y-%m-%dT%H:%M:%S")
                        age = (_dt.datetime.now() - ts).total_seconds()
                        stuck = age >= cutoff_sec
                    except Exception:
                        stuck = True
                if not stuck:
                    continue
                cur = conn.execute(
                    """UPDATE response_approvals SET status='pending', updated_at=?,
                              review_note=CASE
                                WHEN review_note IS NULL OR review_note='' THEN ?
                                ELSE review_note || ' | ' || ?
                              END
                       WHERE id=? AND status='dispatching'""",
                    (now, "auto-recover:dispatching interrupted", "auto-recover:dispatching interrupted", row["id"]),
                )
                if cur.rowcount:
                    recovered.append(str(row["id"]))
            if recovered:
                conn.commit()
                agent_edr._audit(
                    "response_approval:recover_stuck",
                    detail=json.dumps({"ids": recovered, "count": len(recovered)}, ensure_ascii=False),
                    actor="system",
                )
        finally:
            conn.close()
    return {"ok": True, "recovered": recovered, "count": len(recovered)}


def decide_approval(
    approval_id: str,
    *,
    approve: bool,
    actor: str = "",
    note: str = "",
) -> Dict[str, Any]:
    aid = str(approval_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 approval_id"}
    now = _now()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM response_approvals WHERE id=?", (aid,)).fetchone()
            if not row:
                return {"ok": False, "error": "审批单不存在"}
            if row["status"] != "pending":
                return {"ok": False, "error": f"状态不可审: {row['status']}"}
            info = dict(row)
            if not approve:
                conn.execute(
                    """UPDATE response_approvals SET status='rejected', reviewed_by=?, review_note=?, updated_at=?
                       WHERE id=? AND status='pending'""",
                    (str(actor or "")[:64], str(note or "")[:500], now, aid),
                )
                conn.commit()
                return {"ok": True, "id": aid, "status": "rejected"}
            # 原子抢占：一张审批单只允许一次下发，防止重复点批准生成多条命令
            cur = conn.execute(
                """UPDATE response_approvals SET status='dispatching', reviewed_by=?, review_note=?, updated_at=?
                   WHERE id=? AND status='pending'""",
                (str(actor or "")[:64], str(note or "")[:500], now, aid),
            )
            conn.commit()
            if cur.rowcount == 0:
                again = conn.execute("SELECT * FROM response_approvals WHERE id=?", (aid,)).fetchone()
                if again and again["status"] == "approved" and again["command_id"]:
                    return {
                        "ok": True, "id": aid, "status": "approved", "deduped": True,
                        "command": {"ok": True, "id": again["command_id"], "deduped": True},
                    }
                return {"ok": False, "error": f"状态不可审: {(again['status'] if again else row['status'])}"}
            try:
                params = json.loads(info.get("params_json") or "{}")
            except Exception:
                params = {}
        finally:
            conn.close()

    # 批准：解析终端后下发（跳过二次审批）
    target_aid = str(info.get("agent_id") or "").strip()
    with _lock:
        conn = _connect()
        try:
            resolved = _resolve_agent_id(conn, target_aid)
        finally:
            conn.close()
    act = str(info.get("action") or "").strip().lower()
    if not resolved:
        # 卸载类：终端已不在册 → 视为批准完成，无需再下发
        if act == "uninstall_agent":
            with _lock:
                conn = _connect()
                try:
                    conn.execute(
                        """UPDATE response_approvals SET status='approved', reviewed_by=?, review_note=?,
                                  command_id=?, updated_at=? WHERE id=?""",
                        (
                            str(actor or "")[:64],
                            (str(note or "") or "终端已不在册，无需下发")[:500],
                            "",
                            now,
                            aid,
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
            return {
                "ok": True, "id": aid, "status": "approved",
                "skipped_dispatch": True, "error": "",
                "message": "终端已不在册，审批已关闭（无需下发卸载指令）",
            }
        with _lock:
            conn = _connect()
            try:
                conn.execute(
                    """UPDATE response_approvals SET status='pending', updated_at=? WHERE id=? AND status='dispatching'""",
                    (now, aid),
                )
                conn.commit()
            finally:
                conn.close()
        return {
            "ok": False,
            "error": f"终端不存在或已卸载（agent_id={target_aid[:16]}…），无法下发。可驳回此单或确认终端仍在「主机」列表中。",
        }

    # 审批单 id 作为幂等键：重复批准复用同一条命令
    out = agent_edr.create_command(
        resolved, act, params,
        actor=actor or info.get("requested_by") or "",
        idempotency_key=f"approval:{aid}",
    )
    if not out.get("ok"):
        with _lock:
            conn = _connect()
            try:
                conn.execute(
                    """UPDATE response_approvals SET status=?, updated_at=? WHERE id=? AND status='dispatching'""",
                    ("verification_required" if out.get("verification_required") else "pending", now, aid),
                )
                conn.commit()
            finally:
                conn.close()
        return out
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """UPDATE response_approvals SET status='approved', reviewed_by=?, review_note=?,
                          command_id=?, updated_at=? WHERE id=?""",
                (str(actor or "")[:64], str(note or "")[:500], out.get("id") or "", now, aid),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "id": aid, "status": "approved", "command": out}


# 已完成处置 → 建议回滚动作
_ROLLBACK_MAP = {
    "isolate_network": ("unisolate_network", {}),
    "quarantine_file": ("restore_file", None),  # params 从原指令带 original/dest
    "disable_service": ("enable_service", None),
    "disable_task": ("enable_task", None),  # Agent 侧若无 enable_task 则仅作建议
    "reg_delete_value": ("reg_rollback", None),
    "reg_set_value": ("reg_rollback", None),
    "clear_persistence": ("reg_rollback", None),
}


def suggest_rollback(command_id: str) -> Dict[str, Any]:
    agent_edr.ensure()
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            row = conn.execute(
                "SELECT id, agent_id, action, params_json, status, result_json FROM agent_commands WHERE id=?",
                (str(command_id or "").strip(),),
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return {"ok": False, "error": "指令不存在"}
    act = str(row["action"] or "")
    mapped = _ROLLBACK_MAP.get(act)
    if not mapped:
        return {"ok": False, "error": f"动作 {act} 无内置回滚映射"}
    rb_act, rb_params = mapped
    try:
        orig = json.loads(row["params_json"] or "{}")
    except Exception:
        orig = {}
    try:
        result = json.loads(row["result_json"] or "{}")
    except Exception:
        result = {}
    params: Dict[str, Any] = dict(rb_params or {})
    if rb_act == "restore_file":
        params.setdefault("original", orig.get("path") or result.get("original"))
        params.setdefault("dest", result.get("dest"))
    elif rb_act == "enable_service":
        params.setdefault("service", orig.get("service") or orig.get("name"))
        params.setdefault("start", "demand")
    elif rb_act == "reg_rollback":
        params.setdefault("backup_id", (result or {}).get("backup_id"))
        params.setdefault("backup", (result or {}).get("backup"))
    elif rb_act == "enable_task":
        params.setdefault("task", orig.get("task") or orig.get("name"))
    return {
        "ok": True,
        "agent_id": row["agent_id"],
        "from_command": row["id"],
        "from_action": act,
        "rollback_action": rb_act,
        "params": params,
    }


def create_rollback(command_id: str, *, actor: str = "", skip_approval: bool = False) -> Dict[str, Any]:
    sug = suggest_rollback(command_id)
    if not sug.get("ok"):
        return sug
    return request_action(
        sug["agent_id"], sug["rollback_action"], sug.get("params") or {},
        actor=actor, reason=f"rollback of {command_id}", skip_approval=skip_approval,
    )
