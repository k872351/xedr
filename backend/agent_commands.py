# -*- coding: utf-8 -*-
"""Agent 远程处置指令：创建、轮询、回执、列表。从 agent_edr 拆出以便多实例演进。"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Optional

from . import agent_protocol
from .agent_edr import _audit, _connect, _lock, _now, ensure

# 命令租约：Agent 取走后在 lease 内必须 ack，否则重投；超过 max_attempts 或 deadline 终止。
COMMAND_LEASE_DEFAULT_SEC = 60
COMMAND_LEASE_SEC = {
    "scan_memory": 180, "upgrade": 300, "rollback_upgrade": 300, "refresh_modules": 90,
    "pull_file": 180, "collect_diagnostics": 180,
    "run_cmd": 120, "reg_read": 90, "fs_list": 90, "fs_stat": 60, "fs_read": 120, "fs_volumes": 60,
    "shell_open": 60, "shell_write": 45, "shell_poll": 45, "shell_close": 30,
}
COMMAND_MAX_ATTEMPTS = 3
COMMAND_TTL_DEFAULT_SEC = 1800
COMMAND_TTL_SEC = {
    "upgrade": 86400, "rollback_upgrade": 86400, "uninstall_agent": 86400,
    "unisolate_network": 86400, "isolate_network": 3600,
}
ACTIONS = (
    "kill_process",
    "quarantine_file",
    "isolate_network",
    "unisolate_network",
    "refresh_modules",
    "upgrade",
    "scan_memory",
    "restore_file",
    "rollback_upgrade",
    "cancel_upgrade",
    "uninstall_agent",
    "collect_diagnostics",
    "pull_file",
    "disable_service",
    "enable_service",
    "stop_service",
    "delete_task",
    "delete_scheduled_task",
    "disable_task",
    "disable_scheduled_task",
    "enable_task",
    "enable_scheduled_task",
    "reg_delete_value",
    "reg_set_value",
    "reg_rollback",
    "clear_persistence",
    "recheck_persistence",
    "verify_response",
    "reg_read",
    "fs_list",
    "fs_stat",
    "fs_read",
    "fs_volumes",
    "live_query",
    "run_cmd",
    "shell_open",
    "shell_write",
    "shell_poll",
    "shell_close",
)

# 高危处置：默认进入审批队列，批准后才下发 Agent
HIGH_RISK_ACTIONS = frozenset({
    "kill_process", "quarantine_file", "isolate_network", "uninstall_agent",
    "disable_service", "stop_service", "delete_task", "delete_scheduled_task",
    "clear_persistence", "reg_delete_value", "reg_set_value",
})

_REMOTE_OPS_READ = frozenset({"reg_read", "fs_list", "fs_stat", "fs_read", "fs_volumes", "live_query", "shell_poll"})
_REMOTE_OPS_SHELL = frozenset({"shell_open", "shell_write", "shell_poll", "shell_close"})
_REMOTE_OPS_ALL = _REMOTE_OPS_READ | frozenset({"run_cmd"}) | _REMOTE_OPS_SHELL


def _remote_ops_policy_cfg() -> Dict[str, Any]:
    try:
        from .agent_policy_store import get_policy
        pol = get_policy("global").get("policy") or {}
    except Exception:
        pol = {}
    ro = pol.get("remote_ops") if isinstance(pol.get("remote_ops"), dict) else {}
    enabled = bool(ro.get("enabled", pol.get("remote_ops_enabled", False)))
    return {
        "enabled": enabled,
        "read_only": bool(ro.get("read_only", True)),
        "run_cmd_enabled": bool(ro.get("run_cmd_enabled", False)),
        "shell_enabled": bool(ro.get("shell_enabled", False)),
        "run_cmd_whitelist": list(ro.get("run_cmd_whitelist") or []),
    }


def _validate_remote_ops_command(action: str, params: Dict[str, Any]) -> str:
    """按策略校验远程运维指令；默认允许只读，Shell/run_cmd 需显式开启。"""
    act = str(action or "").strip().lower()
    if act not in _REMOTE_OPS_ALL:
        return ""
    cfg = _remote_ops_policy_cfg()
    if not cfg.get("enabled"):
        return "远程运维未开启（策略 remote_ops.enabled）"
    if act in ("run_cmd",) and (cfg.get("read_only") or not cfg.get("run_cmd_enabled")):
        return "run_cmd 未开启或处于只读模式"
    if act in _REMOTE_OPS_SHELL - {"shell_poll"} and not cfg.get("shell_enabled"):
        return "交互 Shell 未开启（策略 remote_ops.shell_enabled）"
    if act == "run_cmd":
        cmdline = str((params or {}).get("command") or (params or {}).get("cmdline") or "").strip().lower()
        wl = [str(x).strip().lower() for x in (cfg.get("run_cmd_whitelist") or []) if str(x).strip()]
        if wl and cmdline and not any(cmdline.startswith(x) for x in wl):
            return "命令不在 run_cmd 白名单内"
    return ""


def create_command(
    agent_id: str,
    action: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    actor: str = "",
    idempotency_key: str = "",
    ttl_sec: int = 0,
) -> Dict[str, Any]:
    ensure()
    aid = str(agent_id or "").strip()
    act = str(action or "").strip().lower()
    if not aid or act not in ACTIONS:
        return {"ok": False, "error": "agent_id 或 action 无效"}
    pol_err = _validate_remote_ops_command(act, params or {})
    if pol_err:
        return {"ok": False, "error": pol_err}
    cid = uuid.uuid4().hex
    now = _now()
    blob = json.dumps(params or {}, ensure_ascii=False)
    idem = str(idempotency_key or "").strip()[:96]
    ttl = int(ttl_sec or 0) or COMMAND_TTL_SEC.get(act, COMMAND_TTL_DEFAULT_SEC)
    # 截止时间统一 UTC（带 Z），避免跨时区误判
    deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl))
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT agent_id, os_family FROM agents WHERE agent_id=?", (aid,)).fetchone()
            if not row:
                return {"ok": False, "error": "终端不存在"}
            if str(row["os_family"] or "").strip().lower() == "linux" and act in {
                "upgrade", "rollback_upgrade", "scan_memory",
            }:
                return {"ok": False, "error": "此 Linux Agent 暂不支持该远程操作，请使用已验证的本地部署流程"}
            if idem:
                if idem.startswith("approval:"):
                    previous = conn.execute("SELECT id, agent_id, action, status FROM agent_commands WHERE idempotency_key=? LIMIT 1", (idem,)).fetchone()
                    if previous:
                        if previous["agent_id"] != aid or previous["action"] != act:
                            return {"ok": False, "verification_required": True, "error": "approval command already belongs to a different target or action"}
                        return {"ok": False, "verification_required": True, "error": "approval already has a command; verify its recorded outcome before any further action"}
                # 同一幂等键且未失败/过期的命令直接复用，避免前端重复点击重复下发
                dup = conn.execute(
                    """SELECT id, status FROM agent_commands
                       WHERE agent_id=? AND idempotency_key=? AND status NOT IN ('failed','expired')
                       ORDER BY created_at DESC LIMIT 1""",
                    (aid, idem),
                ).fetchone()
                if dup:
                    return {"ok": True, "id": dup["id"], "action": act, "status": dup["status"], "deduped": True}
            conn.execute(
                """INSERT INTO agent_commands(id, agent_id, action, params_json, status, created_by, created_at, updated_at,
                                              deadline, idempotency_key, max_attempts, attempts, lease_until)
                   VALUES(?,?,?,?, 'pending', ?, ?, ?, ?, ?, ?, 0, '')""",
                (cid, aid, act, blob, actor[:64], now, now, deadline, idem, COMMAND_MAX_ATTEMPTS),
            )
            conn.commit()
        finally:
            conn.close()
    _audit(f"command:{act}", agent_id=aid, detail=blob, actor=actor)
    agent_protocol.bump_live("command", agent_id=aid, command_id=cid)
    try:
        from . import agent_store
        agent_store.write_command({
            "id": cid, "agent_id": aid, "action": act, "params_json": blob,
            "status": "pending", "created_by": actor[:64], "created_at": now, "updated_at": now,
            "deadline": deadline, "idempotency_key": idem,
        })
    except Exception:
        pass
    return {"ok": True, "id": cid, "action": act, "status": "pending"}


def poll_commands(agent_id: str, *, limit: int = 10) -> Dict[str, Any]:
    ensure()
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    now = _now()
    with _lock:
        conn = _connect()
        try:
            # 只有声明 command.lease 的新 Agent 才会重投（它有本地回执去重）；旧 Agent 保持至多一次
            crow = conn.execute("SELECT capabilities_json FROM agents WHERE agent_id=?", (aid,)).fetchone()
            try:
                lease_ok = "command.lease" in json.loads((crow["capabilities_json"] if crow else "") or "[]")
            except Exception:
                lease_ok = False
            # deadline 统一 UTC（…Z）；与本地 now 混比会误判，故用 UTC 墙钟比较
            now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            conn.execute(
                """UPDATE agent_commands SET status='expired', updated_at=?,
                          result_json=COALESCE(NULLIF(result_json,''), '{"error":"deadline exceeded"}')
                   WHERE agent_id=? AND status IN ('pending','sent') AND deadline<>'' AND deadline<?""",
                (now, aid, now_utc),
            )
            conn.execute(
                """UPDATE agent_commands SET status='failed', updated_at=?,
                          result_json='{"error":"lease exhausted: agent never acked"}'
                   WHERE agent_id=? AND status='sent' AND lease_until<>'' AND lease_until<? AND attempts>=max_attempts
                     AND ?=1""",
                (now, aid, now, 1 if lease_ok else 0),
            )
            rows = conn.execute(
                """SELECT id, action, params_json, created_at, attempts, deadline FROM agent_commands
                   WHERE agent_id=? AND (status='pending'
                      OR (status='sent' AND lease_until<>'' AND lease_until<? AND attempts<max_attempts AND ?=1))
                   ORDER BY created_at ASC LIMIT ?""",
                (aid, now, 1 if lease_ok else 0, max(1, min(int(limit or 10), 50))),
            ).fetchall()
            items = []
            for r in rows:
                try:
                    params = json.loads(r["params_json"] or "{}")
                except Exception:
                    params = {}
                lease_sec = COMMAND_LEASE_SEC.get(r["action"], COMMAND_LEASE_DEFAULT_SEC)
                lease_until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + lease_sec))
                conn.execute(
                    """UPDATE agent_commands SET status='sent', updated_at=?, lease_until=?, attempts=attempts+1
                       WHERE id=?""",
                    (now, lease_until, r["id"]),
                )
                items.append({
                    "id": r["id"],
                    "action": r["action"],
                    "params": params,
                    "created_at": r["created_at"],
                    "attempt": int(r["attempts"] or 0) + 1,
                    "lease_sec": lease_sec,
                    "deadline": r["deadline"] or "",
                })
            conn.commit()
            return {"ok": True, "items": items}
        finally:
            conn.close()


def command_owner(command_id: str) -> str:
    ensure()
    with _lock:
        conn = _connect()
        try:
            r = conn.execute("SELECT agent_id FROM agent_commands WHERE id=?", (str(command_id or ""),)).fetchone()
            return str(r["agent_id"]) if r else ""
        finally:
            conn.close()


def ack_command(
    command_id: str,
    *,
    ok: bool,
    result: Optional[Dict[str, Any]] = None,
    caller_agent_id: str = "",
) -> Dict[str, Any]:
    """回执。caller_agent_id 非空时必须与命令所属 Agent 一致（凭据隔离）；重复回执幂等。"""
    ensure()
    cid = str(command_id or "").strip()
    if not cid:
        return {"ok": False, "error": "缺少 command_id"}
    st = "done" if ok else "failed"
    now = _now()
    store_result = dict(result or {})
    if store_result.get("verification_required") is True:
        st = "verification_required"
        ok = False
    with _lock:
        conn_peek = _connect()
        try:
            peek = conn_peek.execute(
                "SELECT agent_id, action, status, acked_at FROM agent_commands WHERE id=?", (cid,)
            ).fetchone()
        finally:
            conn_peek.close()
    if not peek:
        return {"ok": False, "error": "command not found"}
    if caller_agent_id and peek["agent_id"] != caller_agent_id:
        return {"ok": False, "error": "command does not belong to this agent", "forbidden": True}
    if peek["status"] in ("done", "failed", "verification_required") and peek["acked_at"]:
        return {"ok": True, "id": cid, "status": peek["status"], "duplicate": True}
    if peek["action"] == "collect_diagnostics" and ok:
        try:
            from . import agent_diagnostics as adiag

            slim = adiag.persist_from_command_result(str(peek["agent_id"]), cid, store_result)
            if isinstance(slim, dict):
                store_result = slim
        except Exception as e:
            print("[diagnostics] persist:", e)
            if "content_base64" in store_result:
                store_result = {k: v for k, v in store_result.items() if k != "content_base64"}
                store_result["stored"] = False
                store_result["error"] = str(e)[:200]
    if peek["action"] == "pull_file" and ok:
        try:
            from . import agent_samples as asamp

            slim = asamp.persist_from_command_result(str(peek["agent_id"]), cid, store_result)
            if isinstance(slim, dict):
                store_result = slim
        except Exception as e:
            print("[samples] persist:", e)
            if "content_base64" in store_result:
                store_result = {k: v for k, v in store_result.items() if k != "content_base64"}
                store_result["stored"] = False
                store_result["error"] = str(e)[:200]
    action_name = str(peek["action"] if peek else "")
    max_blob = 512_000 if action_name in (
        "live_query", "fs_list", "fs_read", "reg_read", "run_cmd",
        "shell_open", "shell_write", "shell_poll", "shell_close",
    ) else 32_000
    blob = json.dumps(store_result, ensure_ascii=False)[:max_blob]
    if len(json.dumps(store_result, ensure_ascii=False)) > max_blob and isinstance(store_result, dict):
        slim = dict(store_result)
        if isinstance(slim.get("rows"), list):
            slim["rows"] = slim["rows"][:80]
            slim["truncated"] = True
        blob = json.dumps(slim, ensure_ascii=False)[:max_blob]
    with _lock:
        conn = _connect()
        try:
            cur_row = conn.execute(
                "SELECT agent_id, status, acked_at FROM agent_commands WHERE id=?", (cid,)
            ).fetchone()
            if not cur_row:
                return {"ok": False, "error": "指令不存在"}
            if caller_agent_id and cur_row["agent_id"] != caller_agent_id:
                return {"ok": False, "error": "指令不属于该 Agent", "forbidden": True}
            if cur_row["status"] in ("done", "failed", "verification_required") and cur_row["acked_at"]:
                return {"ok": True, "id": cid, "status": cur_row["status"], "duplicate": True}
            conn.execute(
                """UPDATE agent_commands SET status=?, result_json=?, updated_at=?, acked_at=?
                   WHERE id=?""",
                (st, blob, now, now, cid),
            )
            conn.commit()
            row = conn.execute("SELECT agent_id, action FROM agent_commands WHERE id=?", (cid,)).fetchone()
        finally:
            conn.close()
    if row:
        _audit(f"ack:{row['action']}:{st}", agent_id=row["agent_id"], detail=blob)
        agent_protocol.bump_live("command_ack", agent_id=row["agent_id"], command_id=cid, status=st)
        if row["action"] == "scan_memory" and ok:
            _memscan_to_events(row["agent_id"], result or {})
        try:
            from . import agent_store
            agent_store.write_command({
                "id": cid, "agent_id": row["agent_id"], "action": row["action"],
                "status": st, "result_json": blob, "updated_at": now, "acked_at": now,
            })
        except Exception:
            pass
    return {"ok": True, "id": cid, "status": st}


def _memscan_to_events(agent_id: str, result: Dict[str, Any]) -> int:
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    n = 0
    for f in findings[:20]:
        if not isinstance(f, dict):
            continue
        mod = "memory"
        if f.get("building_block"):
            mod = "building_block"
        detail = {
            "scan_mode": result.get("mode"),
            "yara_engine": result.get("yara_engine"),
            "rules_rev": result.get("rules_rev"),
            "engine": f.get("engine"),
            "rule_id": f.get("rule_id"),
            "rule_name": f.get("rule_name"),
            "type": f.get("type"),
            "pid": f.get("pid"),
            "name": f.get("name"),
            "address": f.get("address"),
            "matched_string": f.get("matched_string"),
            "matched_strings": f.get("matched_strings"),
            "mitre": f.get("mitre"),
            "building_block": bool(f.get("building_block")),
            "investigation": "打开进程树核对签名与路径；YARA 命中建议对该 PID 做隔离或内存转储复核。",
        }
        ev = agent_protocol.report_event({
            "agent_id": agent_id,
            "module": mod,
            "severity": str(f.get("severity") or "high"),
            "title": str(f.get("summary") or f.get("title") or f"内存可疑：{f.get('type')}")[:200],
            "detail": detail,
            "building_block": bool(f.get("building_block")),
        })
        if ev.get("ok") and not ev.get("deduped") and not ev.get("suppressed"):
            n += 1
    return n


def list_commands(agent_id: str = "", *, limit: int = 50) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            if agent_id:
                rows = conn.execute(
                    "SELECT * FROM agent_commands WHERE agent_id=? ORDER BY created_at DESC LIMIT ?",
                    (agent_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM agent_commands ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            items = [dict(r) for r in rows]
            return {"ok": True, "items": items}
        finally:
            conn.close()
