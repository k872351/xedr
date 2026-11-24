# -*- coding: utf-8 -*-
"""EDR 扩展：远程处置指令、审计、时间线、策略、狩猎。"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import agent_protocol, config, timeline_filter
from .timeline_value_format import _parse_detail, _timeline_int, _parse_ts_any
from .attack_story_format import _ATTCK_TACTICS, _story_process_name, _build_story_lanes
from .ioc_candidate_parser import _extract_ioc_candidates
from .agent_alert_detail import _timeline_rule_hit_detail, _timeline_rule_hit_module

from .agent_alert_promotion import _promote_sensor_alerts

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_commands (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    params_json TEXT DEFAULT '{}',
    status TEXT DEFAULT 'pending',
    result_json TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT '',
    acked_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cmd_agent_status ON agent_commands(agent_id, status);

CREATE TABLE IF NOT EXISTS agent_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT DEFAULT '',
    action TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    actor TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON agent_audit(created_at);

CREATE TABLE IF NOT EXISTS agent_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    etype TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    detail_json TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    ts TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tl_agent_ts ON agent_timeline(agent_id, ts);
CREATE INDEX IF NOT EXISTS idx_tl_etype ON agent_timeline(etype);
CREATE INDEX IF NOT EXISTS idx_tl_ts ON agent_timeline(ts);
CREATE INDEX IF NOT EXISTS idx_tl_sev_ts ON agent_timeline(severity, ts);

CREATE TABLE IF NOT EXISTS agent_policy (
    scope TEXT PRIMARY KEY,
    policy_json TEXT DEFAULT '{}',
    rev INTEGER DEFAULT 1,
    updated_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_groups (
    id TEXT PRIMARY KEY,
    name TEXT DEFAULT '',
    agent_ids_json TEXT DEFAULT '[]',
    note TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_whitelist (
    id TEXT PRIMARY KEY,
    kind TEXT DEFAULT '',
    value TEXT DEFAULT '',
    note TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_ioc (
    id TEXT PRIMARY KEY,
    ioc_type TEXT DEFAULT '',
    value TEXT DEFAULT '',
    severity TEXT DEFAULT 'high',
    note TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    hits INTEGER DEFAULT 0,
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON agent_ioc(ioc_type, value);

CREATE TABLE IF NOT EXISTS agent_tags (
    agent_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY(agent_id, tag)
);

CREATE TABLE IF NOT EXISTS agent_seq_rules (
    id TEXT PRIMARY KEY,
    title TEXT DEFAULT '',
    severity TEXT DEFAULT 'high',
    window_sec INTEGER DEFAULT 120,
    steps_json TEXT DEFAULT '[]',
    enabled INTEGER DEFAULT 1,
    note TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_upgrade_packages (
    id TEXT PRIMARY KEY,
    version TEXT DEFAULT '',
    filename TEXT DEFAULT '',
    sha256 TEXT DEFAULT '',
    size INTEGER DEFAULT 0,
    note TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    sig_ed25519 TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_upgrade_created ON agent_upgrade_packages(created_at);
"""

_lock = threading.RLock()

# 命令常量与 create/poll/ack/list 已拆至 agent_commands（文末 re-export）

# ATT&CK 战术顺序（看板列）

# 粗粒度：模块 / 标题关键字 → 技术
_ATTCK_HINTS = [
    (["落地文件扫描", "file_scan"], "T1204.002", "execution"),
    (["smb共享", "smb高危", "win_smb", "admin$", "ipc$"], "T1021.002", "lateral_movement"),
    (["横向移动工具", "lateral_tool", "psexec", "winrm", "schtasks"], "T1021.002", "lateral_movement"),
    (["凭据访问", "credential_access", "lsass"], "T1003.001", "credential_access"),
    (["日志被清空", "win_audit_clear"], "T1070.001", "defense_evasion"),
    (["账号创建", "win_account_create"], "T1136.001", "persistence"),
    (["加入本地组", "加入组", "加入通用组", "win_group_add"], "T1098", "persistence"),
    (["登录失败", "win_logon_fail"], "T1110", "credential_access"),
    (["显式凭据", "win_explicit_logon"], "T1078", "defense_evasion"),
    (["lsass"], "T1003.001", "credential_access"),
    (["进程打开", "process_access"], "T1055", "defense_evasion"),
    (["疑似dga", "dns_nx_burst", "nxdomain"], "T1568.002", "command_and_control"),
    (["情报 ioc"], "T1071", "command_and_control"),
    (["powershell 脚本块", "win_ps_scriptblock", "win_ps_module"], "T1059.001", "execution"),
    (["服务安装", "win_service_install"], "T1543.003", "persistence"),
    (["计划任务创建", "win_task_create"], "T1053.005", "persistence"),
    (["defender排除", "defender\\", "exclusions", "disableantispyware", "disablerealtimemonitoring"], "T1562.001", "defense_evasion"),
    (["持久化新增", "持久化修改", "winlogon", "appinit", "image file execution", "ifeo"], "T1547.001", "persistence"),
    (["远程线程", "remote_thread"], "T1055", "defense_evasion"),
    (["拦截对 agent", "protect_block"], "T1562.001", "defense_evasion"),
    (["dll 加载", "image_load", "未签名 dll", "目录 dll", "系统目录未签名"], "T1574.002", "defense_evasion"),
    (["fim新增", "fim修改", "fim删除", "fim_add", "fim_modify", "文件完整性"], "T1036.005", "defense_evasion"),
    (["powershell", "pwsh", "cmd.exe", "wscript", "cscript", "编码执行"], "T1059", "execution"),
    (["临时目录", "\\temp\\", "\\appdata\\"], "T1105", "command_and_control"),
    (["计划任务创建", "计划任务更新", "schtasks", "win_task"], "T1053.005", "persistence"),
    (["服务安装", "win_service_install", "服务启动类型"], "T1543.003", "persistence"),
    (["启动项", "run\\\\", "startup"], "T1547.001", "persistence"),
    (["网络隔离", "firewall", "etw外联", "network_connect"], "T1071", "command_and_control"),
    (["ioc 命中", "ioc命中", "file_hash", "哈希"], "T1204", "execution"),
    (["行为序列", "office", "winword", "excel"], "T1566", "initial_access"),
    (["隔离文件", "quarantine", "落地"], "T1105", "command_and_control"),
    (["凭证", "lsass", "mimikatz", "password"], "T1003", "credential_access"),
    (["横向", "psexec", "wmi", "smb"], "T1021", "lateral_movement"),
    (["注册表", "reg ", "registry"], "T1112", "defense_evasion"),
]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _db() -> Path:
    return agent_protocol.db_path()


def _connect() -> sqlite3.Connection:
    amb = agent_protocol.ambient_conn()
    if amb is not None:  # v2 批量事务内共享同一连接
        return amb  # type: ignore[return-value]
    conn = sqlite3.connect(str(_db()), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    agent_protocol.migrate(conn)
    return conn


_ensured = False


def ensure() -> None:
    global _ensured
    with _lock:
        conn = _connect()
        # 默认全局策略（避免 get_policy→ensure 递归）
        row = conn.execute("SELECT scope FROM agent_policy WHERE scope='global'").fetchone()
        if not row:
            conn.execute(
                "INSERT INTO agent_policy(scope, policy_json, rev, updated_at) VALUES(?,?,1,?)",
                ("global", json.dumps(_DEFAULT_POLICY, ensure_ascii=False), _now()),
            )
            conn.commit()
        conn.close()
        first = not _ensured
        _ensured = True
    if first:
        try:
            from . import response_approval
            response_approval.recover_stuck_approvals()
        except Exception:
            pass
        try:
            from . import policy_sign
            policy_sign.ensure_policy_keypair()
        except Exception:
            pass


def _audit(action: str, *, agent_id: str = "", detail: str = "", actor: str = "") -> None:
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO agent_audit(agent_id, action, detail, actor, created_at) VALUES(?,?,?,?,?)",
                (agent_id, action, detail[:2000], actor[:64], _now()),
            )
            conn.commit()
        finally:
            conn.close()


def purge_agent_data(agent_id: str) -> Dict[str, Any]:
    """删除终端后清理告警、时间线、指令、标签等残留。"""
    ensure()
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    with _lock:
        conn = _connect()
        try:
            n_ev = 0
            try:
                n_ev = conn.execute("DELETE FROM agent_events WHERE agent_id=?", (aid,)).rowcount
            except Exception:
                pass
            n_tl = conn.execute("DELETE FROM agent_timeline WHERE agent_id=?", (aid,)).rowcount
            n_cmd = conn.execute("DELETE FROM agent_commands WHERE agent_id=?", (aid,)).rowcount
            n_tag = 0
            try:
                n_tag = conn.execute("DELETE FROM agent_tags WHERE agent_id=?", (aid,)).rowcount
            except Exception:
                pass
            conn.commit()
        finally:
            conn.close()
    if n_ev:
        try:
            from . import agent_protocol
            agent_protocol.bump_live("event")
        except Exception:
            pass
    return {"ok": True, "events": n_ev, "timeline": n_tl, "commands": n_cmd, "tags": n_tag}


_ORPHAN_TABLES = (
    "agent_events", "agent_timeline", "agent_snapshots", "agent_commands",
    "agent_tags", "agent_receipts", "agent_streams",
)


def purge_orphan_agent_data() -> Dict[str, int]:
    """清理已删除终端残留的告警 / 时间线等（旧版本删除不彻底或删除后仍有回传）。"""
    ensure()
    out: Dict[str, int] = {}
    with _lock:
        conn = _connect()
        try:
            for tbl in _ORPHAN_TABLES:
                try:
                    cur = conn.execute(
                        f"DELETE FROM {tbl} WHERE agent_id NOT IN (SELECT agent_id FROM agents)"
                    )
                except sqlite3.Error:
                    continue
                if cur.rowcount:
                    out[tbl] = int(cur.rowcount)
            conn.commit()
        finally:
            conn.close()
    if out.get("agent_events"):
        agent_protocol.bump_live("event")
    return out


# create_command / poll_commands / ack_command / list_commands → agent_commands

def _is_agent_self_noise(etype: str, summary: str, detail: Dict[str, Any]) -> bool:
    """过滤端侧噪声：Agent 自写临时脚本 + Windows PowerShell 策略探针。"""
    detail = detail if isinstance(detail, dict) else {}
    parts = [
        str(etype or ""),
        str(summary or ""),
        str(detail.get("path") or ""),
        str(detail.get("name") or ""),
        str(detail.get("FileName") or ""),
        str(detail.get("image") or ""),
        str(detail.get("TargetFilename") or ""),
        str(detail.get("module") or ""),
        str(detail.get("module_name") or ""),
    ]
    blob = " ".join(parts).lower()
    for pre in ("fa-ps-", "fa-etw-", "fa-wevt-", "fa-watch-", "fa-upg-"):
        if pre in blob:
            return True
    # Windows Constrained Language / 执行策略探针（任意扩展中间段：.gfz.ps1 / .xla.ps1）
    if "psscriptpolicytest" in blob:
        return True
    return False


def purge_agent_self_noise_events() -> Dict[str, Any]:
    """清理历史误报：Agent 自写临时脚本晋升成的威胁事件 / 时间线。"""
    ensure()
    patterns = ("%fa-ps-%", "%fa-etw-%", "%fa-wevt-%", "%fa-watch-%", "%fa-upg-%", "%psscriptpolicytest%")
    n_ev = n_tl = 0
    with _lock:
        conn = _connect()
        try:
            for pat in patterns:
                cur = conn.execute(
                    "DELETE FROM agent_events WHERE lower(title) LIKE ? OR lower(detail) LIKE ?",
                    (pat, pat),
                )
                n_ev += int(cur.rowcount or 0)
                cur = conn.execute(
                    "DELETE FROM agent_timeline WHERE lower(summary) LIKE ? OR lower(detail_json) LIKE ?",
                    (pat, pat),
                )
                n_tl += int(cur.rowcount or 0)
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "events_deleted": n_ev, "timeline_deleted": n_tl}


def _apply_process_cmd_patch(
    conn: sqlite3.Connection,
    agent_id: str,
    detail: Dict[str, Any],
    ts: str,
) -> None:
    """Agent 迟到命令行：更新进程实体与近期时间线 detail。"""
    cmd = str(detail.get("command_line") or "").strip()
    if not cmd:
        return
    eid = str(detail.get("entity_id") or "").strip()[:64]
    pid = detail.get("pid")
    now = _now()
    if eid:
        conn.execute(
            """UPDATE agent_processes SET command_line=?, last_seen=?
               WHERE agent_id=? AND entity_id=? AND (command_line IS NULL OR command_line='')""",
            (cmd[:2000], now, agent_id, eid),
        )
    elif pid is not None:
        row = conn.execute(
            """SELECT entity_id FROM agent_processes WHERE agent_id=? AND pid=?
               AND (command_line IS NULL OR command_line='') ORDER BY last_seen DESC LIMIT 1""",
            (agent_id, int(pid)),
        ).fetchone()
        if row:
            conn.execute(
                """UPDATE agent_processes SET command_line=?, last_seen=?
                   WHERE agent_id=? AND entity_id=?""",
                (cmd[:2000], now, agent_id, str(row["entity_id"])),
            )
    rows = conn.execute(
        """SELECT id, detail_json FROM agent_timeline
           WHERE agent_id=? AND etype LIKE 'process_create%' AND ts >= datetime('now', '-2 hours')
           ORDER BY id DESC LIMIT 40""",
        (agent_id,),
    ).fetchall()
    for row in rows:
        try:
            dj = json.loads(row["detail_json"] or "{}")
        except Exception:
            continue
        if not isinstance(dj, dict):
            continue
        if pid is not None and int(dj.get("pid") or 0) != int(pid):
            continue
        if eid and str(dj.get("entity_id") or "") != eid:
            continue
        if str(dj.get("command_line") or "").strip():
            continue
        dj["command_line"] = cmd[:2000]
        dj["cmd_backfill"] = True
        conn.execute(
            "UPDATE agent_timeline SET detail_json=? WHERE id=?",
            (agent_protocol.fit_detail(dj), int(row["id"])),
        )






def clean_timeline_history() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            stats = timeline_filter.clean_history(conn)
        finally:
            conn.close()
    return {"ok": True, **stats}


_THREAT_ETYPES = {
    "remote_thread_kernel", "protect_block_kernel",
}
_RISK_ETYPES = {
    "file_create", "file_write", "file_write_etw",
    "image_load_etw", "image_load_kernel",
    "network_connect", "network_connect_etw", "http_request_etw", "beacon_like",
    "driver_load_kernel",
}
_SURFACE_ETYPES = {"protect_block_kernel", "sensor_status", "etw_status"}


def _log_nature(sev: str, etype: str, summary: str = "") -> str:
    """威胁 / 风险 / 细微 / 攻击面。"""
    et = str(etype or "")
    blob = f"{et} {summary or ''}".lower()
    if et in _SURFACE_ETYPES or "隔离" in blob or "quarantine" in blob:
        if et in _THREAT_ETYPES or str(sev).lower() in ("high", "critical"):
            return "threat"
        return "surface"
    if et in _THREAT_ETYPES or str(sev).lower() in ("high", "critical"):
        return "threat"
    if et in _RISK_ETYPES or str(sev).lower() == "medium" or any(
        k in blob for k in ("可疑", "临时", "public", "inject", "bypass", "dll", "文件创建", "落地")
    ):
        return "risk"
    return "minor"


def _inv_chain_nodes(det: Dict[str, Any]) -> List[Dict[str, Any]]:
    """PTM/EVM 等聚合事件：从 trigger/chain 抽出节点证据。"""
    out: List[Dict[str, Any]] = []
    if not isinstance(det, dict):
        return out
    trig = det.get("trigger")
    if isinstance(trig, dict):
        out.append(trig)
    chain = det.get("chain")
    if isinstance(chain, list):
        for c in reversed(chain):
            if isinstance(c, dict):
                out.append(c)
    return out


# 本产品中几乎只由 Sysmon 产出的 etype（无 source 字段时也可认）
_SYSMON_MARKER_ETYPES = frozenset({
    "process_create_sysmon", "process_exit_sysmon", "image_load_sysmon",
    "driver_load_sysmon",
    "file_create", "file_delete", "file_delete_detected", "file_stream_create",
    "pipe_created", "process_tampering",
    "registry_create", "registry_rename",
})

_INV_TOPIC_LABELS = {
    "file_create": "文件创建",
    "service": "服务",
    "task": "计划任务",
    "startup": "启动项",
}


def _inv_topics(etype: str, det: Dict[str, Any], summary: str = "", *, _depth: int = 0) -> List[str]:
    """调查页固定主题：文件创建 / 服务 / 计划任务 / 启动项。"""
    et = str(etype or "").lower()
    det = det if isinstance(det, dict) else {}
    path = str(
        det.get("path")
        or det.get("reg_key")
        or det.get("image")
        or det.get("target_path")
        or det.get("task")
        or ""
    ).lower()
    topic_hint = str(det.get("topic") or "").lower()
    out: List[str] = []

    def add(t: str) -> None:
        if t and t not in out:
            out.append(t)

    if topic_hint in _INV_TOPIC_LABELS:
        add(topic_hint)

    if et in ("file_create", "file_write", "file_write_etw", "file_stream_create") or et.startswith("fim_"):
        add("file_create")
    if et.startswith("win_service") or (
        "\\services\\" in path
        and any(x in path for x in ("\\imagepath", "\\servicedll", "\\start", "\\servicemanifest"))
    ):
        add("service")
    if et.startswith("win_task") or "\\tasks\\" in path or "\\windows\\tasks" in path:
        add("task")
    if (
        et.startswith("persist_")
        or et.startswith("wmi_persist")
        or "currentversion\\run" in path
        or "\\runonce" in path
        or "\\startup\\" in path
        or "\\start menu\\" in path
        or "shell folders\\startup" in path
        or "\\winlogon" in path
        or "\\appinit_dlls" in path
        or "image file execution options" in path
    ):
        add("startup")

    if _depth < 1:
        for n in _inv_chain_nodes(det):
            for t in _inv_topics(str(n.get("etype") or ""), n, str(n.get("summary") or ""), _depth=_depth + 1):
                add(t)
    return out


def _inv_match_topic(topic: str, etype: str, det: Dict[str, Any], summary: str = "") -> bool:
    t = str(topic or "").strip().lower()
    if not t:
        return True
    return t in _inv_topics(etype, det, summary)


def _inv_involves_sysmon(etype: str, det: Dict[str, Any], summary: str = "") -> bool:
    et = str(etype or "").lower()
    if "sysmon" in et or et in _SYSMON_MARKER_ETYPES:
        return True
    if str((det or {}).get("source") or "").lower() == "sysmon":
        return True
    ch = str((det or {}).get("channel") or "").lower()
    if "sysmon" in ch:
        return True
    if "sysmon" in str(summary or "").lower():
        return True
    for n in _inv_chain_nodes(det or {}):
        net = str(n.get("etype") or "").lower()
        if "sysmon" in net or net in _SYSMON_MARKER_ETYPES:
            return True
        if str(n.get("source") or "").lower() == "sysmon":
            return True
        if "sysmon" in str(n.get("channel") or "").lower():
            return True
    return False


def _inv_list_fields(etype: str, det: Dict[str, Any], summary: str = "") -> Dict[str, Any]:
    """日志调查列表瘦身字段：补进程路径，并标出 Sysmon / 源 etype。"""
    det = det if isinstance(det, dict) else {}
    name = det.get("name") or det.get("process_name")
    path = det.get("path") or det.get("image") or det.get("target_path")
    cmd = det.get("command_line")
    pid = det.get("pid")
    source_etype = str(det.get("source_etype") or "") or None
    for n in _inv_chain_nodes(det):
        if not source_etype:
            se = str(n.get("etype") or "").strip()
            if se:
                source_etype = se
        if not name:
            name = n.get("name") or n.get("process_name")
            if not name:
                img = str(n.get("image") or n.get("path") or "").strip()
                if img and "\\" in img:
                    name = img.rsplit("\\", 1)[-1]
        if not path:
            path = n.get("path") or n.get("image") or n.get("reg_key") or n.get("key") or n.get("target_path")
        if not cmd:
            cmd = n.get("command_line")
        if pid is None and n.get("pid") not in (None, ""):
            pid = n.get("pid")
    src = str(det.get("source") or "")
    is_sys = _inv_involves_sysmon(etype, det, summary)
    if is_sys and not src:
        src = "sysmon"
    return {
        "pid": pid,
        "name": name,
        "path": path,
        "command_line": (str(cmd)[:180] if cmd else None),
        "source": src,
        "source_etype": source_etype,
        "event_id": det.get("event_id"),
        "channel": det.get("channel") or "",
        "is_sysmon": is_sys,
    }


_DROP_FILE_ETYPES = frozenset({
    "file_create", "file_write", "file_write_etw",
    "fim_add", "fim_modify", "fim_rename",
})
_DROP_PROC_ETYPES = frozenset({
    "process_create_etw", "process_create", "process_create_live", "process_create_kernel",
})


def _drop_edge_label(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    if a.get("kind") == "proc" and b.get("kind") == "file":
        return "释放文件"
    if a.get("kind") == "file" and b.get("kind") == "proc":
        return "启动"
    if a.get("kind") == "proc" and b.get("kind") == "proc":
        if b.get("role") == "parent":
            return "父进程"
        if a.get("role") == "parent":
            return "运行"
        return "创建子进程"
    return "关联"


def _proc_step_from_entity(p: Dict[str, Any], *, role: str, is_hit: bool = False) -> Dict[str, Any]:
    eid = str(p.get("entity_id") or "").strip()
    return {
        "id": f"proc-{eid or p.get('pid')}",
        "kind": "proc",
        "role": role,
        "is_hit": is_hit,
        "name": p.get("name") or "?",
        "pid": p.get("pid"),
        "ppid": p.get("ppid"),
        "path": p.get("path") or "",
        "ts": p.get("last_seen") or p.get("first_seen") or "",
        "timeline_id": None,
    }


def _proc_step_from_timeline(row: Dict[str, Any], d: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    path = str(d.get("path") or d.get("image") or "")
    name = d.get("name") or (os.path.basename(path) if path else "") or str(row.get("summary") or "?")[:80]
    pid = d.get("pid") or d.get("process_id")
    return {
        "id": f"tl-proc-{row.get('id')}",
        "kind": "proc",
        "role": role,
        "is_hit": False,
        "name": name,
        "pid": pid,
        "ppid": d.get("ppid"),
        "path": path,
        "command_line": str(d.get("command_line") or d.get("cmdline") or "")[:160],
        "ts": row.get("ts") or "",
        "timeline_id": row.get("id"),
        "etype": row.get("etype") or "",
    }


def _file_step_from_timeline(row: Dict[str, Any], d: Dict[str, Any]) -> Dict[str, Any]:
    path = str(d.get("path") or d.get("file") or "").strip()
    name = os.path.basename(path) if path else str(row.get("summary") or "文件")[:80]
    return {
        "id": f"tl-file-{row.get('id')}",
        "kind": "file",
        "role": "dropped",
        "is_hit": False,
        "name": name,
        "path": path,
        "pid": d.get("pid") or d.get("process_id") or d.get("creator_pid"),
        "ts": row.get("ts") or "",
        "timeline_id": row.get("id"),
        "etype": row.get("etype") or "",
    }




def _hour_bucket(ts: str) -> str:
    s = str(ts or "").replace("T", " ")
    if len(s) >= 13:
        return s[:13] + ":00"
    return s[:10] + " 00:00" if len(s) >= 10 else "unknown"






def hunt(q: str, *, limit: int = 100) -> Dict[str, Any]:
    """跨主机狩猎：时间线 + 快照 JSON + 威胁事件。"""
    ensure()
    query = str(q or "").strip()
    if len(query) < 2:
        return {"ok": False, "error": "请输入至少 2 个字符"}
    limit = max(1, min(int(limit or 100), 300))
    like = f"%{query}%"
    hits: List[Dict[str, Any]] = []
    with _lock:
        conn = _connect()
        try:
            for r in conn.execute(
                """SELECT id, agent_id, hostname, etype, summary, detail_json, severity, ts
                   FROM agent_timeline
                   WHERE summary LIKE ? OR detail_json LIKE ?
                   ORDER BY ts DESC LIMIT ?""",
                (like, like, limit),
            ).fetchall():
                hits.append({
                    "source": "timeline",
                    "id": r["id"],
                    "agent_id": r["agent_id"],
                    "hostname": r["hostname"],
                    "title": r["summary"],
                    "module": r["etype"],
                    "severity": r["severity"],
                    "ts": r["ts"],
                    "snippet": (r["detail_json"] or "")[:240],
                })
            for r in conn.execute(
                """SELECT agent_id, module, collected_at, payload_json FROM agent_snapshots
                   WHERE payload_json LIKE ? LIMIT ?""",
                (like, max(20, limit // 3)),
            ).fetchall():
                hits.append({
                    "source": "snapshot",
                    "agent_id": r["agent_id"],
                    "hostname": agent_protocol._host_of(r["agent_id"]),
                    "title": f"快照命中 · {r['module']}",
                    "module": r["module"],
                    "severity": "info",
                    "ts": r["collected_at"],
                    "snippet": _snip(r["payload_json"] or "", query),
                })
            for r in conn.execute(
                """SELECT id, agent_id, hostname, title, module, severity, detail, updated_at
                   FROM agent_events
                   WHERE title LIKE ? OR detail LIKE ?
                   ORDER BY id DESC LIMIT ?""",
                (like, like, max(20, limit // 3)),
            ).fetchall():
                hits.append({
                    "source": "event",
                    "id": r["id"],
                    "agent_id": r["agent_id"],
                    "hostname": r["hostname"],
                    "title": r["title"],
                    "module": r["module"],
                    "severity": r["severity"],
                    "ts": r["updated_at"],
                    "snippet": (r["detail"] or "")[:240],
                })
        finally:
            conn.close()
    hits = hits[:limit]
    return {"ok": True, "q": query, "count": len(hits), "items": hits}


def _snip(blob: str, q: str, radius: int = 80) -> str:
    low = blob.lower()
    i = low.find(q.lower())
    if i < 0:
        return blob[:160]
    a = max(0, i - radius)
    b = min(len(blob), i + len(q) + radius)
    return ("…" if a else "") + blob[a:b] + ("…" if b < len(blob) else "")


_DEFAULT_POLICY = {
    "intervals_sec": dict(agent_protocol.MODULE_INTERVAL_SEC),
    "heartbeat_sec": 3,
    "response_enabled": True,
    "response_approval_required": True,
    "timeline_process": True,
    "timeline_file": True,
    "timeline_network": True,
    "isolate_allow_server": True,
    "whitelist_skip_rules": True,
    "self_protect": False,
    "timeline_retain_days": 14,
    "events_retain_days": 90,
    "mysql_dual_write": True,
    # 文件完整性监控：内置关键目录 + 自定义目录（"D:\\app" 或 "D:\\app|r" 递归）
    "fim_enabled": True,
    "fim_paths": [],
    # 定向日志 tail（非 Filebeat filestream）；绝对路径白名单，如 C:\\Windows\\Temp\\app.log
    "log_tail_paths": [],
    # Winlog 通道：all | critical | custom；custom 时用 winevent_channels 列表（security/sysmon/…）
    "winevent_channel_mode": "all",
    "winevent_channels": [],
    # 默认由 Agent 托管安装 Sysmon（需平台 Sysmon/Sysmon64.exe 或安装包内带上）
    "sysmon_managed": True,
    "integrations": {
        "etw": True,
        "winevent": True,
        "fim": True,
        "registry": True,
        "persist": True,
        "device": True,
        "memory_scan": True,
        "evm": True,
        "ptm": True,
        "rootcheck": True,
        "sca": True,
    },
    "sca": {
        "policies": ["cis_win10_enterprise", "cis_win11_enterprise"],
        "max_checks_per_run": 48,
    },
    "active_response_enabled": True,
    "remote_ops_enabled": True,
    "remote_ops": {
        "enabled": True,
        "read_only": True,
        "run_cmd_enabled": False,
        "shell_enabled": False,
        "shell_max_minutes": 15,
        "run_cmd_whitelist": [
            "dir", "type", "reg", "ipconfig", "netstat", "tasklist", "systeminfo",
            "whoami", "hostname", "net", "sc", "cd", "echo", "where", "findstr",
        ],
    },
    "memory_scan": {
        "mode": "yara_triggered",
        "rules_rev": "2026.10.31.1",
        "max_processes_per_run": 20,
        "max_region_read_kb": 512,
        "schedule_interval_sec": 1800,
        # 内存完整性巡检：注入线程 / 反射 PE / ETW·AMSI 补丁 / ntdll 挂钩
        "integrity_checks": True,
        "integrity_interval_sec": 1800,
        "triggers": [
            "remote_thread_kernel",
            "process_access",
            "credential_access",
            "process_tampering",
            "image_load_etw",
            "image_load_sysmon",
            "priv_escalation",
            "evm_hit",
            "api_amsi",
            "amsi_hit",
            "api_call",
            "api_hit",
        ],
        "exclude_signed_vendor": ["Microsoft Corporation", "Google LLC"],
    },
    # 落地文件扫描：可执行/脚本落地后在用户态做规则 + PE 启发式 + 签名研判
    "drop_scan": {
        "enabled": True,
        "auto_quarantine": False,
        "quarantine_min_score": 80,
        "max_file_mb": 32,
    },
    # DataProtector 内核驱动（可选组件）：未安装驱动的终端忽略本段
    "dp_driver": {
        "enabled": True,
        # 拦截：关闭时驱动只告警（凭据/横向/威胁引擎/静态扫描均审计模式）
        "block": False,
        # 透明加密：开启后平台向终端下发主密钥；加密规则需另行配置
        "encryption_enabled": False,
    },
}




































def list_audit(*, limit: int = 100) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT * FROM agent_audit ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
            return {"ok": True, "items": [dict(r) for r in rows]}
        finally:
            conn.close()


def agent_side_bundle(agent_id: str, *, host_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """心跳附带：待执行指令 + 策略 + 白名单摘要。"""
    ensure()
    pol = get_policy("global")
    cmds = poll_commands(agent_id, limit=5)
    wl = list_whitelist()
    try:
        from . import agent_rules as _ar
        rule_fim = _ar.rule_fim_paths()
    except Exception:
        rule_fim = []
    mem_rev = ""
    try:
        from . import memory_yara
        mem_rev = str((memory_yara.bundle().get("rev") or ""))
    except Exception:
        mem_rev = ""
    policy_out = dict(pol.get("policy") or {})
    ms = policy_out.get("memory_scan")
    if isinstance(ms, dict) and mem_rev:
        ms = dict(ms)
        ms["rules_rev"] = mem_rev
        policy_out["memory_scan"] = ms
    if not isinstance(policy_out.get("drop_scan"), dict):
        policy_out["drop_scan"] = dict(_DEFAULT_POLICY.get("drop_scan") or {})
    else:
        ds = dict(_DEFAULT_POLICY.get("drop_scan") or {})
        ds.update(policy_out["drop_scan"])
        policy_out["drop_scan"] = ds
    policy_rev = int(pol.get("rev") or 1)
    try:
        from . import policy_sign
        policy_out = policy_sign.attach_policy_signature(policy_out, policy_rev)
    except Exception:
        pass
    cmd_items = cmds.get("items") or []
    out = {
        "commands": cmd_items,
        "rule_fim_paths": rule_fim,
        "policy": policy_out,
        "policy_rev": policy_rev,
        "memory_yara_rev": mem_rev,
        "whitelist": [
            {"kind": x.get("kind"), "value": x.get("value")}
            for x in (wl.get("items") or [])
            if x.get("enabled")
        ][:200],
        "self_protect": bool((pol.get("policy") or {}).get("self_protect")),
        "dp_crypto": _dp_crypto_for(agent_id),
    }
    # 有待执行指令时强制最短心跳，缩短结束进程/隔离的等待窗口
    if cmd_items:
        out["heartbeat_sec"] = 3
        out["pending_commands"] = len(cmd_items)
    return out


def _dp_crypto_for(agent_id: str) -> Optional[Dict[str, Any]]:
    try:
        from . import xedr_keys
        return xedr_keys.crypto_bundle_for_agent(agent_id)
    except Exception:
        return None


# IOC CRUD / lib → agent_ioc_ops（文末 re-export）

def _list_timeline_with_event_id(agent_id: str = "", *, limit: int = 300) -> List[Dict[str, Any]]:
    """专抽带 EventID 的时间线（不被 ETW 海量事件淹没）。"""
    ensure()
    limit = max(1, min(int(limit or 300), 500))
    clauses = ["detail_json LIKE ?"]
    args: List[Any] = ['%"event_id"%']
    if agent_id:
        clauses.insert(0, "agent_id=?")
        args.insert(0, agent_id)
    where = " WHERE " + " AND ".join(clauses)
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM agent_timeline{where} ORDER BY ts DESC, id DESC LIMIT ?",
                (*args, limit * 3),
            ).fetchall()
        finally:
            conn.close()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["detail"] = json.loads(d.pop("detail_json") or "{}")
        except Exception:
            d["detail"] = {}
        det = d.get("detail") if isinstance(d.get("detail"), dict) else {}
        if det.get("event_id") is None and det.get("EventID") is None:
            continue
        out.append(d)
        if len(out) >= limit:
            break
    return out




# ---------- 标签 ----------

def set_agent_tags(agent_id: str, tags: List[str]) -> Dict[str, Any]:
    ensure()
    aid = str(agent_id or "").strip()
    tags = [str(t).strip()[:32] for t in (tags or []) if str(t).strip()][:20]
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM agent_tags WHERE agent_id=?", (aid,))
            for t in tags:
                conn.execute("INSERT OR IGNORE INTO agent_tags(agent_id, tag) VALUES(?,?)", (aid, t))
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "agent_id": aid, "tags": tags}


def get_agent_tags(agent_id: str = "") -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            if agent_id:
                rows = conn.execute("SELECT tag FROM agent_tags WHERE agent_id=?", (agent_id,)).fetchall()
                return {"ok": True, "agent_id": agent_id, "tags": [r["tag"] for r in rows]}
            rows = conn.execute("SELECT agent_id, tag FROM agent_tags").fetchall()
            m: Dict[str, List[str]] = {}
            for r in rows:
                m.setdefault(r["agent_id"], []).append(r["tag"])
            return {"ok": True, "items": m}
        finally:
            conn.close()


# ---------- 行为序列 ----------

_DEFAULT_SEQ = [
    {
        "id": "seq-office-ps",
        "title": "办公进程后出现 PowerShell",
        "severity": "high",
        "window_sec": 180,
        "steps": [
            {"etype_contains": "process", "name_regex": r"(?i)(winword|excel|powerpnt|outlook)\.exe"},
            {"etype_contains": "process", "name_regex": r"(?i)(powershell|pwsh|cmd)\.exe"},
        ],
        "enabled": 1,
        "note": "宏/钓鱼常见链 · T1566→T1059",
    },
    {
        "id": "seq-temp-net",
        "title": "临时目录进程后外联",
        "severity": "high",
        "window_sec": 120,
        "steps": [
            {"summary_contains": "临时", "etype_contains": "process"},
            {"etype_contains": "network"},
        ],
        "enabled": 1,
        "note": "落地执行后外联 · T1105→T1071",
    },
    {
        "id": "seq-ps-net",
        "title": "PowerShell 后外联",
        "severity": "high",
        "window_sec": 90,
        "steps": [
            {"etype_contains": "process", "name_regex": r"(?i)(powershell|pwsh)\.exe"},
            {"etype_contains": "network"},
        ],
        "enabled": 1,
        "note": "脚本执行后 C2 · T1059→T1071",
    },
    {
        "id": "seq-file-proc",
        "title": "文件落地后进程创建",
        "severity": "medium",
        "window_sec": 120,
        "steps": [
            {"etype_contains": "file"},
            {"etype_contains": "process"},
        ],
        "enabled": 1,
        "note": "投放后执行 · T1105→T1204",
    },
]


def ensure_seq_rules() -> None:
    ensure()
    with _lock:
        conn = _connect()
        try:
            n = conn.execute("SELECT COUNT(*) AS c FROM agent_seq_rules").fetchone()["c"]
            if n:
                return
            for r in _DEFAULT_SEQ:
                conn.execute(
                    """INSERT INTO agent_seq_rules(id, title, severity, window_sec, steps_json, enabled, note, updated_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        r["id"], r["title"], r["severity"], r["window_sec"],
                        json.dumps(r["steps"], ensure_ascii=False), r["enabled"], r.get("note") or "", _now(),
                    ),
                )
            conn.commit()
        finally:
            conn.close()


def list_seq_rules() -> Dict[str, Any]:
    ensure_seq_rules()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM agent_seq_rules ORDER BY id").fetchall()
            items = []
            for r in rows:
                d = dict(r)
                try:
                    d["steps"] = json.loads(d.pop("steps_json") or "[]")
                except Exception:
                    d["steps"] = []
                items.append(d)
            return {"ok": True, "items": items}
        finally:
            conn.close()


def upsert_seq_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    ensure_seq_rules()
    rid = str(payload.get("id") or "").strip() or ("seq-" + uuid.uuid4().hex[:10])
    title = str(payload.get("title") or rid).strip()[:120]
    if not title:
        return {"ok": False, "error": "标题不能为空"}
    steps_in = payload.get("steps") if isinstance(payload.get("steps"), list) else []
    steps: List[Dict[str, Any]] = []
    for s in steps_in[:8]:
        if not isinstance(s, dict):
            continue
        st = {
            "etype_contains": str(s.get("etype_contains") or "").strip()[:64],
            "summary_contains": str(s.get("summary_contains") or "").strip()[:120],
            "name_regex": str(s.get("name_regex") or "").strip()[:200],
        }
        if not any(st.values()):
            continue
        steps.append(st)
    if len(steps) < 2:
        return {"ok": False, "error": "至少需要 2 个有效步骤（A→B）"}
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_seq_rules(id, title, severity, window_sec, steps_json, enabled, note, updated_at)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     title=excluded.title, severity=excluded.severity, window_sec=excluded.window_sec,
                     steps_json=excluded.steps_json, enabled=excluded.enabled, note=excluded.note,
                     updated_at=excluded.updated_at""",
                (
                    rid, title, str(payload.get("severity") or "high")[:16],
                    max(10, min(int(payload.get("window_sec") or 120), 3600)),
                    json.dumps(steps, ensure_ascii=False),
                    1 if payload.get("enabled", True) else 0,
                    str(payload.get("note") or "")[:200], _now(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "id": rid}


def delete_seq_rule(rule_id: str) -> Dict[str, Any]:
    ensure_seq_rules()
    rid = str(rule_id or "").strip()
    if not rid:
        return {"ok": False, "error": "缺少 id"}
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM agent_seq_rules WHERE id=?", (rid,))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "规则不存在"}
        finally:
            conn.close()
    return {"ok": True}


def _step_match(ev: Dict[str, Any], step: Dict[str, Any]) -> bool:
    import re
    et = str(ev.get("etype") or "")
    sm = str(ev.get("summary") or "")
    detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    name = str(detail.get("name") or detail.get("process_name") or "")
    want_et = str(step.get("etype_contains") or "").lower().strip()
    if want_et and want_et not in et.lower():
        return False
    # 「process」步骤不应命中退出事件，否则易变成「进程退出后碰巧有外联」误报
    if want_et == "process" and "exit" in et.lower():
        return False
    if step.get("summary_contains") and str(step["summary_contains"]).lower() not in sm.lower():
        return False
    rx = step.get("name_regex")
    if rx:
        try:
            if not re.search(str(rx), name or sm):
                return False
        except re.error:
            return False
    return True


def _seq_detail_of(ev: Dict[str, Any]) -> Dict[str, Any]:
    d = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    return d if isinstance(d, dict) else {}


def _seq_link_ok(prev: Dict[str, Any], cur: Dict[str, Any]) -> bool:
    """进程→网络：要求同 PID 或同进程名，避免 PS 退出后无关 svchost 外联误报。"""
    et_prev = str(prev.get("etype") or "").lower()
    et_cur = str(cur.get("etype") or "").lower()
    if "network" not in et_cur:
        return True
    if "process" not in et_prev:
        return True
    dp = _seq_detail_of(prev)
    dc = _seq_detail_of(cur)
    try:
        pid_a = int(dp.get("pid")) if dp.get("pid") is not None and str(dp.get("pid")).strip() != "" else None
        pid_b = int(dc.get("pid")) if dc.get("pid") is not None and str(dc.get("pid")).strip() != "" else None
        if pid_a is not None and pid_b is not None and pid_a == pid_b and pid_a > 0:
            return True
    except Exception:
        pass
    prev_name = str(dp.get("name") or dp.get("process_name") or "").lower().strip()
    cur_name = str(dc.get("process_name") or dc.get("name") or "").lower().strip()
    if not prev_name:
        # 从摘要兜底：进程创建: powershell.exe
        sm = str(prev.get("summary") or "")
        if ":" in sm:
            prev_name = sm.split(":")[-1].strip().lower()
    if prev_name and cur_name and (prev_name == cur_name or prev_name in cur_name or cur_name in prev_name):
        return True
    return False


def _seq_step_brief(ev: Dict[str, Any]) -> Dict[str, Any]:
    d = _seq_detail_of(ev)
    brief: Dict[str, Any] = {
        "etype": ev.get("etype"),
        "summary": ev.get("summary"),
        "ts": ev.get("ts"),
    }
    for k in (
        "pid", "ppid", "name", "process_name", "path", "image", "command_line",
        "remote", "remote_ip", "proto", "protocol", "local", "user",
    ):
        v = d.get(k)
        if v is not None and v != "":
            brief[k] = v
    if not brief.get("remote"):
        sm = str(ev.get("summary") or "")
        # 新外联: 1.2.3.4:443 / ETW外联: … (1.2.3.4:443)
        import re
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})", sm)
        if m:
            brief["remote"] = m.group(1)
    return brief


def _seq_event_detail(rule: Dict[str, Any], chain: List[Dict[str, Any]]) -> Dict[str, Any]:
    briefs = [_seq_step_brief(c) for c in chain]
    detail: Dict[str, Any] = {
        "rule_id": rule.get("id"),
        "etype": "sequence_hit",
        "steps": briefs,
        "chain_summary": " → ".join(
            str(b.get("summary") or b.get("etype") or "") for b in briefs
        ),
    }
    # 展平关键字段，便于告警详情直接展示外联地址 / 进程
    for b in briefs:
        et = str(b.get("etype") or "").lower()
        if "process" in et and "exit" not in et:
            for k in ("pid", "ppid", "name", "process_name", "path", "image", "command_line", "user"):
                if b.get(k) not in (None, "") and detail.get(k) in (None, ""):
                    detail[k] = b.get(k)
            if not detail.get("process_name") and b.get("name"):
                detail["process_name"] = b.get("name")
        if "network" in et or b.get("remote") or b.get("remote_ip"):
            for k in ("remote", "remote_ip", "proto", "protocol", "local", "pid", "process_name"):
                if b.get(k) not in (None, "") and detail.get(k) in (None, ""):
                    detail[k] = b.get(k)
            if b.get("etype") and detail.get("etype") == "sequence_hit":
                detail["network_etype"] = b.get("etype")
    if detail.get("remote") and not detail.get("remote_ip"):
        detail["remote_ip"] = str(detail["remote"]).split(":")[0]
    return detail




def _parse_ts(s: Any) -> float:
    try:
        return time.mktime(time.strptime(str(s)[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def _etype_to_rule_module(etype: str) -> str:
    et = str(etype or "").lower()
    if "file" in et or "image_load" in et or et.startswith("fim_"):
        return "file"
    if et.startswith("wmi_persist") or et.startswith("win_task") or et in ("win_bits", "win_smb", "persist_add", "persist_modify", "persist_delete"):
        return "file"
    if "network" in et:
        return "network"
    if "process" in et or et.endswith("_live"):
        return "process"
    if "driver" in et:
        return "file"
    return ""




# 挂钩：时间线入库后做 IOC + 序列 + 规则
from .agent_timeline_service import ingest_timeline as _ingest_timeline_base
_orig_ingest = _ingest_timeline_base


def ingest_timeline(payload: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[no-redef]
    out = _orig_ingest(payload)
    events = out.pop("_detect_events", None)
    if not out.get("ok"):
        return out
    agent_id = str(payload.get("agent_id") or "").strip()
    host = str(payload.get("hostname") or "").strip()
    if events is None:
        events = payload.get("events") if isinstance(payload.get("events"), list) else []
    blob_parts = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        blob_parts.append(str(ev.get("summary") or ""))
        d = ev.get("detail")
        if isinstance(d, dict):
            blob_parts.append(json.dumps(d, ensure_ascii=False))
        elif d:
            blob_parts.append(str(d))
    ioc_n = match_iocs(agent_id, host, blob="\n".join(blob_parts), events=events, module="ioc")
    seq_n = match_sequences(agent_id, host)
    rule_n = apply_timeline_rules(agent_id, host, events)
    corr_n = 0
    try:
        from . import correlation_engine
        corr_n = correlation_engine.apply_correlations(agent_id, host, events)
    except Exception as e:
        print("[correlation_engine]", e)
    log_rule_n = 0
    try:
        log_rule_n = apply_log_rules(agent_id, host, events)
    except Exception as e:
        print("[log_rules]", e)
    out["ioc_hits"] = ioc_n
    out["seq_hits"] = seq_n
    out["rule_hits"] = rule_n
    out["correlation_hits"] = corr_n
    out["log_rule_hits"] = log_rule_n
    out["sensor_alerts"] = _promote_sensor_alerts(agent_id, host, events)
    return out


_CHANNEL_FROM_SOURCE = {
    "security": "Security",
    "system": "System",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "bits": "Microsoft-Windows-Bits-Client/Operational",
    "smb": "Microsoft-Windows-SMBClient/Operational",
    "terminalservices": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
}


def _timeline_to_eventlog_shape(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """把 Agent 时间线事件转成 eventlog_rules.match_events 可吃的结构。"""
    if not isinstance(ev, dict):
        return None
    d = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    eid = d.get("event_id") if d.get("event_id") is not None else d.get("EventID")
    if eid is None:
        return None
    try:
        eid_i = int(eid)
    except Exception:
        return None
    if eid_i <= 0:
        return None
    ch = str(d.get("channel") or "").strip()
    if not ch:
        src = str(d.get("source") or "").strip().lower()
        ch = _CHANNEL_FROM_SOURCE.get(src, src)
    fields: Dict[str, Any] = {}
    for k, v in d.items():
        if v is None or isinstance(v, (dict, list)):
            continue
        fields[str(k)] = v
    flat = {
        "event_id": eid_i,
        "EventID": eid_i,
        "channel": ch,
        "time": str(ev.get("ts") or d.get("time") or ""),
        "provider": str(d.get("provider") or ""),
        "message": str(ev.get("summary") or ""),
        "fields": fields,
    }
    for k, v in fields.items():
        flat.setdefault(k, v)
    return flat




# 允许晋升为威胁事件的传感器 etype（明确白名单；不在表内的一律只留时间线）
_LAST_THREAT_SYNC_AT = 0.0
_THREAT_SYNC_MIN_INTERVAL = 45.0




# ---------- ATT&CK 看板 / 攻击故事 ----------

def _map_attck(text: str, module: str = "", etype: str = "") -> Dict[str, str]:
    if "LOLBin" in str(text or ""):
        try:
            from . import lolbin as _lb
            hit = _lb.technique_for_text(text)
            if hit:
                return hit
        except Exception:
            pass
    blob = f"{module} {etype} {text}".lower()
    if module == "memory" or "内存" in blob:
        if "mimikatz" in blob or "lsass" in blob:
            return {"technique": "T1003.001", "tactic": "credential_access"}
        return {"technique": "T1055", "tactic": "defense_evasion"}
    for keys, tid, tactic in _ATTCK_HINTS:
        if any(k.lower() in blob for k in keys):
            return {"technique": tid, "tactic": tactic}
    if module in ("startup", "task", "service"):
        return {"technique": "T1547.001" if module == "startup" else ("T1053.005" if module == "task" else "T1543.003"),
                "tactic": "persistence"}
    if module == "network" or "network" in etype:
        return {"technique": "T1071", "tactic": "command_and_control"}
    if module == "process" or "process" in etype:
        return {"technique": "T1059", "tactic": "execution"}
    return {"technique": "", "tactic": ""}


_TECH_NAME_CN = {
    "T1003": "凭证转储", "T1021": "远程服务", "T1053.005": "计划任务", "T1055": "进程注入",
    "T1059": "命令与脚本解释器", "T1071": "应用层协议通信", "T1105": "远程工具传入",
    "T1112": "修改注册表", "T1204": "用户执行", "T1543.003": "Windows 服务",
    "T1547.001": "注册表运行键 / 启动文件夹", "T1562.001": "禁用或篡改安全工具",
    "T1566": "钓鱼",     "T1574.002": "DLL 侧加载", "T1036.005": "匹配合法名称或位置",
    "T1070.001": "清除 Windows 事件日志", "T1136.001": "创建本地账号", "T1098": "账号操纵",
    "T1110": "暴力破解", "T1078": "有效账号", "T1003.001": "LSASS 内存读取", "T1568.002": "域名生成算法(DGA)",
    "T1059.001": "PowerShell",
}


def _tech_name(tid: str) -> str:
    if not tid:
        return ""
    if tid in _TECH_NAME_CN:
        return _TECH_NAME_CN[tid]
    try:
        from . import mitre
        meta = mitre.technique_meta(tid)
        return meta.get("name_cn") or meta.get("name_en") or ""
    except Exception:
        return ""


def _tech_label(tid: str) -> str:
    if not tid:
        return ""
    name = _tech_name(tid)
    return f"{tid} · {name}" if name else tid












def _attck_source_events(*, agent_id: str = "", days: int = 0, limit: int = 2000) -> List[Dict[str, Any]]:
    """看板数据源：时间窗在 SQL 里过滤，避免先截断条数再按天筛导致漏数；已加白（无需处置）不计入。"""
    clauses = ["status != 'ignored'"]
    args: List[Any] = []
    if agent_id:
        clauses.append("agent_id=?")
        args.append(str(agent_id))
    if days and days > 0:
        clauses.append("created_at>=?")
        args.append(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - int(days) * 86400)))
    args.append(max(1, min(int(limit or 2000), 5000)))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                f"""SELECT id, agent_id, hostname, severity, title, module, status, created_at
                    FROM agent_events WHERE {' AND '.join(clauses)}
                    ORDER BY id DESC LIMIT ?""",
                args,
            ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []
        finally:
            conn.close()


# ---------- 灰度升级包 ----------

def _upgrade_dir() -> Path:
    root = Path(getattr(config, "DATA_ROOT", None) or getattr(config, "ROOT", Path(".")))
    d = root / "data" / "agent_upgrades"
    d.mkdir(parents=True, exist_ok=True)
    return d


def upgrade_sign_message(sha256_hex: str, version: str, size: int) -> bytes:
    """与 Agent upgradeSignMessage 一致。"""
    return f"FA-UPGRADE-V1\n{str(sha256_hex).lower().strip()}\n{str(version).strip()}\n{int(size)}".encode("utf-8")


def _upgrade_key_paths() -> tuple:
    d = _upgrade_dir()
    return d / "ed25519_priv.pem", d / "ed25519_pub.b64"


def ensure_upgrade_keypair() -> Dict[str, Any]:
    """首次调用时生成 Ed25519 密钥对；私钥仅留在服务端 data 目录。"""
    priv_path, pub_path = _upgrade_key_paths()
    if priv_path.is_file() and pub_path.is_file():
        return {"ok": True, "pubkey": pub_path.read_text(encoding="utf-8").strip(), "created": False}
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
    import base64

    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    priv_path.write_bytes(priv_pem)
    try:
        priv_path.chmod(0o600)
    except Exception:
        pass
    pub_path.write_text(pub_b64 + "\n", encoding="utf-8")
    return {"ok": True, "pubkey": pub_b64, "created": True}


def get_upgrade_pubkey() -> Dict[str, Any]:
    out = ensure_upgrade_keypair()
    if not out.get("ok"):
        return out
    return {"ok": True, "pubkey": out["pubkey"], "alg": "Ed25519"}


def sign_upgrade_package(sha256_hex: str, version: str, size: int) -> str:
    """返回 base64 签名；密钥不可用时返回空串。"""
    out = ensure_upgrade_keypair()
    if not out.get("ok"):
        return ""
    priv_path, _ = _upgrade_key_paths()
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except Exception:
        return ""
    try:
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            return ""
        sig = priv.sign(upgrade_sign_message(sha256_hex, version, size))
        import base64

        return base64.b64encode(sig).decode("ascii")
    except Exception as e:
        print("[upgrade] sign failed:", e)
        return ""


def list_upgrade_packages() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT id, version, filename, sha256, size, note, created_by, created_at, "
                "COALESCE(sig_ed25519,'') AS sig_ed25519 FROM agent_upgrade_packages ORDER BY created_at DESC"
            ).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                d["signed"] = bool(d.get("sig_ed25519"))
                items.append(d)
            return {"ok": True, "items": items}
        finally:
            conn.close()


def save_upgrade_package(
    content: bytes,
    *,
    version: str,
    filename: str = "forensic-agent.exe",
    note: str = "",
    actor: str = "",
) -> Dict[str, Any]:
    ensure()
    import hashlib

    if not content or len(content) < 1024:
        return {"ok": False, "error": "包内容过小"}
    if len(content) > 80 * 1024 * 1024:
        return {"ok": False, "error": "包超过 80MB"}
    ver = str(version or "").strip()[:32] or time.strftime("%Y%m%d%H%M%S")
    pid = uuid.uuid4().hex
    sha = hashlib.sha256(content).hexdigest()
    safe_name = Path(filename or "forensic-agent.exe").name
    # 仅允许 Agent 发布件扩展名，并剥离路径成分
    low = safe_name.lower()
    if not any(low.endswith(ext) for ext in (".exe", ".msi", ".zip", ".pkg", ".deb", ".rpm")):
        return {"ok": False, "error": "仅允许 exe/msi/zip/pkg/deb/rpm 发布件"}
    if ".." in safe_name or "/" in safe_name or "\\" in safe_name or "\x00" in safe_name:
        return {"ok": False, "error": "文件名非法"}
    # PE/ZIP 魔数抽检，避免上传脚本伪装扩展名
    head = content[:8]
    if low.endswith(".exe") and not (head.startswith(b"MZ") or head.startswith(b"\x7fELF")):
        return {"ok": False, "error": "可执行文件魔数不匹配"}
    if low.endswith(".zip") and not head.startswith(b"PK"):
        return {"ok": False, "error": "ZIP 魔数不匹配"}
    if low.endswith(".msi") and not head.startswith(b"\xd0\xcf\x11\xe0"):
        return {"ok": False, "error": "MSI 魔数不匹配"}
    dest = _upgrade_dir() / f"{pid}_{safe_name}"
    dest.write_bytes(content)
    sig = sign_upgrade_package(sha, ver, len(content))
    now = _now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_upgrade_packages(id, version, filename, sha256, size, note, created_by, created_at, sig_ed25519)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (pid, ver, dest.name, sha, len(content), note[:200], actor[:64], now, sig),
            )
            conn.commit()
        finally:
            conn.close()
    _audit("upgrade_upload", detail=f"version={ver} sha256={sha[:16]}… size={len(content)} signed={bool(sig)}", actor=actor)
    pub = get_upgrade_pubkey().get("pubkey") or ""
    return {"ok": True, "id": pid, "version": ver, "sha256": sha, "size": len(content), "sig_ed25519": sig, "pubkey": pub}


def get_upgrade_package(pid: str) -> Optional[Dict[str, Any]]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM agent_upgrade_packages WHERE id=?", (str(pid),)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def read_upgrade_package_bytes(pid: str) -> tuple:
    meta = get_upgrade_package(pid)
    if not meta:
        return None, None
    path = _upgrade_dir() / meta["filename"]
    if not path.is_file():
        return meta, None
    return meta, path.read_bytes()


def delete_upgrade_package(pid: str) -> Dict[str, Any]:
    ensure()
    meta = get_upgrade_package(pid)
    if not meta:
        return {"ok": False, "error": "不存在"}
    path = _upgrade_dir() / meta["filename"]
    try:
        if path.is_file():
            path.unlink()
    except Exception:
        pass
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM agent_upgrade_packages WHERE id=?", (str(pid),))
            conn.commit()
        finally:
            conn.close()
    return {"ok": True}


def push_upgrade(
    package_id: str,
    agent_ids: List[str],
    *,
    actor: str = "",
    base_url: str = "",
) -> Dict[str, Any]:
    """向指定终端下发 upgrade 指令（灰度）。"""
    meta = get_upgrade_package(package_id)
    if not meta:
        return {"ok": False, "error": "升级包不存在"}
    ids = [str(a).strip() for a in (agent_ids or []) if str(a).strip()]
    if not ids:
        return {"ok": False, "error": "未选择终端"}
    base = str(base_url or "").rstrip("/")
    url = f"{base}/api/agent/upgrade-packages/{meta['id']}/download" if base else f"/api/agent/upgrade-packages/{meta['id']}/download"
    sig = str(meta.get("sig_ed25519") or "")
    if not sig:
        sig = sign_upgrade_package(meta["sha256"], meta["version"], int(meta.get("size") or 0))
        if sig:
            with _lock:
                conn = _connect()
                try:
                    conn.execute(
                        "UPDATE agent_upgrade_packages SET sig_ed25519=? WHERE id=?",
                        (sig, meta["id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()
    pub = get_upgrade_pubkey().get("pubkey") or ""
    results = []
    for aid in ids[:200]:
        params = {
            "package_id": meta["id"],
            "version": meta["version"],
            "sha256": meta["sha256"],
            "url": url,
            "size": meta["size"],
        }
        if sig:
            params["sig_ed25519"] = sig
        if pub:
            params["pubkey"] = pub  # 仅当 Agent 未钉扎公钥时作开发兜底
        r = create_command(aid, "upgrade", params, actor=actor)
        results.append({"agent_id": aid, **r})
    _audit(
        "upgrade_push",
        detail=json.dumps({"package_id": package_id, "version": meta["version"], "agents": len(ids)}, ensure_ascii=False),
        actor=actor,
    )
    return {"ok": True, "package_id": package_id, "version": meta["version"], "results": results}



from .agent_policy_store import (
    _num, get_policy, list_policy_history, policy_rollout, rollback_policy,
    set_policy, validate_policy,
)


from .agent_policy_entities import (
    add_whitelist, assign_agent_to_group, delete_group, delete_whitelist,
    list_groups, list_whitelist, set_whitelist_enabled, update_whitelist, upsert_group,
)

from .agent_log_analysis import diagnose_log_rules, investigate_logs, get_log_detail

from .agent_process_tree import _build_threat_drop_chain, threat_process_tree


from .agent_commands import (
    ACTIONS, HIGH_RISK_ACTIONS,
    COMMAND_LEASE_DEFAULT_SEC, COMMAND_LEASE_SEC, COMMAND_MAX_ATTEMPTS,
    COMMAND_TTL_DEFAULT_SEC, COMMAND_TTL_SEC,
    create_command, poll_commands, command_owner, ack_command, list_commands,
    _validate_remote_ops_command, _remote_ops_policy_cfg, _memscan_to_events,
)
from .agent_ioc_ops import (
    list_ioc, add_ioc, import_iocs, delete_ioc,
    match_iocs_against_text, ioc_lib_status, lookup_ioc_lib, _IOC_TYPE_CN,
)

from .agent_detection_analytics import match_iocs, apply_timeline_rules, sync_threats_from_timeline, attack_story, attck_board

from .agent_timeline_service import list_timeline, apply_log_rules, match_sequences
