# -*- coding: utf-8 -*-
"""终端 Agent 协议（骨架）。

现状：平台主路径仍是离线 pack / 一次性 POST。
本模块定义实时 Agent 的模块集、心跳与增量快照存储，供后续 Windows 安装包对接。

工作量说明（务实）：
- MVP 心跳 + 在线列表：小
- 计划任务/服务/启动项/网络增量同步 + 变更 diff + 告警：中大
- 安装包、保活、权限、断线续传、多版本兼容：大

建议分阶段：heartbeat → snapshot(persist/network) → 变更事件 → 安装器。
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import secrets
import signal
import sqlite3
import threading
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from . import config
from .sqlite_schema_tools import _col_exists, _add_col
from .agent_event_detail import fit_detail, _detail_richer
from .agent_package_builder import agent_binary_path, build_install_package, clear_install_package_cache


# Agent 默认同步模块（与 forensic 侧栏对齐，先做高价值轻量项）
AGENT_MODULES = (
    "sysinfo",
    "service",
    "task",
    "startup",
    "network",
    "process",
    "file",   # 高危目录近期文件
    "user",   # 本地用户 / 登录会话
    "software",  # 已装软件清单（HKLM/HKCU/AppX）
    "hotfix",    # 补丁 KB
    "listen",    # 监听端口
    "driver",    # 内核/文件系统驱动
    "netif",     # 网卡 / IP / 网关
    "groups",    # 本地用户组
    "firewall",  # 防火墙启用规则
    "shares",    # SMB 共享
    "certs",     # 计算机证书
    "usb",       # USB 设备快照
)

# 采集周期（秒）——威胁相关模块尽量压到秒级，抓住黄金时间
# 实时威胁由 ETW/FIM/注册表/事件日志负责；周期快照只做资产与兜底，避免 PowerShell 拖慢终端
MODULE_INTERVAL_SEC = {
    "sysinfo": 300,
    "service": 600,
    "task": 900,
    "startup": 300,
    "network": 60,
    "process": 120,
    "file": 900,
    "user": 300,
    "software": 1800,
    "hotfix": 7200,
    "listen": 300,
    "driver": 1800,
    "netif": 600,
    "groups": 900,
    "firewall": 900,
    "shares": 900,
    "certs": 1800,
    "usb": 600,
}

PROTOCOL_VERSION = 1
DB_NAME = "agents.db"

# 服务端支持的协议范围与能力。新增接口后同步上调 MAX 并追加能力名。
SERVER_PROTOCOL_MIN = 1
SERVER_PROTOCOL_MAX = 2
SERVER_CAPABILITIES = (
    "inventory.parts.v1",
    "inventory.software.extended.v1",
    "inventory.software.paged.v1",
    "inventory.assets.paged.v1",
    "inventory.user.paged.v1",
    "snapshot.v1",
    "timeline.v1",
    "command.ack.v1",
    "process.identity.v1",
    "sensor.etw",
    "sensor.wevt",
    "upgrade.replace",
    "upgrade.ed25519",
    "upgrade.watchdog",
    # 阶段1
    "ingest.v2",          # POST /api/agent/v2/events/batch 幂等批量上报
    "auth.agent_secret",  # 每 Agent 独立凭据
    "command.lease",      # 命令 lease/重试/截止
    "health.v1",          # 心跳健康指标
    # 阶段2
    "process.entity.v1",  # 进程实体 entity_id / 墓碑，服务端 agent_processes
    "registry.realtime",  # 实时注册表（persist_* / registry_*）
    "dns.aggregate",      # dns_query / dns_summary / dns_nx_burst，服务端 agent_dns
    "fim.v1",             # fim_add / fim_modify / fim_delete / fim_rename
    # 阶段3
    "inventory.delta",    # snapshot_delta：按 generation 链应用增量清单
    "policy.lkg",         # Agent 心跳回报策略生效/试用/拒绝/回滚状态
    "sync.v1",
    "fleet.checkin.v1",
    "diagnostics.v2",
    "composable.host.v1",
    "event.schema.v1",
    # Platform-recognized build capabilities (kept explicit for negotiation).
    "memory.integrity.v1", "file.meta.v1", "http.etw.v1", "beacon.watch.v1",
    "response.persist.v1", "policy.sign.v1", "self.protect.watch.v1",
    "fim.polling.v1", "inventory.kernel_module.v1",
    "inventory.process.procfs.v1", "inventory.network.procfs.v1",
    "inventory.services.systemd_units.linux.v1",
    "inventory.tasks.cron_systemd.linux.v1", "inventory.startup.linux.v1",
    "rules.linux.process_snapshot.v1",
    "inventory.software.linux.v1", "inventory.package_updates.linux.v1",
    "rootcheck.linux.v1", "sca.linux.v1", "response.kill_process.linux.v1",
    "response.quarantine_file.linux.v1", "sensor.linux.journal.v1",
)


def negotiate_protocol(payload: Dict[str, Any]) -> Dict[str, Any]:
    """按 Agent 声明的协议范围/能力与服务端取交集。旧 Agent 不带字段时视为 v1。"""
    def _i(v: Any, d: int) -> int:
        try:
            return max(1, int(v))
        except Exception:
            return d
    amin = _i(payload.get("protocol_min"), 1)
    amax = _i(payload.get("protocol_max"), amin)
    if amax < amin:
        amin, amax = amax, amin
    lo, hi = max(amin, SERVER_PROTOCOL_MIN), min(amax, SERVER_PROTOCOL_MAX)
    caps_in = payload.get("capabilities")
    if not isinstance(caps_in, list):
        caps_in = []
    caps = [str(c)[:48] for c in caps_in][:64]
    enabled = [c for c in caps if c in SERVER_CAPABILITIES]
    out: Dict[str, Any] = {
        "agent_min": amin, "agent_max": amax,
        "selected": hi if lo <= hi else 0,
        "agent_caps": caps, "enabled_caps": enabled,
    }
    if lo > hi:
        out["warning"] = (
            f"协议不兼容：Agent 支持 v{amin}-v{amax}，服务端支持 "
            f"v{SERVER_PROTOCOL_MIN}-v{SERVER_PROTOCOL_MAX}，请升级较旧的一方"
        )
    return out

# ---- 数据库迁移（PRAGMA user_version）----
# 迁移必须幂等，按版本号递增追加，禁止修改已发布的迁移。

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT DEFAULT '',
    os_family TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    version TEXT DEFAULT '',
    token_hint TEXT DEFAULT '',
    last_seen TEXT DEFAULT '',
    status TEXT DEFAULT 'offline',
    meta_json TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS agent_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    module TEXT NOT NULL,
    collected_at TEXT DEFAULT '',
    item_count INTEGER DEFAULT 0,
    digest TEXT DEFAULT '',
    payload_json TEXT DEFAULT '',
    UNIQUE(agent_id, module)
);
CREATE TABLE IF NOT EXISTS agent_meta (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS agent_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    title TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    module TEXT DEFAULT '',
    status TEXT DEFAULT 'open',
    hit_count INTEGER DEFAULT 1,
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agents_seen ON agents(last_seen);
CREATE INDEX IF NOT EXISTS idx_snap_agent ON agent_snapshots(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_created ON agent_events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_status ON agent_events(status);
"""

ENROLL_META_KEY = "enroll_key"

_lock = threading.RLock()

# 近实时推送：有心跳/快照/事件变更时递增，SSE 客户端据此拉取
_live_rev = 0
_live_cv = threading.Condition(_lock)
_live_hint: Dict[str, Any] = {"kind": "init"}


def bump_live(kind: str, **extra: Any) -> int:
    global _live_rev, _live_hint
    with _live_cv:
        _live_rev += 1
        _live_hint = {"kind": kind, "rev": _live_rev, **extra}
        _live_cv.notify_all()
        return _live_rev


_last_heartbeat_live_bump = 0.0


def bump_live_heartbeat(agent_id: str) -> None:
    """心跳节流推送（约 2s 一次），避免 SSE 被刷爆，仍能让概览及时看到上下线。"""
    global _last_heartbeat_live_bump
    now = time.time()
    if now - _last_heartbeat_live_bump < 2.0:
        return
    _last_heartbeat_live_bump = now
    bump_live("heartbeat", agent_id=str(agent_id or "")[:64])


def live_revision() -> int:
    with _lock:
        return int(_live_rev)


_live_shutdown = threading.Event()
_live_hooks_installed = False


def reset_live_shutdown() -> None:
    """进程启动时清除关闭标志（reload 子进程）。"""
    _live_shutdown.clear()


def shutdown_live() -> None:
    """服务关闭时唤醒并结束所有 SSE 生成器，避免 uvicorn 一直等长连接。"""
    _live_shutdown.set()
    with _live_cv:
        _live_cv.notify_all()


def install_live_shutdown_hooks() -> None:
    """在 SIGINT/SIGTERM 时先于 uvicorn 等待连接，唤醒 SSE（lifespan finally 可能被 CancelledError 跳过）。"""
    global _live_hooks_installed
    if _live_hooks_installed:
        return
    _live_hooks_installed = True

    import atexit

    atexit.register(shutdown_live)

    def _wrap(prev):
        def handler(signum, frame):
            shutdown_live()
            if callable(prev):
                prev(signum, frame)
            elif prev == signal.SIG_DFL:
                raise KeyboardInterrupt

        return handler

    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None), getattr(signal, "SIGBREAK", None)):
        if sig is None:
            continue
        try:
            signal.signal(sig, _wrap(signal.getsignal(sig)))
        except (OSError, ValueError, RuntimeError):
            pass


def _live_snapshot(rev: int) -> Tuple[int, Optional[str]]:
    with _lock:
        cur = int(_live_rev)
        if cur <= rev:
            return cur, None
        hint = dict(_live_hint)
    return cur, f"data: {json.dumps(hint, ensure_ascii=False)}\n\n"


async def async_iter_live_sse(
    request: Any,
    last_rev: int = 0,
    *,
    timeout_sec: float = 15.0,
    poll_sec: float = 0.25,
):
    """异步 SSE：可响应客户端断开与服务关闭，避免 sync 生成器在 graceful shutdown 超时后被强杀。"""
    rev = int(last_rev or 0)
    idle = 0.0
    poll = max(0.05, min(float(poll_sec), 1.0))
    while not _live_shutdown.is_set():
        try:
            if await request.is_disconnected():
                return
        except Exception:
            return
        cur, chunk = _live_snapshot(rev)
        if chunk is not None:
            rev = cur
            idle = 0.0
            yield chunk
            continue
        idle += poll
        if idle >= timeout_sec:
            idle = 0.0
            yield ": ping\n\n"
        await asyncio.sleep(poll)
    yield 'data: {"kind":"server_shutdown"}\n\n'


def iter_live_sse(last_rev: int = 0, *, timeout_sec: float = 15.0):
    """SSE 事件生成器：data 为 JSON（rev/kind）。心跳注释保持连接。

    等待以 1 秒为片，随时响应关闭信号；客户端断开后下一次 yield 即退出。
    禁止在持有 Condition 锁时 yield：生成器被关闭时 __exit__ 可能在非持锁
    线程上 release，触发 RuntimeError: cannot release un-acquired lock。
    """
    rev = int(last_rev or 0)
    idle = 0.0
    while not _live_shutdown.is_set():
        to_yield: Optional[str] = None
        with _live_cv:
            if _live_rev <= rev:
                _live_cv.wait(timeout=0.25)
                if _live_shutdown.is_set():
                    return
                if _live_rev <= rev:
                    idle += 0.25
                    if idle >= timeout_sec:
                        idle = 0.0
                        to_yield = ": ping\n\n"
                else:
                    idle = 0.0
                    rev = _live_rev
                    to_yield = f"data: {json.dumps(dict(_live_hint), ensure_ascii=False)}\n\n"
            else:
                idle = 0.0
                rev = _live_rev
                to_yield = f"data: {json.dumps(dict(_live_hint), ensure_ascii=False)}\n\n"
        if to_yield is not None:
            yield to_yield


def db_path() -> Path:
    d = Path(getattr(config, "REPORTS_DIR", None) or (Path(config.ROOT) / "reports"))
    d.mkdir(parents=True, exist_ok=True)
    return d / DB_NAME


def _mig_001_agent_build_protocol(conn: sqlite3.Connection) -> None:
    """agents 增加构建号/源码指纹/协议协商/能力列。"""
    _add_col(conn, "agents", "build_id", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "source_rev", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "build_time", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "proto_min", "INTEGER DEFAULT 1")
    _add_col(conn, "agents", "proto_max", "INTEGER DEFAULT 1")
    _add_col(conn, "agents", "proto_selected", "INTEGER DEFAULT 1")
    _add_col(conn, "agents", "capabilities_json", "TEXT DEFAULT '[]'")


def _mig_002_credentials_health(conn: sqlite3.Connection) -> None:
    """每 Agent 独立凭据（仅存哈希）、吊销标记、健康指标。"""
    _add_col(conn, "agents", "secret_hash", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "secret_issued_at", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "secret_rev", "INTEGER DEFAULT 0")
    _add_col(conn, "agents", "revoked", "INTEGER DEFAULT 0")
    _add_col(conn, "agents", "health_json", "TEXT DEFAULT '{}'")
    _add_col(conn, "agents", "health_at", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "clock_skew_sec", "REAL DEFAULT 0")


def _mig_003_ingest_commands(conn: sqlite3.Connection) -> None:
    """v2 幂等上报回执 + 命令 lease/截止/幂等键。"""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_receipts (
               agent_id TEXT NOT NULL,
               event_uuid TEXT NOT NULL,
               kind TEXT DEFAULT '',
               stream TEXT DEFAULT 'main',
               seq INTEGER DEFAULT 0,
               status TEXT DEFAULT 'ok',
               error TEXT DEFAULT '',
               received_at TEXT DEFAULT '',
               PRIMARY KEY(agent_id, event_uuid)
           )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_receipts_time ON agent_receipts(received_at)")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_streams (
               agent_id TEXT NOT NULL,
               stream TEXT NOT NULL,
               high_seq INTEGER DEFAULT 0,
               received INTEGER DEFAULT 0,
               rejected INTEGER DEFAULT 0,
               updated_at TEXT DEFAULT '',
               PRIMARY KEY(agent_id, stream)
           )"""
    )
    _add_col(conn, "agent_commands", "lease_until", "TEXT DEFAULT ''")
    _add_col(conn, "agent_commands", "attempts", "INTEGER DEFAULT 0")
    _add_col(conn, "agent_commands", "max_attempts", "INTEGER DEFAULT 3")
    _add_col(conn, "agent_commands", "deadline", "TEXT DEFAULT ''")
    _add_col(conn, "agent_commands", "idempotency_key", "TEXT DEFAULT ''")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cmd_idem ON agent_commands(agent_id, idempotency_key)"
    )


def _mig_004_entities_dns(conn: sqlite3.Connection) -> None:
    """进程实体（墓碑保留）+ DNS 域名聚合 + 时间线 entity_id 索引。"""
    from . import agent_telemetry
    agent_telemetry.migrate(conn)


def _mig_005_inventory_policy(conn: sqlite3.Connection) -> None:
    """增量清单（快照代号 + 条目键）+ 策略版本历史。"""
    _add_col(conn, "agent_snapshots", "generation", "INTEGER DEFAULT 0")
    _add_col(conn, "agent_snapshots", "keys_json", "TEXT DEFAULT ''")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_policy_history (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               scope TEXT NOT NULL,
               rev INTEGER NOT NULL,
               policy_json TEXT DEFAULT '{}',
               actor TEXT DEFAULT '',
               note TEXT DEFAULT '',
               created_at TEXT DEFAULT ''
           )"""
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_hist ON agent_policy_history(scope, rev)")
    # 现有策略作为历史起点，便于回滚
    conn.execute(
        """INSERT OR IGNORE INTO agent_policy_history(scope, rev, policy_json, actor, note, created_at)
           SELECT scope, rev, policy_json, '', '迁移时的现行版本', updated_at FROM agent_policy"""
    )


def _mig_006_upgrade_ed25519(conn: sqlite3.Connection) -> None:
    """升级包 Ed25519 签名列。"""
    _add_col(conn, "agent_upgrade_packages", "sig_ed25519", "TEXT DEFAULT ''")


def _mig_007_alert_allow(conn: sqlite3.Connection) -> None:
    """告警加白：主机范围、告警标题限定、命中计数。"""
    _add_col(conn, "agent_whitelist", "agent_id", "TEXT DEFAULT ''")
    _add_col(conn, "agent_whitelist", "rule", "TEXT DEFAULT ''")
    _add_col(conn, "agent_whitelist", "hits", "INTEGER DEFAULT 0")
    _add_col(conn, "agent_whitelist", "last_hit_at", "TEXT DEFAULT ''")
    _add_col(conn, "agent_whitelist", "created_by", "TEXT DEFAULT ''")
    _add_col(conn, "agent_whitelist", "source_event_id", "INTEGER DEFAULT 0")


def _mig_008_agent_tombstones(conn: sqlite3.Connection) -> None:
    """删除终端时保留凭据哈希：仍在运行的 Agent 凭原凭据可自动恢复注册，不必重装。"""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_tombstones (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT DEFAULT '',
            secret_hash TEXT DEFAULT '',
            deleted_at TEXT DEFAULT ''
        )"""
    )


def _mig_009_event_deletions(conn: sqlite3.Connection) -> None:
    """记录被删除的告警，时间线补晋升时不再把它们恢复回来。"""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_event_deletions (
            agent_id TEXT NOT NULL,
            title TEXT NOT NULL,
            deleted_at TEXT DEFAULT '',
            PRIMARY KEY (agent_id, title)
        )"""
    )


def _mig_010_event_notes(conn: sqlite3.Connection) -> None:
    """威胁研判：评论 / 研判结论（真实威胁、误报、待观察）。"""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_event_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            agent_id TEXT DEFAULT '',
            kind TEXT DEFAULT 'comment',
            verdict TEXT DEFAULT '',
            content TEXT DEFAULT '',
            author TEXT DEFAULT '',
            created_at TEXT DEFAULT ''
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_notes_event ON agent_event_notes(event_id, id)")


def _mig_011_event_hit_count(conn: sqlite3.Connection) -> None:
    """告警去重累计命中次数（同载荷/同标题合并时递增）。"""
    _add_col(conn, "agent_events", "hit_count", "INTEGER DEFAULT 1")
    conn.execute("UPDATE agent_events SET hit_count=1 WHERE hit_count IS NULL OR hit_count < 1")

def _mig_012_heartbeat_period_and_index_outbox(conn: sqlite3.Connection) -> None:
    _add_col(conn, "agents", "heartbeat_period_sec", "INTEGER DEFAULT 3")
    _add_col(conn, "agents", "last_heartbeat_at", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "last_telemetry_at", "TEXT DEFAULT ''")
    conn.execute("INSERT OR IGNORE INTO agent_meta(key,value) VALUES('sync_revision',?)",
                 (str(int(time.time() // 60)),))
    from .es_event_queue import ensure_transactional_schema
    ensure_transactional_schema(conn)

def _mig_013_snapshot_parts(conn: sqlite3.Connection) -> None:
    from .agent_snapshot_parts import ensure_schema
    ensure_schema(conn)


def _mig_014_approval_command_guard(conn: sqlite3.Connection) -> None:
    # Prevent new duplicate approval commands without deleting historical rows.
    conn.execute("""CREATE TRIGGER IF NOT EXISTS approval_command_once
        BEFORE INSERT ON agent_commands
        WHEN substr(NEW.idempotency_key,1,9)='approval:' AND EXISTS (
            SELECT 1 FROM agent_commands WHERE idempotency_key=NEW.idempotency_key)
        BEGIN SELECT RAISE(ABORT,'approval command already exists'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS approval_command_key_immutable
        BEFORE UPDATE OF idempotency_key ON agent_commands
        WHEN NEW.idempotency_key IS NOT OLD.idempotency_key AND
             (substr(OLD.idempotency_key,1,9)='approval:' OR substr(NEW.idempotency_key,1,9)='approval:')
        BEGIN SELECT RAISE(ABORT,'approval command key is immutable'); END""")


_MIGRATIONS = (
    (1, "agent build/protocol columns", _mig_001_agent_build_protocol),
    (2, "per-agent credentials + health", _mig_002_credentials_health),
    (3, "v2 receipts + command lease", _mig_003_ingest_commands),
    (4, "process entities + dns aggregate", _mig_004_entities_dns),
    (5, "inventory delta + policy history", _mig_005_inventory_policy),
    (6, "upgrade package ed25519 sig", _mig_006_upgrade_ed25519),
    (7, "alert allowlist scope + hits", _mig_007_alert_allow),
    (8, "agent tombstones", _mig_008_agent_tombstones),
    (9, "event deletion marks", _mig_009_event_deletions),
    (10, "event triage notes", _mig_010_event_notes),
    (11, "event hit_count", _mig_011_event_hit_count),
    (12, "heartbeat period and transactional ES outbox", _mig_012_heartbeat_period_and_index_outbox),
    (13, "bounded snapshot staging", _mig_013_snapshot_parts),
    (14, "approval command identity guard", _mig_014_approval_command_guard),
)
SCHEMA_VERSION = _MIGRATIONS[-1][0]
_migrated_paths: set = set()


def _backup_db(conn: sqlite3.Connection, from_ver: int) -> Optional[Path]:
    """迁移前做一致性备份（sqlite backup API，含 WAL 内容），仅保留最近 5 份。"""
    try:
        bdir = db_path().parent / "db_backups"
        bdir.mkdir(parents=True, exist_ok=True)
        dst_path = bdir / f"agents_v{from_ver}_{time.strftime('%Y%m%d_%H%M%S')}.db"
        dst = sqlite3.connect(str(dst_path))
        try:
            conn.backup(dst)
        finally:
            dst.close()
        olds = sorted(bdir.glob("agents_v*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
        for p in olds[5:]:
            try:
                p.unlink()
            except OSError:
                pass
        return dst_path
    except Exception as e:
        print("[agent_db] 迁移前备份失败:", e)
        return None


def migrate(conn: sqlite3.Connection) -> int:
    """按 user_version 顺序执行未应用的迁移；每个迁移独立事务，失败则回滚并抛出。"""
    key = str(db_path())
    if key in _migrated_paths:
        return SCHEMA_VERSION
    cur = int(conn.execute("PRAGMA user_version").fetchone()[0])
    pending = [m for m in _MIGRATIONS if m[0] > cur]
    if pending:
        # 迁移可能涉及主表与 EDR 扩展表，先确保它们存在
        conn.executescript(_SCHEMA)
        try:
            from . import agent_edr
            conn.executescript(agent_edr._SCHEMA)
        except Exception as e:
            print("[agent_db] edr schema:", e)
        has_data = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0] > 0
        if has_data:
            conn.commit()
            bk = _backup_db(conn, cur)
            if bk:
                print(f"[agent_db] 迁移 v{cur}→v{SCHEMA_VERSION}，已备份 {bk.name}")
        for ver, name, fn in pending:
            try:
                conn.execute("BEGIN IMMEDIATE")
                fn(conn)
                conn.execute(f"PRAGMA user_version={int(ver)}")
                conn.commit()
                print(f"[agent_db] migration {ver} ok: {name}")
            except Exception:
                conn.rollback()
                raise
    _migrated_paths.add(key)
    return SCHEMA_VERSION


class _AmbientConn:
    """批量事务内共享的连接代理：commit/rollback/close 由外层 batch_tx 统一控制。"""

    def __init__(self, conn: sqlite3.Connection):
        self._c = conn

    def __getattr__(self, name: str) -> Any:
        return getattr(self._c, name)

    def commit(self) -> None:  # noqa: D401
        return None

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None

    def executescript(self, *_a: Any, **_k: Any) -> Any:
        raise RuntimeError("batch_tx 内禁止 executescript（会隐式提交）")


_ambient = threading.local()


def _real_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    migrate(conn)
    return conn


def ambient_conn() -> Optional[_AmbientConn]:
    return getattr(_ambient, "conn", None)


def _connect() -> sqlite3.Connection:
    a = ambient_conn()
    if a is not None:
        return a  # type: ignore[return-value]
    return _real_connect()


from contextlib import contextmanager  # noqa: E402


@contextmanager
def batch_tx():
    """把一批写入放进同一个 SQLite 事务：期间 agent_protocol/agent_edr 的 _connect() 都返回同一连接。

    锁顺序固定为 agent_edr._lock → agent_protocol._lock，与现有 edr→protocol 调用链一致。
    yield 真实连接，供调用方做 SAVEPOINT 与回执写入；正常退出统一提交，异常整体回滚。
    """
    from . import agent_edr
    with agent_edr._lock, _lock:
        if ambient_conn() is not None:
            raise RuntimeError("batch_tx 不可嵌套")
        conn = _real_connect()
        conn.execute("BEGIN IMMEDIATE")
        _ambient.conn = _AmbientConn(conn)
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            _ambient.conn = None
            conn.close()


def ensure_db() -> Path:
    with _lock:
        conn = _connect()
        conn.close()
    return db_path()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def get_or_create_enroll_key(*, rotate: bool = False) -> str:
    """平台统一接入密钥：安装包内嵌此 key，终端无需再填账号密码。"""
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            if not rotate:
                row = conn.execute(
                    "SELECT value FROM agent_meta WHERE key=?", (ENROLL_META_KEY,)
                ).fetchone()
                if row and str(row["value"] or "").strip():
                    return str(row["value"]).strip()
            key = secrets.token_urlsafe(32)
            conn.execute(
                """INSERT INTO agent_meta(key, value) VALUES(?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (ENROLL_META_KEY, key),
            )
            conn.commit()
            return key
        finally:
            conn.close()


def verify_enroll_key(token: str) -> bool:
    tok = str(token or "").strip()
    if not tok or len(tok) < 16:
        return False
    try:
        return secrets.compare_digest(tok, get_or_create_enroll_key())
    except Exception:
        return False


# ---- 每 Agent 独立凭据 ----
SECRET_PREFIX = "fa_"
SHARED_KEY_META = "allow_shared_key"


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _new_secret() -> str:
    return SECRET_PREFIX + secrets.token_urlsafe(32)


def agent_auth_state(agent_id: str) -> Dict[str, Any]:
    aid = str(agent_id or "").strip()
    if not aid:
        return {"exists": False, "has_secret": False, "revoked": False}
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT secret_hash, revoked FROM agents WHERE agent_id=?", (aid,)
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return {"exists": False, "has_secret": False, "revoked": False}
    return {
        "exists": True,
        "has_secret": bool(str(row["secret_hash"] or "")),
        "revoked": bool(row["revoked"]),
    }


def verify_agent_secret(agent_id: str, token: str) -> str:
    """返回 ok | revoked | bad。常量时间比较，仅比较哈希。"""
    aid = str(agent_id or "").strip()
    tok = str(token or "").strip()
    if not aid or not tok.startswith(SECRET_PREFIX):
        return "bad"
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT secret_hash, revoked FROM agents WHERE agent_id=?", (aid,)
            ).fetchone()
        finally:
            conn.close()
    if row is None:
        return "ok" if _restore_tombstoned_agent(aid, tok) else "bad"
    stored = str(row["secret_hash"] or "")
    ok = bool(stored) and secrets.compare_digest(stored, _hash_secret(tok))
    if not ok:
        return "bad"
    return "revoked" if row["revoked"] else "ok"


def _restore_tombstoned_agent(agent_id: str, token: str) -> bool:
    """被删除但仍在运行的终端带原凭据回连：校验哈希后恢复注册记录（历史数据不恢复）。"""
    with _lock:
        conn = _connect()
        try:
            try:
                tomb = conn.execute(
                    "SELECT hostname, secret_hash FROM agent_tombstones WHERE agent_id=?", (agent_id,)
                ).fetchone()
            except sqlite3.Error:
                return False
            stored = str(tomb["secret_hash"] or "") if tomb else ""
            if not stored or not secrets.compare_digest(stored, _hash_secret(token)):
                return False
            now = _now()
            conn.execute(
                """INSERT OR IGNORE INTO agents(agent_id, hostname, last_seen, status, meta_json, secret_hash, secret_issued_at)
                   VALUES(?,?,?, 'online', ?, ?, ?)""",
                (agent_id, str(tomb["hostname"] or ""), now,
                 json.dumps({"registered": now, "restored": True}, ensure_ascii=False), stored, now),
            )
            conn.execute("DELETE FROM agent_tombstones WHERE agent_id=?", (agent_id,))
            conn.commit()
        finally:
            conn.close()
    try:
        from . import agent_edr
        agent_edr._audit("agent_auto_restore", agent_id=agent_id, detail="已删除终端凭原凭据回连，自动恢复注册")
    except Exception:
        pass
    bump_live("agent", agent_id=agent_id)
    return True


def issue_agent_secret(agent_id: str, *, conn: Optional[sqlite3.Connection] = None) -> str:
    """签发（或轮换）凭据，明文只返回这一次，库里只存 SHA256。"""
    aid = str(agent_id or "").strip()
    secret = _new_secret()
    sql = "UPDATE agents SET secret_hash=?, secret_issued_at=?, secret_rev=COALESCE(secret_rev,0)+1 WHERE agent_id=?"
    args = (_hash_secret(secret), _now(), aid)
    if conn is not None:
        conn.execute(sql, args)
        return secret
    ensure_db()
    with _lock:
        c = _connect()
        try:
            c.execute(sql, args)
            c.commit()
        finally:
            c.close()
    return secret


def rotate_agent_secret(agent_id: str) -> Dict[str, Any]:
    st = agent_auth_state(agent_id)
    if not st["exists"]:
        return {"ok": False, "error": "Agent 不存在"}
    if st["revoked"]:
        return {"ok": False, "error": "Agent 已吊销"}
    secret = issue_agent_secret(agent_id)
    bump_live("credential", agent_id=agent_id)
    return {"ok": True, "agent_secret": secret}


def set_agent_revoked(agent_id: str, revoked: bool) -> Dict[str, Any]:
    aid = str(agent_id or "").strip()
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("UPDATE agents SET revoked=? WHERE agent_id=?", (1 if revoked else 0, aid))
            if revoked:
                # 吊销时同时作废凭据，恢复后需重新注册换取新凭据
                conn.execute("UPDATE agents SET secret_hash='' WHERE agent_id=?", (aid,))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "Agent 不存在"}
        finally:
            conn.close()
    bump_live("credential", agent_id=aid)
    return {"ok": True, "agent_id": aid, "revoked": bool(revoked)}


def shared_key_allowed() -> bool:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT value FROM agent_meta WHERE key=?", (SHARED_KEY_META,)).fetchone()
        finally:
            conn.close()
    return not (row and str(row["value"]).strip() == "0")


def set_shared_key_allowed(allowed: bool) -> None:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_meta(key, value) VALUES(?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (SHARED_KEY_META, "1" if allowed else "0"),
            )
            conn.commit()
        finally:
            conn.close()


def credential_summary() -> Dict[str, Any]:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            r = conn.execute(
                """SELECT COUNT(*) AS total,
                          SUM(CASE WHEN secret_hash<>'' THEN 1 ELSE 0 END) AS with_secret,
                          SUM(CASE WHEN revoked=1 THEN 1 ELSE 0 END) AS revoked
                   FROM agents"""
            ).fetchone()
        finally:
            conn.close()
    return {
        "total": int(r["total"] or 0),
        "with_secret": int(r["with_secret"] or 0),
        "revoked": int(r["revoked"] or 0),
        "allow_shared_key": shared_key_allowed(),
    }












def protocol_info() -> Dict[str, Any]:
    return {
        "ok": True,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_min": SERVER_PROTOCOL_MIN,
        "protocol_max": SERVER_PROTOCOL_MAX,
        "capabilities": list(SERVER_CAPABILITIES),
        "schema_version": SCHEMA_VERSION,
        "modules": list(AGENT_MODULES),
        "intervals_sec": dict(MODULE_INTERVAL_SEC),
        "has_binary": agent_binary_path() is not None,
        "endpoints": {
            "register": "POST /api/agent/register",
            "heartbeat": "POST /api/agent/heartbeat",
            "snapshot": "POST /api/agent/snapshot",
            "list": "GET /api/agent/list",
            "install_package": "GET /api/agent/install-package",
        },
        "notes": [
            "管理端下载安装包（已内嵌平台地址与接入密钥），目标机管理员运行 install.bat 即可。",
            "服务名 ForensicAgent：开机自启，心跳 + 按模块实时 snapshot。",
            "snapshot 只传精简 JSON，禁止整盘 files；完整取证仍用离线 pack。",
        ],
    }


def register_agent(payload: Dict[str, Any], *, cred: str = "user") -> Dict[str, Any]:
    """cred: enroll=共享接入密钥 | secret=每 Agent 凭据 | user=管理台会话。

    仅当 Agent 声明 auth.agent_secret 能力且是 enroll 注册时才签发新凭据，旧 Agent 不受影响。
    """
    ensure_db()
    hostname = str(payload.get("hostname") or "").strip()[:128]
    os_family = str(payload.get("os_family") or "").strip().lower()[:32]
    ip = str(payload.get("ip") or "").strip()[:64]
    version = str(payload.get("version") or "").strip()[:64]
    agent_id = str(payload.get("agent_id") or "").strip()
    now = _now()
    neg = negotiate_protocol(payload)
    build_id = str(payload.get("build_id") or "").strip()[:64]
    source_rev = str(payload.get("source_rev") or "").strip()[:32]
    build_time = str(payload.get("build_time") or "").strip()[:40]
    with _lock:
        conn = _connect()
        try:
            # 主机名仅作展示，不作身份依据：无 agent_id 时签发全新身份，
            # 避免同名机器串档；同一台覆盖安装须携带原 agent_id 与凭据。
            if not agent_id:
                agent_id = uuid.uuid4().hex
            prev = conn.execute("SELECT revoked, secret_hash FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if prev and prev["secret_hash"] and cred == "enroll":
                return {"ok": False, "error": "Existing agent requires its enrolled credential"}
            if prev and prev["revoked"]:
                return {"ok": False, "error": "该 Agent 已被吊销，请管理员恢复或删除记录后重新安装"}
            conn.execute(
                """INSERT INTO agents(agent_id, hostname, os_family, ip, version, last_seen, status, meta_json)
                   VALUES(?,?,?,?,?,?, 'offline', ?)
                   ON CONFLICT(agent_id) DO UPDATE SET
                     hostname=excluded.hostname,
                     os_family=excluded.os_family,
                     ip=excluded.ip,
                     version=excluded.version,
                     last_seen=excluded.last_seen,
                     status='offline',
                     last_heartbeat_at=''""",
                (agent_id, hostname, os_family, ip, version, now, json.dumps({"registered": now}, ensure_ascii=False)),
            )
            conn.execute(
                """UPDATE agents SET build_id=?, source_rev=?, build_time=?,
                       proto_min=?, proto_max=?, proto_selected=?, capabilities_json=?
                   WHERE agent_id=?""",
                (build_id, source_rev, build_time, neg["agent_min"], neg["agent_max"],
                 neg["selected"], json.dumps(neg["enabled_caps"], ensure_ascii=False), agent_id),
            )
            new_secret = ""
            if cred == "enroll" and "auth.agent_secret" in neg["enabled_caps"]:
                new_secret = issue_agent_secret(agent_id, conn=conn)
            conn.commit()
        finally:
            conn.close()
    bump_live("register", agent_id=agent_id)
    try:
        from . import agent_store
        agent_store.write_agent({
            "agent_id": agent_id,
            "hostname": hostname,
            "os_family": os_family,
            "ip": ip,
            "version": version,
            "status": "offline",
            "last_seen": now,
            "capabilities_json": neg.get("enabled_caps") or [],
            "updated_at": now,
        })
    except Exception:
        pass
    return {
        "ok": True,
        "agent_id": agent_id,
        **({"agent_secret": new_secret} if new_secret else {}),
        "protocol_version": PROTOCOL_VERSION,
        "protocol_selected": neg["selected"],
        "protocol_warning": neg.get("warning", ""),
        "server_capabilities": list(SERVER_CAPABILITIES),
        "enabled_capabilities": neg["enabled_caps"],
        "modules": list(AGENT_MODULES),
        "intervals_sec": dict(MODULE_INTERVAL_SEC),
        "live_rev": live_revision(),
    }


def _host_meta_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    health = payload.get("health")
    if isinstance(health, dict):
        h = health.get("host")
        if isinstance(h, dict):
            return dict(h)
    top = payload.get("host")
    if isinstance(top, dict):
        return dict(top)
    return {}


def bounded_health_json(health: Dict[str, Any], limit: int = 60000) -> str:
    """Keep a valid object; drop whole optional sections rather than slicing JSON."""
    data = dict(health)
    def encode():
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    raw = encode()
    if len(raw.encode("utf-8")) <= limit:
        return raw
    required = {"capture_quality", "fim_root_health", "inventory_quality", "memory_scan_quality", "loop_quality",
                "cpu_pct", "rss_mb", "outbox", "heartbeat_period_sec", "fleet_report"}
    candidates = sorted(data, key=lambda key: (key in required, -len(json.dumps(data[key], ensure_ascii=False))))
    omitted = []
    for key in candidates:
        data.pop(key, None)
        omitted.append(key)
        data["health_truncated"] = True
        data["health_omitted_sections"] = omitted
        raw = encode()
        if len(raw.encode("utf-8")) <= limit:
            return raw
    return '{"health_truncated":true}'


def _store_health(conn: sqlite3.Connection, agent_id: str, payload: Dict[str, Any], now: str) -> None:
    """保存 Agent 自报健康（CPU/内存/spool/传感器），并按 agent_ts 估算时钟偏差。"""
    health = payload.get("health")
    if not isinstance(health, dict):
        health = {}
    fleet = {
        "policy_applied": bool(payload.get("policy_applied")),
        "local_sync_rev": int(payload.get("local_sync_rev") or 0),
        "local_policy_rev": int(payload.get("local_policy_rev") or 0),
    }
    if isinstance(health.get("fleet"), dict):
        fleet.update({k: health["fleet"][k] for k in health["fleet"] if k in (
            "server_sync_rev", "server_policy_rev", "fleet_state", "fleet_message",
        )})
    health = {**health, "fleet_report": fleet}
    skew = 0.0
    ats = str(payload.get("agent_ts") or "")
    try:
        skew = round(time.time() - float(ats), 1) if ats.replace(".", "", 1).isdigit() else 0.0
    except Exception:
        skew = 0.0
    blob = bounded_health_json(health)
    conn.execute(
        "UPDATE agents SET health_json=?, health_at=?, clock_skew_sec=? WHERE agent_id=?",
        (blob, now, skew, agent_id),
    )


def heartbeat(payload: Dict[str, Any]) -> Dict[str, Any]:
    ensure_db()
    agent_id = str(payload.get("agent_id") or "").strip()
    if not agent_id:
        return {"ok": False, "error": "缺少 agent_id"}
    now = _now()
    acked_ids: List[str] = []
    acks = payload.get("command_acks")
    if isinstance(acks, list):
        try:
            from . import agent_edr
            for item in acks[:20]:
                if not isinstance(item, dict):
                    continue
                cid = str(item.get("id") or "").strip()
                if not cid:
                    continue
                ok = bool(item.get("ok"))
                result = item.get("result") if isinstance(item.get("result"), dict) else {}
                r = agent_edr.ack_command(cid, ok=ok, result=result, caller_agent_id=agent_id)
                if r.get("ok"):
                    acked_ids.append(cid)
        except Exception as e:
            print("[agent] heartbeat command_acks:", e)
    hb_row = None
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "UPDATE agents SET last_seen=?, last_heartbeat_at=?, status='online', ip=COALESCE(NULLIF(?, ''), ip) WHERE agent_id=?",
                (now, now, str(payload.get("ip") or "").strip()[:64], agent_id),
            )
            if cur.rowcount > 0:
                _store_health(conn, agent_id, payload, now)
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "未知 agent，请先 register"}
            hb_row = conn.execute(
                "SELECT hostname, os_family, ip, version, health_json, capabilities_json FROM agents WHERE agent_id=?",
                (agent_id,),
            ).fetchone()
        finally:
            conn.close()
    try:
        from . import agent_store
        payload_health = payload.get("health") if isinstance(payload.get("health"), dict) else None
        agent_store.write_agent({
            "agent_id": agent_id,
            "hostname": (hb_row["hostname"] if hb_row else "") or "",
            "os_family": (hb_row["os_family"] if hb_row else "") or "",
            "ip": str(payload.get("ip") or (hb_row["ip"] if hb_row else "") or "")[:64],
            "version": (hb_row["version"] if hb_row else "") or "",
            "status": "online",
            "last_seen": now,
            "health_json": payload_health if payload_health is not None else ((hb_row["health_json"] if hb_row else "") or ""),
            "health_at": now if payload_health is not None else "",
            "capabilities_json": (hb_row["capabilities_json"] if hb_row else "") or "",
            "updated_at": now,
        })
    except Exception:
        pass
    out: Dict[str, Any] = {
        "ok": True,
        "server_time": now,
        # 热更新采集周期，无需重装 Agent
        "intervals_sec": dict(MODULE_INTERVAL_SEC),
        "heartbeat_sec": 3,
        "live_rev": live_revision(),
        "commands": [],
        "policy": {},
        "policy_rev": 0,
        "whitelist": [],
        "sync_rev": 0,
        "policy_applied": False,
        "acked_command_ids": acked_ids,
    }
    try:
        from . import agent_sync
        out["sync_rev"] = agent_sync.sync_revision()
        out["sync_manifest"] = agent_sync.manifest().get("parts")
    except Exception:
        pass
    try:
        from . import agent_edr
        bundle = agent_edr.agent_side_bundle(agent_id, host_meta=_host_meta_from_payload(payload))
        out.update(bundle)
        pol = bundle.get("policy") or {}
        if isinstance(pol.get("intervals_sec"), dict):
            out["intervals_sec"] = {**MODULE_INTERVAL_SEC, **pol["intervals_sec"]}
        if isinstance(pol.get("heartbeat_sec"), int) and 3 <= pol["heartbeat_sec"] <= 120:
            out["heartbeat_sec"] = int(pol["heartbeat_sec"])
        # bundle 在有待执行命令时会覆盖为 3 秒
        if isinstance(bundle.get("heartbeat_sec"), int) and 3 <= bundle["heartbeat_sec"] <= 120:
            out["heartbeat_sec"] = int(bundle["heartbeat_sec"])
        if bundle.get("commands"):
            out["heartbeat_sec"] = 3
    except Exception as e:
        print("[agent_edr] heartbeat bundle:", e)
    srv_sync = int(out.get("sync_rev") or 0)
    local_sync = int(payload.get("local_sync_rev") or 0)
    agent_pa = bool(payload.get("policy_applied"))
    out["policy_applied"] = agent_pa and (srv_sync <= 0 or local_sync >= srv_sync)
    out["server_policy_rev"] = int(out.get("policy_rev") or 0)
    out["server_sync_rev"] = srv_sync
    # 策略对账：消费 Agent 自报的 applied-rev/status，检测漂移并记录。
    # 仅做检测+审计+状态暴露；策略下发仍走心跳拉取式，不主动推送。
    try:
        from . import policy_reconcile as recon
        rec = recon.evaluate(
            payload,
            server_policy_rev=int(out.get("policy_rev") or 0),
            server_sync_rev=srv_sync,
            policy_applied=bool(out.get("policy_applied")),
        )
        out["policy_reconcile"] = rec
        if rec.get("state") in ("rejected", "rolled_back", "behind"):
            with _lock:
                rc = _connect()
                try:
                    recon.maybe_audit(rc, agent_id, rec)
                    rc.commit()
                finally:
                    rc.close()
    except Exception as e:
        print("[policy_reconcile] heartbeat:", e)
    # The effective period is a server policy value, bounded to the supported range.
    # Preserve the previous longer period when the agent reports it still in use.
    reported = payload.get("health") or {}
    actual = reported.get("heartbeat_period_sec") if isinstance(reported, dict) else None
    period = max(normalize_heartbeat_period(actual), normalize_heartbeat_period(out.get("heartbeat_sec")))
    with _lock:
        conn = _connect()
        try:
            conn.execute("UPDATE agents SET heartbeat_period_sec=? WHERE agent_id=?", (period, agent_id))
            conn.commit()
        finally:
            conn.close()
    bump_live_heartbeat(agent_id)
    return out


def normalize_heartbeat_period(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and 3 <= value <= 120:
        return value
    return 3


def heartbeat_online_window(value: Any) -> int:
    return max(45, 2 * normalize_heartbeat_period(value) + 15)


def is_agent_online(last_seen: Any, period: Any, *, now: Optional[float] = None, revoked: bool = False) -> bool:
    if revoked:
        return False
    try:
        ts = time.mktime(time.strptime(str(last_seen), "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError, OverflowError):
        return False
    age = (time.time() if now is None else now) - ts
    return 0 <= age <= heartbeat_online_window(period)


def mark_telemetry_received(conn: Any, agent_id: str, now: str) -> None:
    conn.execute("UPDATE agents SET last_telemetry_at=? WHERE agent_id=?", (now, agent_id))


def list_agents(*, online_within_sec: int = 45, offset: Optional[int] = None,
                limit: Optional[int] = None, online: Optional[bool] = None,
                include_health: bool = True) -> Dict[str, Any]:
    ensure_db()
    # 默认心跳 3s，超过约 15s 无上报视为离线（调用方可传更大窗口）
    online_within_sec = max(12, min(int(online_within_sec or 15), 3600))
    now_ts = time.time()
    try:
        from . import agent_release
        rel = agent_release.release_status()
    except Exception:
        agent_release, rel = None, {}
    with _lock:
        conn = _connect()
        try:
            paged = offset is not None or limit is not None or online is not None or not include_health
            total = None
            if paged:
                start, size = 0 if offset is None else offset, 100 if limit is None else limit
                if type(start) is not int or type(size) is not int or start < 0 or not 1 <= size <= 500:
                    return {"ok": False, "error": "agent_page_invalid"}
                # Use the same heartbeat predicate as the legacy list, including local time parsing.
                conn.create_function("agent_is_online", 3, lambda stamp, period, revoked:
                    int(is_agent_online(stamp, period, now=now_ts, revoked=bool(revoked))))
                where, args = (" WHERE agent_is_online(last_heartbeat_at,heartbeat_period_sec,revoked)=?", (int(online),)) if online is not None else ("", ())
                total = conn.execute("SELECT COUNT(*) FROM agents" + where, args).fetchone()[0]
                columns = "*" if include_health else ",".join('"' + row[1].replace('"', '""') + '"' for row in conn.execute("PRAGMA table_info(agents)") if row[1] != "health_json")
                rows = conn.execute("SELECT " + columns + " FROM agents" + where + " ORDER BY last_seen DESC, agent_id ASC LIMIT ? OFFSET ?", (*args, size, start)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC, agent_id ASC").fetchall()
            items = []
            for r in rows:
                d = dict(r)
                try:
                    d["capabilities"] = json.loads(d.pop("capabilities_json", "") or "[]")
                except Exception:
                    d["capabilities"] = []
                try:
                    d["health"] = json.loads(d.pop("health_json", "") or "{}")
                except Exception:
                    d["health"] = {}
                d["has_secret"] = bool(d.pop("secret_hash", ""))  # 绝不外泄哈希
                d["revoked"] = bool(d.get("revoked"))
                d["outdated"] = bool(agent_release and rel.get("build_id") and agent_release.agent_outdated(d, rel))
                period = normalize_heartbeat_period(d.get("heartbeat_period_sec"))
                online = is_agent_online(d.get("last_heartbeat_at"), period, now=now_ts, revoked=d["revoked"])
                d["heartbeat_period_sec"] = period
                d["online_window_sec"] = heartbeat_online_window(period)
                d["telemetry_received"] = bool(d.get("last_telemetry_at"))
                d["online"] = online
                d["status"] = "online" if online else "offline"
                items.append(d)
            release = {k: rel.get(k) for k in (
                "status", "is_latest", "version", "build_id", "build_time", "exe_sha256",
            )} if rel else {}
            if not include_health:
                for item in items:
                    item.pop("health", None)
            result = {"ok": True, "items": items, "online_within_sec": online_within_sec,
                      "online_policy": "per_agent_heartbeat_period", "release": release}
            if paged:
                result["page"] = {"total": total, "offset": start, "limit": size,
                                  "next_offset": start + size if start + size < total else None}
            return result
        finally:
            conn.close()


def get_snapshot(agent_id: str, module: str, *, offset: Optional[int] = None,
                 limit: Optional[int] = None, snapshot_version: Optional[str] = None) -> Dict[str, Any]:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM agent_snapshots WHERE agent_id=? AND module=?",
                (str(agent_id), str(module).lower()),
            ).fetchone()
            if not row:
                return {"ok": False, "error": "无快照"}
            d = dict(row)
            paged = offset is not None or limit is not None or snapshot_version is not None
            raw = d.pop("payload_json") or "[]"
            try:
                d["items"] = json.loads(raw)
            except Exception:
                if paged:
                    return {"ok": False, "error": "snapshot_data_invalid"}
                d["items"] = []
            if paged:
                import hashlib
                if not isinstance(d["items"], list) or len(d["items"]) != d["item_count"]:
                    return {"ok": False, "error": "snapshot_data_invalid"}
                start, size = 0 if offset is None else offset, 100 if limit is None else limit
                if type(start) is not int or type(size) is not int or start < 0 or not 1 <= size <= 500:
                    return {"ok": False, "error": "snapshot_page_invalid"}
                version = hashlib.sha256(f'{d.get("generation", 0)}\n{d.get("collected_at", "")}\n{raw}'.encode('utf-8')).hexdigest()
                if snapshot_version is not None and snapshot_version != version:
                    return {"ok": False, "error": "snapshot_version_changed"}
                total = len(d["items"])
                d["items"] = d["items"][start:start + size]
                d.pop("keys_json", None)
                return {"ok": True, "item": d, "page": {"offset": start, "limit": size, "total": total,
                    "next_offset": start + size if start + size < total else None, "snapshot_version": version}}
            return {"ok": True, "item": d}
        finally:
            conn.close()


def delete_agent(agent_id: str) -> Dict[str, Any]:
    ensure_db()
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    with _lock:
        conn = _connect()
        try:
            prev = conn.execute(
                "SELECT hostname, secret_hash, revoked FROM agents WHERE agent_id=?", (aid,)
            ).fetchone()
            if prev and str(prev["secret_hash"] or "") and not prev["revoked"]:
                conn.execute(
                    """INSERT INTO agent_tombstones(agent_id, hostname, secret_hash, deleted_at) VALUES(?,?,?,?)
                       ON CONFLICT(agent_id) DO UPDATE SET hostname=excluded.hostname,
                         secret_hash=excluded.secret_hash, deleted_at=excluded.deleted_at""",
                    (aid, str(prev["hostname"] or ""), str(prev["secret_hash"]), _now()),
                )
            cur = conn.execute("DELETE FROM agents WHERE agent_id=?", (aid,))
            deleted = cur.rowcount > 0
            if deleted:
                conn.execute("DELETE FROM agent_snapshots WHERE agent_id=?", (aid,))
                conn.execute("DELETE FROM agent_events WHERE agent_id=?", (aid,))
                conn.execute("DELETE FROM agent_receipts WHERE agent_id=?", (aid,))
                conn.execute("DELETE FROM agent_streams WHERE agent_id=?", (aid,))
            conn.commit()
        finally:
            conn.close()
    # 时间线 / 指令 / 标签在 edr 扩展库，一并清掉，避免「主机删了告警还在」
    try:
        from . import agent_edr
        agent_edr.purge_agent_data(aid)
    except Exception:
        pass
    if not deleted:
        return {"ok": False, "error": "主机不存在"}
    bump_live("agent_deleted", agent_id=aid)
    return {"ok": True, "deleted": aid}


def _host_of(agent_id: str) -> str:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT hostname FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            return str(row["hostname"] if row else "") or ""
        finally:
            conn.close()












_REMOTE_OPS_ACTIONS = frozenset({
    "reg_read", "fs_list", "fs_stat", "fs_read", "fs_volumes", "run_cmd",
    "shell_open", "shell_write", "shell_poll", "shell_close",
})


def _suppress_response_ops_event(module: str, title: str) -> bool:
    """远程运维/只读指令的结果不写威胁事件（见 Agent 指令记录）。"""
    if str(module or "").strip().lower() != "response":
        return False
    t = str(title or "").strip()
    for prefix in ("处置成功：", "处置失败：", "远程运维失败："):
        if not t.startswith(prefix):
            continue
        act = t[len(prefix):].strip().lower()
        if act in _REMOTE_OPS_ACTIONS:
            return True
        if prefix == "处置成功：" and act == "refresh_modules":
            return True
    return False


_REMOTE_OPS_NOISE_PREFIXES = (
    "处置成功：fs_list", "处置成功：fs_stat", "处置成功：fs_read", "处置成功：fs_volumes",
    "处置成功：reg_read", "处置成功：run_cmd",
    "处置成功：shell_open", "处置成功：shell_write", "处置成功：shell_poll", "处置成功：shell_close",
    "处置失败：fs_volumes",
)


def _is_remote_ops_noise(title: str) -> bool:
    t = str(title or "").strip()
    return any(t == p or t.startswith(p) for p in _REMOTE_OPS_NOISE_PREFIXES)


def _event_payload_key(detail: Any) -> str:
    """从告警 detail 提取可合并键：任务/快捷方式/服务真实载荷路径。"""
    import json as _json
    d: Any = detail
    if isinstance(d, str) and d.strip():
        try:
            d = _json.loads(d)
        except Exception:
            return ""
    if not isinstance(d, dict):
        return ""
    for k in (
        "task_execute", "payload_path", "shortcut_target", "service_exe",
        "local_path", "image", "matched",
    ):
        v = str(d.get(k) or "").strip().lower()
        if v and (":\\" in v or v.startswith("\\\\") or v.endswith((".exe", ".dll", ".bat", ".ps1", ".cmd", ".scr"))):
            return v.replace("/", "\\")
    return ""




_QUIET_AT = 0.0


def _quiet_open_alerts(conn: sqlite3.Connection) -> int:
    """已加白的未处置告警、以及远程运维成功回执，不再留在威胁列表。"""
    global _QUIET_AT
    now_ts = time.time()
    if now_ts - _QUIET_AT < 15:
        return 0
    _QUIET_AT = now_ts
    now = _now()
    cur = conn.execute(
        """UPDATE agent_events SET status='ignored', updated_at=?
           WHERE status='open' AND (
             title LIKE '处置成功：fs_%' OR title LIKE '处置成功：reg_read%'
             OR title LIKE '处置成功：run_cmd%' OR title LIKE '处置成功：shell_%'
             OR title LIKE '处置失败：fs_volumes%'
           )""",
        (now,),
    )
    n = int(cur.rowcount or 0)
    try:
        from . import alert_allow
        n += alert_allow.apply_all_enabled(conn)
    except Exception:
        pass
    if n:
        conn.commit()
    return n




def _event_detail_obj_light(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """列表接口用：只解析 JSON，不做时间线回填（回填留给 get_event）。"""
    raw = item.get("detail") or ""
    if not str(raw).lstrip().startswith("{"):
        return None
    try:
        d = json.loads(raw)
    except Exception:
        return None
    return d if isinstance(d, dict) else None


def list_events(
    *,
    status: str = "",
    agent_id: str = "",
    limit: int = 100,
    severity: str = "",
    module: str = "",
    start_at: str = "",
    end_at: str = "",
    before_id: Optional[int] = None,
    anchor_id: Optional[int] = None,
) -> Dict[str, Any]:
    ensure_db()
    limit = max(1, min(int(limit or 100), 500))
    clauses = []
    args: List[Any] = []
    st = str(status or "").strip().lower()
    if st and st not in ("open", "closed", "ignored"):
        return {"ok": False, "error": "invalid_event_status"}
    if st in ("open", "closed", "ignored"):
        clauses.append("status=?")
        args.append(st)
    aid = str(agent_id or "").strip()
    if aid:
        clauses.append("agent_id=?")
        args.append(aid)
    for column, value in (("severity", severity), ("module", module)):
        if value:
            clauses.append(column + "=?")
            args.append(str(value).strip().lower())
    for stamp in (start_at, end_at):
        if stamp:
            try:
                parsed = time.strptime(stamp, "%Y-%m-%dT%H:%M:%S")
                if time.strftime("%Y-%m-%dT%H:%M:%S", parsed) != stamp:
                    raise ValueError
            except (ValueError, TypeError):
                return {"ok": False, "error": "invalid_event_time_range"}
    if start_at and end_at and start_at >= end_at:
        return {"ok": False, "error": "invalid_event_time_range"}
    if start_at:
        clauses.append("created_at>=?")
        args.append(start_at)
    if end_at:
        clauses.append("created_at<?")
        args.append(end_at)
    with _lock:
        conn = _connect()
        try:
            _quiet_open_alerts(conn)
            if anchor_id is None:
                anchor_id = int(conn.execute("SELECT COALESCE(MAX(id),0) FROM agent_events").fetchone()[0])
            clauses.append("id<=?")
            args.append(anchor_id)
            where = " WHERE " + " AND ".join(clauses)
            total = conn.execute("SELECT COUNT(*) FROM agent_events" + where, args).fetchone()[0]
            if before_id is not None:
                where += " AND id<?"
                args.append(before_id)
            rows = conn.execute(
                f"""SELECT id, agent_id, hostname, severity, title, detail, module, status,
                           hit_count, created_at, updated_at
                    FROM agent_events{where} ORDER BY id DESC LIMIT ?""",
                (*args, limit + 1),
            ).fetchall()
            items = []
            for r in rows[:limit]:
                it = dict(r)
                obj = _event_detail_obj_light(it)
                if obj is not None:
                    it["detail_obj"] = obj
                items.append(it)
            open_n = conn.execute("SELECT COUNT(*) AS c FROM agent_events WHERE status='open'").fetchone()["c"]
            return {"ok": True, "items": items, "open_count": int(open_n or 0), "total": int(total),
                    "anchor_id": anchor_id, "next_before_id": items[-1]["id"] if len(rows) > limit and items else None}
        finally:
            conn.close()


def update_event(event_id: int, *, status: str = "") -> Dict[str, Any]:
    ensure_db()
    st = str(status or "").strip().lower()
    if st not in ("open", "closed", "ignored"):
        return {"ok": False, "error": "status 无效"}
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "UPDATE agent_events SET status=?, updated_at=? WHERE id=?",
                (st, _now(), int(event_id)),
            )
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "事件不存在"}
            return {"ok": True}
        finally:
            conn.close()


def delete_event(event_id: int) -> Dict[str, Any]:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            _mark_deleted(conn, "id=?", [int(event_id)])
            cur = conn.execute("DELETE FROM agent_events WHERE id=?", (int(event_id),))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "事件不存在"}
            return {"ok": True, "deleted": int(event_id)}
        finally:
            conn.close()


def delete_events(*, status: str = "", agent_id: str = "", severity: str = "") -> Dict[str, Any]:
    """按筛选条件批量删除告警（不带条件即全部）。"""
    ensure_db()
    clauses, args = [], []
    st = str(status or "").strip().lower()
    if st in ("open", "closed", "ignored"):
        clauses.append("status=?")
        args.append(st)
    if agent_id:
        clauses.append("agent_id=?")
        args.append(str(agent_id))
    sev = str(severity or "").strip().lower()
    if sev in ("info", "low", "medium", "high", "critical"):
        clauses.append("lower(severity)=?")
        args.append(sev)
    where = " AND ".join(clauses) or "1=1"
    with _lock:
        conn = _connect()
        try:
            _mark_deleted(conn, where, args)
            cur = conn.execute(f"DELETE FROM agent_events WHERE {where}", args)
            conn.commit()
            n = int(cur.rowcount or 0)
        finally:
            conn.close()
    bump_live("event")
    return {"ok": True, "deleted": n}


def _mark_deleted(conn: sqlite3.Connection, where: str, args: List[Any]) -> None:
    conn.execute(
        f"""INSERT INTO agent_event_deletions(agent_id, title, deleted_at)
            SELECT agent_id, title, ? FROM agent_events WHERE {where}
            ON CONFLICT(agent_id, title) DO UPDATE SET deleted_at=excluded.deleted_at""",
        (_now(), *args),
    )


def _repair_event_detail(conn: sqlite3.Connection, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    title = str(item.get("title") or "")
    aid = str(item.get("agent_id") or "")
    if not title or not aid:
        return None
    raw = item.get("detail") or ""
    try:
        cur = json.loads(raw) if str(raw).lstrip().startswith("{") else {}
    except ValueError:
        cur = {}
    if not isinstance(cur, dict):
        cur = {}
    try:
        from . import event_detail_enrich as ede
        out, changed = ede.enrich_detail_from_timeline(
            conn, agent_id=aid, title=title, detail=cur,
            created_at=str(item.get("created_at") or ""),
        )
        if changed:
            detail_s = fit_detail(out)
            conn.execute(
                "UPDATE agent_events SET detail=?, updated_at=? WHERE id=?",
                (detail_s, _now(), int(item["id"])),
            )
            conn.commit()
            return out
    except Exception:
        pass
    try:
        tl = conn.execute(
            """SELECT etype, detail_json FROM agent_timeline
               WHERE agent_id=? AND summary=? ORDER BY id DESC LIMIT 1""",
            (aid, title),
        ).fetchone()
    except sqlite3.Error:
        return None
    if not tl:
        return None
    try:
        d = json.loads(tl["detail_json"] or "{}")
    except Exception:
        return None
    if not isinstance(d, dict) or not d:
        return None
    out = {"etype": tl["etype"] or ""}
    out.update(d)
    try:
        conn.execute(
            "UPDATE agent_events SET detail=? WHERE id=?",
            (fit_detail(out), int(item["id"])),
        )
        conn.commit()
    except sqlite3.Error:
        pass
    return out


def enrich_event_details(*, limit: int = 500) -> Dict[str, Any]:
    """从时间线回填缺详情的威胁事件（PTM/EVM/SCA 等）。"""
    ensure_db()
    from . import event_detail_enrich as ede
    with _lock:
        conn = _connect()
        try:
            return ede.backfill_agent_events(conn, limit=limit, write=True)
        finally:
            conn.close()


def _event_detail_obj(conn: sqlite3.Connection, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = item.get("detail") or ""
    if not str(raw).lstrip().startswith("{"):
        return None
    try:
        d = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    try:
        from . import event_detail_enrich as ede
        out, _ = ede.enrich_detail_from_timeline(
            conn,
            agent_id=str(item.get("agent_id") or ""),
            title=str(item.get("title") or ""),
            detail=d,
            created_at=str(item.get("created_at") or ""),
        )
        return out
    except Exception:
        return d


def repair_broken_event_details(limit: int = 500) -> int:
    ensure_db()
    fixed = 0
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """SELECT id, agent_id, title, detail FROM agent_events
                   WHERE detail LIKE '{%' AND detail NOT LIKE '%}' ORDER BY id DESC LIMIT ?""",
                (int(limit),),
            ).fetchall()
            for r in rows:
                if _repair_event_detail(conn, dict(r)) is not None:
                    fixed += 1
        finally:
            conn.close()
    return fixed


def get_event(event_id: int) -> Dict[str, Any]:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM agent_events WHERE id=?",
                (int(event_id),),
            ).fetchone()
            if not row:
                return {"ok": False, "error": "事件不存在"}
            item = dict(row)
            # 解析 detail JSON（规则命中证据）
            detail_obj = None
            raw = item.get("detail") or ""
            if raw.startswith("{"):
                try:
                    detail_obj = json.loads(raw)
                except Exception:
                    detail_obj = None
            # 旧版晋升时 detail 被截断成非法 JSON：按同主机同标题从时间线回填原始证据
            if not isinstance(detail_obj, dict) or len(detail_obj) <= 1:
                repaired = _repair_event_detail(conn, item)
                if repaired is not None:
                    detail_obj = repaired
                    item["detail"] = fit_detail(repaired)
            elif detail_obj and isinstance(detail_obj, dict):
                try:
                    from . import event_detail_enrich as ede
                    enriched, changed = ede.enrich_detail_from_timeline(
                        conn,
                        agent_id=str(item.get("agent_id") or ""),
                        title=str(item.get("title") or ""),
                        detail=detail_obj,
                        created_at=str(item.get("created_at") or ""),
                    )
                    if changed:
                        detail_obj = enriched
                    if changed:
                        item["detail"] = fit_detail(detail_obj)
                        conn.execute(
                            "UPDATE agent_events SET detail=?, updated_at=? WHERE id=?",
                            (item["detail"], _now(), int(event_id)),
                        )
                        conn.commit()
                except Exception:
                    pass
            item["detail_obj"] = detail_obj or _event_detail_obj(conn, item)
            return {"ok": True, "item": item}
        finally:
            conn.close()


def _blob_has_mojibake(text: str) -> bool:
    if not text:
        return False
    # UTF-8 替换符或连续问号菱形在 JSON 里常表现为 \ufffd
    return ("\ufffd" in text) or (text.count("?") >= 8 and "DisplayName" in text)






DELTA_MAX_ITEMS = 1000

from .agent_protocol_telemetry import report_event, _post_snapshot, upsert_snapshot, apply_snapshot_delta, related_events_by_payload
