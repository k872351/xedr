# -*- coding: utf-8 -*-
"""策略对账：消费 Agent 心跳自报的 applied-rev / status，发现漂移并记录。

背景：Agent 侧已完整上报策略状态（client.go 的 local_policy_rev / policy_applied，
health.policy 的 applied_rev/status/error），但服务端过去只计算一个布尔并存库，
没有消费这些字段。本模块补齐「下发闭环」的可观测与自愈依据：

- 对比 Agent 实际 applied_rev 与服务端期望 policy_rev；
- 识别 rejected / rolled_back / probation 等异常状态；
- 状态变化时写 agent_audit（带冷却，避免每个心跳刷屏）；
- 返回 reconcile 状态供 heartbeat 响应与管理端展示。

注意：策略下发本身是「心跳拉取式」——agent_side_bundle 每次心跳都返回当前
policy_rev，Agent 用 pm.offer() 自行判断应用。本模块**不主动推送**，只做
漂移检测 + 记录 + 状态暴露，因此不会与拉取机制冲突，也不破坏协议兼容。
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

# 状态变化时写审计的最小间隔（秒），防止异常 Agent 每 3 秒刷一条
_AUDIT_COOLDOWN_SEC = 120
# 进程内上次审计的状态缓存：{(agent_id): (state_signature, ts)}
_last_audit: Dict[str, tuple] = {}


def _status_from_health(payload: Dict[str, Any]) -> Dict[str, Any]:
    """从 health.policy 提取状态；兼容旧 Agent（无该字段）。"""
    health = payload.get("health")
    if not isinstance(health, dict):
        return {}
    pol = health.get("policy")
    return dict(pol) if isinstance(pol, dict) else {}


def evaluate(payload: Dict[str, Any], *, server_policy_rev: int,
             server_sync_rev: int, policy_applied: bool) -> Dict[str, Any]:
    """计算对账结论，纯函数，无副作用。

    返回：
      state: converged | behind | rejected | rolled_back | probation | unknown
      need_attention: 是否需要人工关注
      reason: 人类可读原因
    """
    pol = _status_from_health(payload)
    raw_status = str(pol.get("status") or "").strip().lower()
    applied_rev = int(pol.get("applied_rev") or payload.get("local_policy_rev") or 0)
    local_sync = int(payload.get("local_sync_rev") or 0)
    error = str(pol.get("error") or "").strip()

    # 异常状态优先（拒绝/回滚比单纯落后更需要关注）
    if raw_status == "rejected":
        return {"state": "rejected", "need_attention": True,
                "reason": error or "Agent 拒绝了策略（验签或字段校验失败）",
                "applied_rev": applied_rev, "server_policy_rev": server_policy_rev}
    if raw_status == "rolled_back":
        return {"state": "rolled_back", "need_attention": True,
                "reason": error or "Agent 已回滚到 LKG（试用失败或资源超限）",
                "applied_rev": applied_rev, "server_policy_rev": server_policy_rev}
    if raw_status == "probation":
        return {"state": "probation", "need_attention": False,
                "reason": "策略处于试用观察期",
                "applied_rev": applied_rev, "server_policy_rev": server_policy_rev}

    # 版本落后：applied_rev 低于服务端期望
    if server_policy_rev > 0 and 0 < applied_rev < server_policy_rev:
        return {"state": "behind", "need_attention": False,
                "reason": f"Agent 应用 rev {applied_rev}，服务端期望 rev {server_policy_rev}",
                "applied_rev": applied_rev, "server_policy_rev": server_policy_rev}

    # 同步版本落后（策略相同但规则/白名单/IOC 未同步）
    if server_sync_rev > 0 and local_sync and local_sync < server_sync_rev:
        return {"state": "behind", "need_attention": False,
                "reason": f"同步版本 {local_sync} 落后服务端 {server_sync_rev}",
                "applied_rev": applied_rev, "server_policy_rev": server_policy_rev}

    if applied_rev > 0 and server_policy_rev > 0 and applied_rev >= server_policy_rev and policy_applied:
        return {"state": "converged", "need_attention": False,
                "reason": "策略与同步已收敛",
                "applied_rev": applied_rev, "server_policy_rev": server_policy_rev}

    return {"state": "unknown", "need_attention": False,
            "reason": "策略状态证据不足（旧 Agent 或尚未应用）",
            "applied_rev": applied_rev, "server_policy_rev": server_policy_rev}


def maybe_audit(conn, agent_id: str, result: Dict[str, Any]) -> bool:
    """状态变化时写一条 agent_audit；带冷却。返回是否写入。"""
    state = str(result.get("state") or "unknown")
    # 不改变「需要关注」的正常收敛状态不写审计；异常与落后才记
    if state in ("converged", "unknown"):
        return False
    signature = f"{state}|{result.get('applied_rev')}|{result.get('server_policy_rev')}|{result.get('reason')}"
    prev = _last_audit.get(agent_id)
    now = time.time()
    if prev and prev[0] == signature and now - prev[1] < _AUDIT_COOLDOWN_SEC:
        return False
    try:
        detail = json.dumps({
            "state": state,
            "reason": result.get("reason") or "",
            "applied_rev": result.get("applied_rev"),
            "server_policy_rev": result.get("server_policy_rev"),
            "need_attention": bool(result.get("need_attention")),
        }, ensure_ascii=False)
        conn.execute(
            "INSERT INTO agent_audit(agent_id, action, detail, actor, created_at) VALUES(?,?,?,?,?)",
            (agent_id, "policy_reconcile", detail[:2000], "system",
             time.strftime("%Y-%m-%dT%H:%M:%S")),
        )
        _last_audit[agent_id] = (signature, now)
        return True
    except Exception:
        return False
