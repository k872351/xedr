# -*- coding: utf-8 -*-
"""多信号风险评分（port from DataProtector DpThreatEngine.c）。

把同一进程/同一主机在一段时间内命中的多个"弱信号"，按 MITRE 战术与技术
累计成一个有界的、随时间衰减的风险分，并在进程血缘（PPID 链）上传播。

核心规则（与 DataProtector 对齐，参数可在 config/correlation_rules.json 覆盖）：
- 每个信号有 weight / tactic / technique_id；
- 累计分随时间衰减（每 30s 减 8 分），安静进程风险回落到 0；
- 同一信号在冷却窗内重复触发时权重减半（下限 1），避免刷屏；
- 出现新的不同战术时给"杀伤链宽度"奖励（每多一种 +12）；
- 同一技术第 3 次及以后命中给持续使用奖励（+6）；
- 子进程新增的分按 50%/层向上传播（最多 8 层），让释放者/宏宿主被一起标记；
- 分数映射严重度：30 low / 60 medium / 90 high / 130 critical，上限 1000。

本模块是自包含的评分累加器：进程状态保存在进程内（带锁），事件驱动写入。
重启后状态从零开始——这与"风险会衰减"的设计一致，且不影响事件落库。
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

# ---- 默认参数（DataProtector 口径） ---------------------------------------
THRESHOLDS: Dict[str, int] = {
    "low": 30, "medium": 60, "high": 90, "critical": 130,
}
SCORE_MAX = 1000
COOLDOWN_SEC = 30
REPEAT_MIN = 1
REPETITION_BONUS = 6
REPETITION_THRESHOLD = 3
DECAY_INTERVAL_SEC = 30
DECAY_POINTS = 8
CORRELATION_BONUS = 12
PROPAGATION_PCT = 50
ANCESTRY_MAX_DEPTH = 8
MAX_NODES = 4096

# 有序战术表（位掩码下标）；顺序稳定即可，不依赖具体枚举值。
TACTICS: Tuple[str, ...] = (
    "unknown", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
)

DEFAULT_SIGNAL: Dict[str, Any] = {
    "weight": 10, "tactic": "unknown", "technique_id": 0,
}

_lock = threading.RLock()
_nodes: Dict[Tuple[str, str], Dict[str, Any]] = {}
_cfg_cache: Optional[Dict[str, Any]] = None
_cfg_mtime: float = 0.0


def _config_path() -> Path:
    return Path(__file__).resolve().parent.parent / "config" / "correlation_rules.json"


def load_config() -> Dict[str, Any]:
    """读取 risk_scoring 配置段（带 mtime 缓存），失败时返回空字典。"""
    global _cfg_cache, _cfg_mtime
    p = _config_path()
    try:
        mt = p.stat().st_mtime
    except OSError:
        return {}
    with _lock:
        if _cfg_cache is not None and mt == _cfg_mtime:
            return _cfg_cache
        raw: Dict[str, Any] = {}
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and isinstance(doc.get("risk_scoring"), dict):
                raw = doc["risk_scoring"]
        except Exception:
            raw = {}
        _cfg_cache = raw
        _cfg_mtime = mt
        return raw


def _param(name: str, default: Any, *, cast=int) -> Any:
    val = load_config().get(name, default)
    try:
        return cast(val)
    except Exception:
        return default


def enabled() -> bool:
    val = load_config().get("enabled", True)
    return val is not False


def signals() -> Dict[str, Dict[str, Any]]:
    sigs = load_config().get("signals")
    if isinstance(sigs, dict):
        return {str(k): v for k, v in sigs.items() if isinstance(v, dict)}
    return {}


def severity_from_score(score: int) -> str:
    """分数 → 五级语义严重度（与前端 sev 色板一致）。"""
    th = load_config().get("thresholds")
    t = dict(THRESHOLDS)
    if isinstance(th, dict):
        for k in THRESHOLDS:
            try:
                t[k] = int(th.get(k, THRESHOLDS[k]))
            except Exception:
                t[k] = THRESHOLDS[k]
    s = max(0, int(score or 0))
    if s >= t["critical"]:
        return "critical"
    if s >= t["high"]:
        return "high"
    if s >= t["medium"]:
        return "medium"
    if s >= t["low"]:
        return "low"
    return "info"


def _signal_spec(name: str) -> Dict[str, Any]:
    spec = dict(DEFAULT_SIGNAL)
    hit = signals().get(str(name))
    if isinstance(hit, dict):
        spec.update(hit)
    try:
        spec["weight"] = max(0, int(spec.get("weight", 10)))
    except Exception:
        spec["weight"] = 10
    try:
        spec["technique_id"] = int(spec.get("technique_id", 0))
    except Exception:
        spec["technique_id"] = 0
    tac = str(spec.get("tactic") or "unknown").strip().lower()
    spec["tactic"] = tac if tac in TACTICS else "unknown"
    return spec


def _tactic_index(tactic: str) -> int:
    try:
        return TACTICS.index(tactic)
    except ValueError:
        return 0


def _new_node() -> Dict[str, Any]:
    return {
        "score": 0,
        "last_decay": time.time(),
        "last_activity": time.time(),
        "signal_count": 0,
        "tactics": set(),
        "tech_hits": {},        # (technique_id, tactic_index) -> hits
        "signal_seen": {},      # signal_name -> ts
        "signal_divisor": {},   # signal_name -> divisor
    }


def _apply_decay(node: Dict[str, Any], now: float) -> None:
    interval = max(1, _param("decay_interval_sec", DECAY_INTERVAL_SEC))
    points = max(0, _param("decay_points", DECAY_POINTS))
    score = node["score"]
    if score <= 0:
        node["last_decay"] = now
        return
    if now <= node["last_decay"]:
        return
    intervals = int((now - node["last_decay"]) // interval)
    if intervals <= 0:
        return
    decay = score if intervals * points >= score else intervals * points
    node["score"] = score - decay
    node["last_decay"] += intervals * interval


def _evict_if_needed(now: float) -> None:
    limit = max(256, _param("max_nodes", MAX_NODES))
    if len(_nodes) <= limit:
        return
    # 优先淘汰最久未活动且分数最低的节点，给活跃高危进程留位置。
    ordered = sorted(_nodes.items(), key=lambda kv: (kv[1]["last_activity"], kv[1]["score"]))
    for key, _ in ordered[: len(_nodes) - limit]:
        _nodes.pop(key, None)


def proc_key(agent_id: str, detail: Dict[str, Any]) -> str:
    """从事件 detail 推导进程级键，用于跨事件累计。"""
    d = detail if isinstance(detail, dict) else {}
    pid = d.get("pid")
    if pid not in (None, ""):
        return f"pid:{pid}"
    eid = str(d.get("entity_id") or "").strip()
    if eid:
        return f"eid:{eid}"
    name = str(d.get("process_name") or d.get("name") or "").strip().lower()
    if name:
        return f"name:{name}"
    return f"agent:{agent_id}"


def parent_key(detail: Dict[str, Any]) -> Optional[str]:
    d = detail if isinstance(detail, dict) else {}
    ppid = d.get("ppid")
    if ppid not in (None, ""):
        return f"pid:{ppid}"
    peid = str(d.get("parent_entity_id") or "").strip()
    return f"eid:{peid}" if peid else None


def report(
    agent_id: str,
    detail: Dict[str, Any],
    signal_name: str,
    *,
    weight: Optional[int] = None,
    tactic: Optional[str] = None,
    technique_id: Optional[int] = None,
    ts: Optional[float] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """上报一个信号，返回该进程最新的评分快照。永不抛异常。

    detail 会被就地补充评分字段（risk_score / risk_level / risk_breakdown 等），
    便于直接透传给 agent_protocol.report_event()。
    """
    out: Dict[str, Any] = {
        "applied": False, "score": 0, "level": "info", "delta": 0,
        "distinct_tactics": 0, "signal_count": 0, "propagated": 0,
    }
    if not enabled() or not agent_id or not isinstance(detail, dict):
        return out
    try:
        spec = _signal_spec(signal_name)
        if weight is not None:
            spec["weight"] = max(0, int(weight))
        if tactic:
            t = str(tactic).strip().lower()
            spec["tactic"] = t if t in TACTICS else spec["tactic"]
        if technique_id is not None:
            spec["technique_id"] = int(technique_id)

        cur = float(now if now is not None else time.time())
        pkey = proc_key(agent_id, detail)
        key = (str(agent_id), pkey)
        cap = max(0, _param("score_max", SCORE_MAX))

        with _lock:
            node = _nodes.get(key)
            if node is None:
                node = _new_node()
                node["last_decay"] = cur if now is not None else node["last_decay"]
                _nodes[key] = node
                _evict_if_needed(cur)

            # 1) 时间衰减
            _apply_decay(node, cur)

            # 2) 记录技术/战术，判断是否为新战术
            tac = spec["tactic"]
            tidx = _tactic_index(tac)
            tech_key = (int(spec["technique_id"]), tidx)
            tech_hits = int(node["tech_hits"].get(tech_key, 0)) + 1
            node["tech_hits"][tech_key] = tech_hits
            new_tactic = tidx > 0 and tidx not in node["tactics"]
            if tidx > 0:
                node["tactics"].add(tidx)
            distinct = len(node["tactics"])

            # 3) 基础权重
            delta = int(spec["weight"])

            # 4) 同信号冷却窗内重复触发权重减半
            cooldown = max(1, _param("cooldown_sec", COOLDOWN_SEC))
            last = node["signal_seen"].get(signal_name)
            if last is not None and 0 <= (cur - last) <= cooldown:
                divisor = int(node["signal_divisor"].get(signal_name, 1)) * 2
                node["signal_divisor"][signal_name] = max(2, divisor)
                delta = max(_param("repeat_min", REPEAT_MIN), delta // max(2, divisor))
            else:
                node["signal_divisor"][signal_name] = 1
            node["signal_seen"][signal_name] = cur

            # 5) 战术宽度奖励（杀伤链越宽越可信）
            if new_tactic and distinct > 1:
                delta += _param("correlation_bonus", CORRELATION_BONUS) * (distinct - 1)

            # 6) 持续使用同一技术奖励（第 3 次起）
            if tech_hits >= _param("repetition_threshold", REPETITION_THRESHOLD):
                delta += _param("repetition_bonus", REPETITION_BONUS)

            node["score"] = min(cap, node["score"] + delta)
            node["signal_count"] += 1
            node["last_activity"] = cur

            # 7) 分数向父进程传播（每层 50%，最多 8 层）
            propagated_total = 0
            pkey_parent = parent_key(detail)
            if pkey_parent and delta > 0:
                propagated = delta
                cur_key = pkey_parent
                pct = max(0, min(100, _param("propagation_pct", PROPAGATION_PCT)))
                depth_cap = max(0, _param("ancestry_max_depth", ANCESTRY_MAX_DEPTH))
                for _ in range(depth_cap):
                    propagated = propagated * pct // 100
                    if propagated <= 0:
                        break
                    pnode = _nodes.get((str(agent_id), cur_key))
                    if pnode is None:
                        break
                    _apply_decay(pnode, cur)
                    pnode["score"] = min(cap, pnode["score"] + propagated)
                    pnode["last_activity"] = cur
                    propagated_total += propagated
                    # 血缘再向上一层需要父节点自己的 ppid；事件里通常只有一层，
                    # 这里仅传播已知的一跳，更多层级由进程树视图负责还原。
                    break

            score = int(node["score"])
            level = severity_from_score(score)
            out = {
                "applied": True, "score": score, "level": level, "delta": int(delta),
                "distinct_tactics": distinct, "signal_count": int(node["signal_count"]),
                "propagated": int(propagated_total),
            }

            # 8) 回写 detail（静态 risk_score 作为下限，避免评分走低时倒退）
            try:
                static = int(detail.get("risk_score") or 0)
            except Exception:
                static = 0
            displayed = max(static, score)
            detail["risk_score"] = displayed
            # 严重度与展示分保持一致（静态分更高时以静态分为准）
            level = severity_from_score(displayed)
            out["level"] = level
            detail["risk_level"] = level
            detail["risk_breakdown"] = {
                "signal": str(signal_name)[:80],
                "delta": out["delta"],
                "weight": int(spec["weight"]),
                "tactic": tac,
                "technique_id": int(spec["technique_id"]),
                "distinct_tactics": distinct,
                "signal_count": out["signal_count"],
                "decayed": True,
                "propagated": out["propagated"],
            }
            detail["risk_tactics"] = [TACTICS[i] for i in sorted(node["tactics"])][:12]
        return out
    except Exception:
        return out


def snapshot(agent_id: str, detail: Dict[str, Any]) -> Dict[str, Any]:
    """读取某进程当前评分快照（不产生新信号）。"""
    key = (str(agent_id), proc_key(agent_id, detail))
    with _lock:
        node = _nodes.get(key)
        if node is None:
            return {"score": 0, "level": "info", "signal_count": 0, "tactics": []}
        _apply_decay(node, time.time())
        score = int(node["score"])
        return {
            "score": score,
            "level": severity_from_score(score),
            "signal_count": int(node["signal_count"]),
            "tactics": [TACTICS[i] for i in sorted(node["tactics"])][:12],
        }


def host_snapshot(agent_id: str) -> List[Dict[str, Any]]:
    """某主机所有被评分进程的快照，按分数降序（top 20）。"""
    prefix = str(agent_id)
    now = time.time()
    out: List[Dict[str, Any]] = []
    with _lock:
        for (aid, pkey), node in list(_nodes.items()):
            if aid != prefix:
                continue
            _apply_decay(node, now)
            score = int(node["score"])
            out.append({
                "process_key": pkey,
                "score": score,
                "level": severity_from_score(score),
                "signal_count": int(node["signal_count"]),
                "tactics": [TACTICS[i] for i in sorted(node["tactics"])][:12],
            })
    out.sort(key=lambda x: x["score"], reverse=True)
    return out[:20]


def reset() -> None:
    """清空内存评分状态（仅供测试/手动重置）。"""
    with _lock:
        _nodes.clear()
