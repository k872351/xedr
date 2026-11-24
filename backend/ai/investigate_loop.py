"""AI 调查循环：按固定工具编排采集证据 → 结构化报告（可接本地模型润色）。"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional

from . import edr_tools


def _audit(calls: List[Dict[str, Any]], name: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
    calls.append({
        "tool": name,
        "args": {k: v for k, v in args.items() if k != "actor"},
        "ok": bool(result.get("ok", True)),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "error": result.get("error") or "",
    })


def run_investigation(
    agent_id: str,
    *,
    event_id: int = 0,
    hours: int = 24,
    allow_active: bool = False,
    actor: str = "",
    question: str = "",
) -> Dict[str, Any]:
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    iid = uuid.uuid4().hex
    calls: List[Dict[str, Any]] = []
    evidence: Dict[str, Any] = {}

    plan = [
        ("get_host_overview", {}),
        ("list_threat_events", {"status": "open", "limit": 20}),
        ("search_endpoint_events", {"hours": hours, "limit": 40, "q": question or ""}),
        ("get_persistence_items", {"limit": 30}),
        ("get_network_connections", {"hours": hours, "limit": 30}),
        ("get_memory_findings", {"hours": max(hours, 72), "limit": 20}),
        ("get_attack_story", {"event_id": event_id}),
    ]
    if event_id:
        plan.insert(2, ("get_process_tree", {"event_id": event_id}))

    for name, args in plan:
        res = edr_tools.call_tool(
            name, args, agent_id=aid, allow_active=allow_active, actor=actor,
        )
        _audit(calls, name, args, res if isinstance(res, dict) else {"ok": False, "error": "bad result"})
        evidence[name] = res

    threats = (evidence.get("list_threat_events") or {}).get("items") or (evidence.get("list_threat_events") or {}).get("events") or []
    story = (evidence.get("get_attack_story") or {}).get("nodes") or []
    net = (evidence.get("get_network_connections") or {}).get("recent_events") or []
    mem = (evidence.get("get_memory_findings") or {}).get("items") or (evidence.get("get_memory_findings") or {}).get("findings") or []

    findings: List[str] = []
    if threats:
        findings.append(f"未关闭威胁告警 {len(threats)} 条")
    if mem:
        findings.append(f"内存相关命中 {len(mem)} 条")
    if net:
        findings.append(f"近期外联事件 {len(net)} 条")
    if story:
        findings.append(f"攻击链节点 {len(story)} 个")

    report = {
        "investigation_id": iid,
        "agent_id": aid,
        "question": question,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "executive_summary": "；".join(findings) or "未发现明显未关闭告警，建议结合狩猎关键字继续排查",
        "findings": findings,
        "recommendations": [
            "对 high/critical 告警关联进程做隔离或终止（需审批）",
            "核对近期持久化/服务/计划任务变更",
            "对罕见外联域名做情报与流行度比对",
        ],
        "attack_story": story[:30],
        "open_threats": threats[:15],
        "tool_audit": calls,
    }

    # 可选模型润色
    try:
        from . import analyzer
        if hasattr(analyzer, "refine_investigation_report"):
            refined = analyzer.refine_investigation_report(report)
            if isinstance(refined, dict):
                report["executive_summary"] = refined.get("executive_summary") or report["executive_summary"]
                if refined.get("recommendations"):
                    report["recommendations"] = refined["recommendations"]
                report["model_refined"] = True
    except Exception:
        pass

    return {"ok": True, "report": report, "evidence_keys": list(evidence.keys())}
