"""基于 Agent 时间线的 Beacon / 准周期外联检测（平台侧兜底）。"""
from __future__ import annotations

import json
import math
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

_PRIV = re.compile(
    r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fc|fd|fe80:|localhost$)",
    re.I,
)
_BROWSER = {
    "chrome.exe", "msedge.exe", "msedgewebview2.exe", "firefox.exe", "iexplore.exe",
    "brave.exe", "opera.exe", "teams.exe", "outlook.exe", "slack.exe", "discord.exe",
    "svchost.exe", "searchhost.exe", "runtimebroker.exe",
}

# agent_id -> last scan monotonic
_LAST_SCAN: Dict[str, float] = {}
_SCAN_COOLDOWN = 120.0


def _parse_ts(s: str) -> Optional[datetime]:
    s = (s or "").strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(s[:26], fmt)
        except Exception:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _host_port(detail: Dict[str, Any]) -> Tuple[str, str]:
    host = str(detail.get("host") or detail.get("domain") or detail.get("remote_ip") or "").strip().lower()
    port = str(detail.get("port") or detail.get("remote_port") or "").strip()
    remote = str(detail.get("remote") or "").strip()
    if not host and remote:
        if remote.startswith("["):
            m = re.match(r"\[([^\]]+)\]:(\d+)$", remote)
            if m:
                host, port = m.group(1).lower(), m.group(2)
        elif ":" in remote:
            host, _, port = remote.rpartition(":")
            host = host.lower()
    return host, port


def _interval_stats(times: List[datetime]) -> Tuple[float, float, bool]:
    if len(times) < 2:
        return 0.0, 0.0, False
    gaps = []
    for i in range(1, len(times)):
        g = (times[i] - times[i - 1]).total_seconds()
        if g >= 1:
            gaps.append(g)
    if len(gaps) < 4:
        return 0.0, 0.0, False
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return 0.0, 0.0, False
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    cv = math.sqrt(var) / mean
    return mean, cv, True


def analyze_agent_beacon(conn, agent_id: str, hours: int = 6, limit: bool = True) -> Dict[str, Any]:
    """扫描 agent_timeline 中的外联/HTTP，找出准周期 Beacon。"""
    agent_id = str(agent_id or "").strip()
    if not agent_id:
        return {"ok": False, "error": "no_agent"}
    now_m = time.monotonic()
    if limit and now_m - _LAST_SCAN.get(agent_id, 0) < _SCAN_COOLDOWN:
        return {"ok": True, "skipped": "cooldown", "hits": []}
    _LAST_SCAN[agent_id] = now_m

    since = (datetime.utcnow() - timedelta(hours=max(1, min(hours, 48)))).strftime("%Y-%m-%d %H:%M:%S")
    rows = conn.execute(
        """SELECT etype, summary, detail_json, ts FROM agent_timeline
           WHERE agent_id=? AND ts>=? AND etype IN
           ('network_connect_etw','network_connect','http_request_etw','beacon_like')
           ORDER BY ts ASC LIMIT 4000""",
        (agent_id, since),
    ).fetchall()

    buckets: Dict[str, Dict[str, Any]] = {}
    for etype, summary, detail_s, ts in rows:
        if etype == "beacon_like":
            continue
        try:
            detail = json.loads(detail_s or "{}")
        except Exception:
            detail = {}
        if not isinstance(detail, dict):
            detail = {}
        host, port = _host_port(detail)
        if not host or _PRIV.match(host):
            continue
        proc = str(detail.get("process_name") or detail.get("name") or "").strip()
        if proc.lower() in _BROWSER:
            continue
        ent = str(detail.get("entity_id") or "") or f"pid:{detail.get('pid')}"
        key = f"{ent}|{host}|{port}"
        t = _parse_ts(str(ts or ""))
        if not t:
            continue
        slot = buckets.setdefault(key, {
            "host": host, "port": port, "process": proc,
            "path": str(detail.get("path") or detail.get("process_path") or ""),
            "entity_id": ent, "times": [],
        })
        slot["times"].append(t)
        if proc and not slot["process"]:
            slot["process"] = proc

    hits: List[Dict[str, Any]] = []
    for key, slot in buckets.items():
        times = sorted(slot["times"])
        # 去抖：同一秒合并
        dedup: List[datetime] = []
        for t in times:
            if not dedup or (t - dedup[-1]).total_seconds() >= 1:
                dedup.append(t)
        mean, cv, ok = _interval_stats(dedup)
        if not ok or cv > 0.35 or mean < 20 or mean > 3600 or len(dedup) < 5:
            continue
        sev = "high" if cv <= 0.15 or any(x in (slot["path"] or "").lower() for x in ("\\temp\\", "\\appdata\\", "\\users\\")) else "medium"
        hits.append({
            "host": slot["host"], "port": slot["port"], "process": slot["process"],
            "path": slot["path"], "entity_id": slot["entity_id"],
            "samples": len(dedup), "mean_interval_sec": round(mean, 2),
            "jitter_cv": round(cv, 3), "severity": sev,
            "summary": f"疑似Beacon外联: {slot['process'] or '?'} → {slot['host']}:{slot['port']} "
                       f"(间隔≈{mean:.0f}s, CV={cv:.2f}, n={len(dedup)})",
        })
    hits.sort(key=lambda h: (0 if h["severity"] == "high" else 1, h["jitter_cv"]))
    return {"ok": True, "agent_id": agent_id, "hits": hits[:30], "scanned": len(rows), "buckets": len(buckets)}


def maybe_emit_beacon_events(conn, agent_id: str, hostname: str = "") -> int:
    """将平台扫描命中写入 agent_events（去重）。"""
    pack = analyze_agent_beacon(conn, agent_id, hours=6, limit=True)
    hits = pack.get("hits") or []
    if not hits:
        return 0
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    n = 0
    for h in hits[:10]:
        title = str(h.get("summary") or "")[:200]
        if not title:
            continue
        exists = conn.execute(
            """SELECT 1 FROM agent_events
               WHERE agent_id=? AND title=? AND status='open'
                 AND created_at>=datetime('now','-2 hours') LIMIT 1""",
            (agent_id, title),
        ).fetchone()
        if exists:
            continue
        detail = json.dumps({**h, "source": "platform_beacon", "mitre": ["T1071"]}, ensure_ascii=False)
        conn.execute(
            """INSERT INTO agent_events(agent_id, hostname, title, detail, module, severity, status, created_at, updated_at)
               VALUES(?,?,?,?,?,?, 'open', ?, ?)""",
            (agent_id, hostname or "", title, detail, "beacon", str(h.get("severity") or "medium"), now, now),
        )
        n += 1
    return n
