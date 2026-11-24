"""网络感知：时间线外联 vs 主机基线，输出新增连接、趋势与协议分布。"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from . import agent_edr
from . import ip_intel

NET_ETYPES = ("network_connect", "network_connect_etw", "http_request_etw")
_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f")


def _parse_ts(s: Any) -> Optional[datetime]:
    v = str(s or "").strip().replace("Z", "")
    if not v:
        return None
    if "+" in v[10:]:
        v = v[: 10 + v[10:].index("+")]
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(v[:26], fmt)
        except ValueError:
            continue
    return None


def _detail(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        d = json.loads(raw or "{}")
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.strip("[]")).is_private or ipaddress.ip_address(ip.strip("[]")).is_loopback
    except Exception:
        return False


def _norm_row(r: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    d = _detail(r.get("detail_json"))
    etype = str(r.get("etype") or "")
    remote_ip = str(d.get("remote_ip") or "").strip()
    remote_port = str(d.get("remote_port") or d.get("port") or "").strip()
    host = str(d.get("host") or d.get("domain") or "").strip().lower()
    remote = str(d.get("remote") or "").strip()
    if not remote_ip and remote:
        # 223.x.x.x:443 或 [ipv6]:443
        if remote.startswith("[") and "]:" in remote:
            remote_ip = remote[1: remote.index("]")]
            remote_port = remote.split("]:", 1)[-1]
        elif ":" in remote and remote.count(":") == 1:
            remote_ip, remote_port = remote.split(":", 1)
    if not host and not remote_ip:
        return None
    proto = str(d.get("proto") or ("http" if etype == "http_request_etw" else "tcp")).lower()
    method = str(d.get("method") or "").upper()
    url_full = str(d.get("url") or "").strip()
    url_path = str(d.get("url_path") or "").strip()
    if url_full:
        # 从 URL 抽 path / host；若只是路径（如 "/"）则不当作完整 URL
        try:
            from urllib.parse import urlsplit
            sp = urlsplit(url_full if "://" in url_full else f"http://placeholder{url_full if url_full.startswith('/') else '/' + url_full}")
            if "://" in url_full:
                url_path = url_path or ((sp.path or "/") + (("?" + sp.query) if sp.query else ""))
                if not host and sp.hostname:
                    host = str(sp.hostname).lower()
                if not remote_port and sp.port:
                    remote_port = str(sp.port)
            else:
                # path-only / relative：保留为 path，稍后用 host 拼完整 URL
                url_path = url_path or (url_full if url_full.startswith("/") else "/" + url_full)
                url_full = ""
        except Exception:
            if url_full.startswith("/") or "://" not in url_full:
                url_path = url_path or (url_full if url_full.startswith("/") else "/" + url_full)
                url_full = ""
    if not host and remote:
        # remote 可能是域名:端口
        if "://" not in remote and remote.count(":") == 1 and not remote.replace(".", "").replace(":", "").isdigit():
            h, p = remote.split(":", 1)
            if h and not h.replace(".", "").isdigit():
                host = h.lower()
                if not remote_port:
                    remote_port = p
    dest_host = host or remote_ip
    if not url_full and dest_host and (method or etype == "http_request_etw" or url_path):
        scheme = "https" if str(remote_port) == "443" else "http"
        auth = f"{dest_host}:{remote_port}" if remote_port and str(remote_port) not in ("80", "443") else dest_host
        path = url_path or "/"
        if not path.startswith("/"):
            path = "/" + path
        url_full = f"{scheme}://{auth}{path}"
    dest_key = dest_host
    if remote_port:
        dest_key = f"{dest_key}:{remote_port}"
    ecs = d.get("ecs") if isinstance(d.get("ecs"), dict) else {}
    ecs_proc = ecs.get("process") if isinstance(ecs.get("process"), dict) else {}
    return {
        "id": r.get("id"),
        "agent_id": r.get("agent_id"),
        "hostname": r.get("hostname"),
        "etype": etype,
        "ts": r.get("ts"),
        "summary": r.get("summary"),
        "severity": r.get("severity"),
        "process_name": str(d.get("process_name") or d.get("host_process") or ""),
        "process_path": str(d.get("path") or ecs_proc.get("executable") or ""),
        "pid": d.get("pid"),
        "entity_id": str(r.get("entity_id") or d.get("entity_id") or ""),
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "host": host,
        "proto": proto,
        "method": method,
        "url": url_full[:800],
        "url_path": (url_path or "/")[:500] if (method or etype == "http_request_etw") else url_path[:500],
        "http_source": str(d.get("source") or ""),  # webio / wininet
        "status_code": str(d.get("status_code") or d.get("StatusCode") or d.get("response_status") or ""),
        "status_text": str(d.get("status_text") or d.get("StatusText") or ""),
        "dest_key": dest_key,
        "is_private": _is_private(remote_ip) if remote_ip else False,
        "local": str(d.get("local") or ""),
    }


def _load(agent_id: str, since: str, limit: int) -> List[Dict[str, Any]]:
    agent_edr.ensure()
    placeholders = ",".join("?" for _ in NET_ETYPES)
    sql = (f"SELECT id, agent_id, hostname, etype, summary, detail_json, severity, ts, entity_id "
           f"FROM agent_timeline WHERE ts>=? AND etype IN ({placeholders})")
    args: List[Any] = [since, *NET_ETYPES]
    if agent_id:
        sql += " AND agent_id=?"
        args.append(agent_id)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            return [dict(r) for r in conn.execute(sql, args).fetchall()]
        finally:
            conn.close()


def _is_http(e: Dict[str, Any]) -> bool:
    return e.get("etype") == "http_request_etw" or str(e.get("proto") or "").lower() == "http"


def _extract_ipv4(*candidates: Any) -> str:
    """从 remote_ip / dest_key / remote / host 等字段尽量抽出公网 IPv4。"""
    for raw in candidates:
        s = str(raw or "").strip().strip("[]")
        if not s:
            continue
        # 去掉尾部端口 host:443 / [ip]:443
        if s.count(":") == 1 and re_ipv4(s.split(":", 1)[0]):
            s = s.split(":", 1)[0]
        elif s.startswith("[") and "]:" in str(raw or ""):
            s = str(raw)[1: str(raw).index("]")]
        # 摘要里可能夹杂文字，抓第一段 IPv4
        if not re_ipv4(s):
            m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", s)
            s = m.group(1) if m else ""
        if re_ipv4(s):
            return s
    return ""


def _enrich_ip(e: Dict[str, Any]) -> None:
    """就地写入 geo / cloud / risk 字段。优先用 remote_ip；否则从目的地抽 IP。"""
    ip = _extract_ipv4(
        e.get("remote_ip"),
        e.get("dest_key"),
        e.get("host"),
        e.get("summary"),
    )
    if ip and not e.get("remote_ip"):
        e["remote_ip"] = ip
    risk = ip_intel.risk_for_outbound(
        ip=ip,
        is_new=bool(e.get("is_new")),
        process_name=str(e.get("process_name") or ""),
        process_path=str(e.get("process_path") or ""),
        remote_port=str(e.get("remote_port") or ""),
    )
    e["ip_geo"] = risk.get("geo") or "unknown"
    e["ip_cloud"] = risk.get("cloud") or ""
    e["ip_labels"] = list(risk.get("labels") or [])
    e["ip_risk"] = risk.get("risk") or "info"
    e["ip_risk_label"] = risk.get("risk_label") or "正常"
    e["ip_risk_reasons"] = list(risk.get("reasons") or [])
    e["is_overseas"] = bool(risk.get("is_overseas"))
    e["is_cloud"] = bool(risk.get("is_cloud"))
    e["is_domestic"] = bool(risk.get("is_domestic"))


def re_ipv4(s: str) -> bool:
    parts = str(s or "").split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def analyze_network(*, agent_id: str = "", hours: int = 24, baseline_hours: int = 168,
                    only_new: bool = True, only_external: bool = True, q: str = "",
                    only_http: bool = False, proto: str = "",
                    geo: str = "", cloud_only: bool = False, risk: str = "",
                    limit: int = 100) -> Dict[str, Any]:
    hours = max(1, min(int(hours or 24), 24 * 14))
    baseline_hours = max(hours, min(int(baseline_hours or 168), 24 * 30))
    now = datetime.now()
    since = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    base_since = (now - timedelta(hours=baseline_hours)).strftime("%Y-%m-%dT%H:%M:%S")
    window_start = now - timedelta(hours=hours)
    want_proto = str(proto or "").strip().lower()
    if only_http:
        want_proto = "http"
    want_geo = str(geo or "").strip().lower()  # overseas / domestic / cloud
    want_risk = str(risk or "").strip().lower()  # watch / alert

    ip_meta = ip_intel.ensure()

    rows = _load(str(agent_id or "").strip(), base_since, 30000)
    events = [e for e in (_norm_row(r) for r in rows) if e]
    baseline_dests: set = set()
    for e in events:
        ts = _parse_ts(e["ts"])
        if ts and ts < window_start:
            baseline_dests.add(e["dest_key"])

    qlow = (q or "").strip().lower()
    observed: List[Dict[str, Any]] = []
    for e in events:
        ts = _parse_ts(e["ts"])
        if not ts or ts < window_start:
            continue
        if only_external and e["is_private"]:
            continue
        e["is_new"] = e["dest_key"] not in baseline_dests
        if only_new and not e["is_new"]:
            continue
        _enrich_ip(e)
        if qlow:
            blob = " ".join([
                e["dest_key"], e["process_name"], e["host"], e["remote_ip"],
                e["summary"], e.get("method") or "", e.get("url_path") or "",
                " ".join(e.get("ip_labels") or []), e.get("ip_cloud") or "",
            ]).lower()
            if qlow not in blob:
                continue
        observed.append(e)

    # KPI / 趋势始终基于筛选前的观察窗结果（不含协议过滤），避免点 HTTP 后总数被改写
    trend_map: Dict[str, Dict[str, int]] = defaultdict(lambda: {"observed": 0, "new": 0, "http": 0})
    for e in observed:
        bucket = str(e["ts"] or "")[:13]  # YYYY-MM-DDTHH
        if not bucket:
            continue
        trend_map[bucket]["observed"] += 1
        if e["is_new"]:
            trend_map[bucket]["new"] += 1
        if _is_http(e):
            trend_map[bucket]["http"] += 1
    trend = []
    cursor = window_start.replace(minute=0, second=0, microsecond=0)
    end_hour = now.replace(minute=0, second=0, microsecond=0)
    while cursor <= end_hour:
        key = cursor.strftime("%Y-%m-%dT%H")
        cell = trend_map.get(key) or {"observed": 0, "new": 0, "http": 0}
        trend.append({"hour": key, **cell})
        cursor += timedelta(hours=1)

    stats = {
        "observed": len(observed),
        "new": sum(1 for e in observed if e["is_new"]),
        "http": sum(1 for e in observed if _is_http(e)),
        "hosts": len({(e["hostname"] or e["agent_id"]) for e in observed}),
        "overseas": sum(1 for e in observed if e.get("is_overseas")),
        "cloud": sum(1 for e in observed if e.get("is_cloud")),
        "watch": sum(1 for e in observed if e.get("ip_risk") == "watch"),
        "alert": sum(1 for e in observed if e.get("ip_risk") == "alert"),
    }

    # 明细 / 排行 / 饼图再套协议 / 地理 / 风险过滤
    view = observed
    if want_proto == "http":
        view = [e for e in observed if _is_http(e)]
    elif want_proto:
        view = [e for e in observed if str(e.get("proto") or "").lower() == want_proto]

    if want_geo == "overseas":
        view = [e for e in view if e.get("is_overseas")]
    elif want_geo == "domestic":
        view = [e for e in view if e.get("is_domestic")]
    elif want_geo == "cloud" or cloud_only:
        view = [e for e in view if e.get("is_cloud")]

    if want_risk == "alert":
        view = [e for e in view if e.get("ip_risk") == "alert"]
    elif want_risk == "watch":
        view = [e for e in view if e.get("ip_risk") in ("watch", "alert")]

    # 关注/告警优先排序
    risk_rank = {"alert": 0, "watch": 1, "info": 2}
    view = sorted(
        view,
        key=lambda e: (risk_rank.get(str(e.get("ip_risk") or "info"), 9), str(e.get("ts") or "")),
    )

    # 饼图始终全量，方便点协议切换；排行与明细看筛选结果
    proto_c = Counter(e["proto"] or "tcp" for e in observed)
    port_c = Counter(e["remote_port"] for e in view if e["remote_port"])
    process_c = Counter(e["process_name"] for e in view if e["process_name"])
    host_c = Counter(e["hostname"] or e["agent_id"] for e in view)
    cloud_c = Counter(e.get("ip_cloud") for e in observed if e.get("ip_cloud"))

    return {
        "ok": True,
        "since": since,
        "baseline_since": base_since,
        "hours": hours,
        "baseline_hours": baseline_hours,
        "baseline_dest_count": len(baseline_dests),
        "stats": stats,
        "trend": trend,
        "proto_pie": [{"name": k, "value": v} for k, v in proto_c.most_common(8)],
        "cloud_pie": [{"name": k, "value": v} for k, v in cloud_c.most_common(10)],
        "top_ports": port_c.most_common(12),
        "top_processes": process_c.most_common(12),
        "top_hosts": [{"host": k, "count": v} for k, v in host_c.most_common(10)],
        "items": view[: max(1, min(int(limit or 100), 500))],
        "ip_intel": ip_meta,
        "params": {
            "only_new": only_new, "only_external": only_external, "q": q,
            "only_http": bool(only_http or want_proto == "http"), "proto": want_proto,
            "geo": want_geo, "cloud_only": bool(cloud_only or want_geo == "cloud"),
            "risk": want_risk,
        },
    }
