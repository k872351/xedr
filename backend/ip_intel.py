"""IP 情报：国内段 / 云厂商段匹配，供异常外联打标签与分级提示。

数据目录默认：仓库根下 ip/
  - guonei.txt          国内 IPv4 CIDR
  - yun.txt / yun2.txt / yun3.txt  云厂商段（含「厂商名：」分段标题）
"""
from __future__ import annotations

import ipaddress
import os
import re
import threading
import time
from bisect import bisect_right
from typing import Any, Dict, List, Optional, Tuple

_lock = threading.RLock()
_loaded_at = 0.0
_reload_sec = 300.0

# (start_int, end_int) 升序；并行 tags 列表
_domestic: List[Tuple[int, int]] = []
_cloud: List[Tuple[int, int, str]] = []  # start, end, vendor
_cloud_starts: List[int] = []
_domestic_starts: List[int] = []
_meta: Dict[str, Any] = {"ok": False, "path": "", "domestic": 0, "cloud": 0, "vendors": []}

_VENDOR_ALIASES = {
    "阿里云": "阿里云", "aliyun": "阿里云", "alibaba": "阿里云",
    "腾讯云": "腾讯云", "tencent": "腾讯云", "qcloud": "腾讯云",
    "华为云": "华为云", "huawei": "华为云",
    "金山云": "金山云", "百度云": "百度云", "京东云": "京东云",
    "aws": "AWS", "amazon": "AWS",
    "azure": "Azure", "microsoft": "Azure",
    "oracle": "Oracle", "ibm": "IBM",
    "cloudflare": "Cloudflare",
    "digitalocean": "DigitalOcean", "linode": "Linode",
}

_HEADER_RE = re.compile(r"^[\s]*([^\d\s/#][^：:]{0,40}?)[：:]\s*(.*)$")
_CIDR_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s*$")
_SUSPICIOUS_PROC = re.compile(
    r"(?i)^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|"
    r"bitsadmin|curl|wget|python|pythonw|node|perl|ruby|java)\.exe$"
)
_SUSPICIOUS_PATH = re.compile(
    r"(?i)\\(?:temp|tmp)\\|\\appdata\\local\\temp\\|\\users\\[^\\]+\\downloads\\|\\programdata\\[^\\]+\\temp\\"
)


def _default_ip_dir() -> str:
    # backend/ → repo root → ip/
    here = os.path.abspath(os.path.dirname(__file__))
    root = os.path.abspath(os.path.join(here, ".."))
    return os.path.join(root, "ip")


def _ip_to_int(ip: str) -> Optional[int]:
    try:
        a = ipaddress.ip_address(str(ip or "").strip().strip("[]"))
        if a.version != 4:
            return None
        return int(a)
    except Exception:
        return None


def _norm_vendor(name: str) -> str:
    raw = str(name or "").strip().strip("：:").strip()
    if not raw:
        return "云"
    key = raw.lower()
    for k, v in _VENDOR_ALIASES.items():
        if k.lower() in key or key in k.lower():
            return v
    return raw[:24]


def _parse_cidr_line(line: str) -> Optional[Tuple[int, int]]:
    m = _CIDR_RE.match(line)
    if not m:
        # 兼容「IBM:5.10.116.0/22」同行
        if ":" in line or "：" in line:
            parts = re.split(r"[：:]", line, 1)
            if len(parts) == 2 and _CIDR_RE.match(parts[1].strip()):
                return _parse_cidr_line(parts[1].strip())
        return None
    try:
        net = ipaddress.ip_network(m.group(1), strict=False)
        if net.version != 4:
            return None
        return int(net.network_address), int(net.broadcast_address)
    except Exception:
        return None


def _merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not ranges:
        return []
    ranges = sorted(ranges, key=lambda x: (x[0], x[1]))
    out = [ranges[0]]
    for s, e in ranges[1:]:
        ps, pe = out[-1]
        if s <= pe + 1:
            out[-1] = (ps, max(pe, e))
        else:
            out.append((s, e))
    return out


def _load_domestic(path: str) -> List[Tuple[int, int]]:
    rows: List[Tuple[int, int]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                hit = _parse_cidr_line(line)
                if hit:
                    rows.append(hit)
    except FileNotFoundError:
        pass
    return _merge_ranges(rows)


def _load_cloud_file(path: str) -> List[Tuple[int, int, str]]:
    rows: List[Tuple[int, int, str]] = []
    vendor = "云"
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                hm = _HEADER_RE.match(line)
                if hm and not _CIDR_RE.match(line):
                    vendor = _norm_vendor(hm.group(1))
                    rest = (hm.group(2) or "").strip()
                    if rest:
                        hit = _parse_cidr_line(rest)
                        if hit:
                            rows.append((hit[0], hit[1], vendor))
                    continue
                # 标题行后可能仍是纯 CIDR
                if re.match(r"^[\u4e00-\u9fa5A-Za-z].*[：:]\s*$", line):
                    vendor = _norm_vendor(line.rstrip("：:"))
                    continue
                hit = _parse_cidr_line(line)
                if hit:
                    rows.append((hit[0], hit[1], vendor))
    except FileNotFoundError:
        pass
    return rows


def _merge_cloud(rows: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
    """同厂商相邻段合并；不同厂商保持分离（按 start 排序）。"""
    if not rows:
        return []
    rows = sorted(rows, key=lambda x: (x[0], x[1], x[2]))
    out = [rows[0]]
    for s, e, v in rows[1:]:
        ps, pe, pv = out[-1]
        if v == pv and s <= pe + 1:
            out[-1] = (ps, max(pe, e), pv)
        else:
            out.append((s, e, v))
    return out


def reload(force: bool = False) -> Dict[str, Any]:
    global _loaded_at, _domestic, _cloud, _domestic_starts, _cloud_starts, _meta
    now = time.time()
    with _lock:
        if not force and _loaded_at and (now - _loaded_at) < _reload_sec and _meta.get("ok"):
            return dict(_meta)
        ip_dir = os.environ.get("EDR_IP_DIR") or _default_ip_dir()
        domestic = _load_domestic(os.path.join(ip_dir, "guonei.txt"))
        cloud_rows: List[Tuple[int, int, str]] = []
        for name in ("yun.txt", "yun2.txt", "yun3.txt"):
            cloud_rows.extend(_load_cloud_file(os.path.join(ip_dir, name)))
        cloud = _merge_cloud(cloud_rows)
        vendors = sorted({v for _, _, v in cloud})
        _domestic = domestic
        _cloud = cloud
        _domestic_starts = [s for s, _ in domestic]
        _cloud_starts = [s for s, _, _ in cloud]
        _loaded_at = now
        _meta = {
            "ok": bool(domestic or cloud),
            "path": ip_dir,
            "domestic": len(domestic),
            "cloud": len(cloud),
            "vendors": vendors,
            "loaded_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)),
        }
        return dict(_meta)


def ensure() -> Dict[str, Any]:
    return reload(force=False)


def _in_ranges(ip_int: int, starts: List[int], ranges: List[Tuple[int, int]]) -> bool:
    if not ranges:
        return False
    i = bisect_right(starts, ip_int) - 1
    if i < 0:
        return False
    s, e = ranges[i]
    return s <= ip_int <= e


def _cloud_vendor(ip_int: int) -> str:
    if not _cloud:
        return ""
    i = bisect_right(_cloud_starts, ip_int) - 1
    if i < 0:
        return ""
    s, e, v = _cloud[i]
    return v if s <= ip_int <= e else ""


def lookup(ip: str) -> Dict[str, Any]:
    """返回 geo / cloud / labels。"""
    ensure()
    raw = str(ip or "").strip().strip("[]")
    out: Dict[str, Any] = {
        "ip": raw,
        "geo": "unknown",
        "cloud": "",
        "is_domestic": False,
        "is_overseas": False,
        "is_cloud": False,
        "is_private": False,
        "labels": [],
    }
    if not raw:
        return out
    try:
        addr = ipaddress.ip_address(raw)
    except Exception:
        return out
    if addr.version != 4:
        out["geo"] = "non_ipv4"
        return out
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        out["geo"] = "private"
        out["is_private"] = True
        out["labels"] = ["内网"]
        return out

    ip_int = int(addr)
    vendor = _cloud_vendor(ip_int)
    domestic = _in_ranges(ip_int, _domestic_starts, _domestic)
    labels: List[str] = []
    if domestic:
        out["geo"] = "domestic"
        out["is_domestic"] = True
        labels.append("国内")
    else:
        out["geo"] = "overseas"
        out["is_overseas"] = True
        labels.append("境外")
    if vendor:
        out["cloud"] = vendor
        out["is_cloud"] = True
        labels.append(f"云:{vendor}")
    out["labels"] = labels
    return out


def risk_for_outbound(
    *,
    ip: str = "",
    is_new: bool = False,
    process_name: str = "",
    process_path: str = "",
    remote_port: str = "",
) -> Dict[str, Any]:
    """分级：info / watch / alert。"""
    info = lookup(ip)
    level = "info"
    reasons: List[str] = []
    proc = str(process_name or "").strip()
    path = str(process_path or "").strip()
    suspicious = bool(_SUSPICIOUS_PROC.match(proc) or (path and _SUSPICIOUS_PATH.search(path)))
    hot_port = str(remote_port or "") not in ("", "80", "443", "53", "123", "8080", "8443")

    if info.get("is_private"):
        return {
            **info,
            "risk": "info",
            "risk_label": "正常",
            "reasons": [],
        }

    if info.get("is_overseas") and is_new:
        level = "watch"
        reasons.append("新增境外目的地")
    if info.get("is_cloud") and is_new:
        if level == "info":
            level = "watch"
        reasons.append(f"新增云厂商地址（{info.get('cloud') or '云'}）")

    if (info.get("is_overseas") or info.get("is_cloud")) and is_new and suspicious:
        level = "alert"
        reasons.append("可疑进程上下文")
    elif (info.get("is_overseas") or info.get("is_cloud")) and is_new and hot_port and suspicious:
        level = "alert"
        reasons.append(f"非常见端口 {remote_port}")

    # 境外新增且非常见端口：抬到 watch 已足够；若再叠加脚本宿主则 alert 已覆盖
    if info.get("is_overseas") and is_new and hot_port and level == "watch":
        reasons.append(f"非常见端口 {remote_port}")

    label = {"info": "正常", "watch": "关注", "alert": "告警"}.get(level, level)
    return {
        **info,
        "risk": level,
        "risk_label": label,
        "reasons": reasons,
        "suspicious_process": suspicious,
    }
