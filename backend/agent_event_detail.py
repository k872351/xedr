"""Bound and rank event detail payloads before persistence or display."""
from __future__ import annotations

import json
from typing import Any


_DETAIL_MAX = 4000


def _shrink(obj: Any, cap: int) -> Any:
    if isinstance(obj, str):
        return obj if len(obj) <= cap else obj[:cap] + "…"
    if isinstance(obj, dict):
        return {k: _shrink(v, cap) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_shrink(v, cap) for v in obj[:50]]
    return obj


def fit_detail(raw: Any) -> str:
    """告警详情统一存 JSON：dict/list 正常序列化，超长时逐级收缩字符串字段而不是硬截断（硬截断会破坏 JSON）。"""
    if raw is None or raw == "":
        return ""
    obj = raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s.startswith(("{", "[")):
            return json.dumps({"message": s[:_DETAIL_MAX - 40]}, ensure_ascii=False)
        try:
            obj = json.loads(s)
        except ValueError:
            return json.dumps({"message": s[:_DETAIL_MAX - 40], "truncated": True}, ensure_ascii=False)
    try:
        out = json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return json.dumps({"message": str(raw)[:_DETAIL_MAX - 40]}, ensure_ascii=False)
    for cap in (1500, 800, 300, 120):
        if len(out) <= _DETAIL_MAX:
            return out
        out = json.dumps(_shrink(obj, cap), ensure_ascii=False, default=str)
    if len(out) <= _DETAIL_MAX:
        return out
    return json.dumps({"truncated": True, "preview": out[:_DETAIL_MAX - 60]}, ensure_ascii=False)


def _detail_score(s: str) -> int:
    if not s:
        return 0
    try:
        o = json.loads(s) if s.lstrip().startswith(("{", "[")) else None
    except ValueError:
        return max(1, len(s) // 10)
    if not isinstance(o, dict):
        return max(1, len(s) // 10)
    # 只有 raw/etype 的截断残骸视为几乎无信息
    if "raw" in o and len(o) <= 2:
        return 1
    n = 0
    for k, v in o.items():
        if v in (None, "", [], {}):
            continue
        n += 2
        if isinstance(v, dict):
            n += sum(1 for x in v.values() if x not in (None, "", [], {}))
        elif isinstance(v, str) and len(v) > 20:
            n += 1
    return n


def _detail_richer(new: str, old: str) -> bool:
    return _detail_score(new) >= _detail_score(old) and bool(new)
