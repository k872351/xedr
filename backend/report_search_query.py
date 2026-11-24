"""Shared token normalization for report searches."""
from __future__ import annotations

import re
from typing import Any


_DATE_Q_RE = re.compile(r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$")


def _date_q_variants(tok: str):
    """把 2026-04-20 / 2026/4/20 展开成多种日期写法。"""
    m = _DATE_Q_RE.match(str(tok or "").strip())
    if not m:
        return None
    y = m.group(1)
    try:
        mo, d = int(m.group(2)), int(m.group(3))
    except Exception:
        return None
    if not (1 <= mo <= 12 and 1 <= d <= 31):
        return None
    mm, dd = f"{mo:02d}", f"{d:02d}"
    return [
        f"{y}-{mm}-{dd}",
        f"{y}/{mm}/{dd}",
        f"{y}-{mo}-{d}",
        f"{y}/{mo}/{d}",
        f"{y}{mm}{dd}",
        f"{y}年{mm}月{dd}日",
        f"{y}年{mo}月{d}日",
    ]


def _token_in_blob(tok: str, blob: str) -> bool:
    variants = _date_q_variants(tok)
    if variants:
        return any(v.lower() in blob for v in variants)
    return tok in blob


def _item_match_q(item: Any, q: str) -> bool:
    if not q:
        return True
    tokens = [token for token in str(q).lower().split() if token and token not in ("-", "—", "–")]
    if not tokens:
        return True
    blob = _item_search_blob(item)
    return all(_token_in_blob(token, blob) for token in tokens)
def _item_search_blob(item: Any) -> str:
    """全字段可搜文本：嵌套 dict/list 全展开；空/-/N/A 不入索引；未签名带同义词。"""
    parts: List[str] = []

    def walk(v: Any, depth: int = 0) -> None:
        if v is None or depth > 10:
            return
        if isinstance(v, bool):
            parts.append("true" if v else "false")
            return
        if isinstance(v, (int, float)):
            parts.append(str(v))
            return
        if isinstance(v, str):
            s = v.strip()
            if not s or s in ("-", "—", "–", "N/A", "n/a", "(空)", "无"):
                return
            parts.append(s)
            return
        if isinstance(v, dict):
            for k, val in v.items():
                if str(k).startswith("_"):
                    continue
                walk(val, depth + 1)
            return
        if isinstance(v, (list, tuple)):
            for x in v:
                walk(x, depth + 1)

    walk(item)
    if isinstance(item, dict):
        st = str(item.get("sig_status") or item.get("SigStatus") or "").strip().lower()
        signed_flag = item.get("signed")
        if signed_flag is None:
            signed_flag = item.get("Signed")
        empty_st = (not st) or st in ("-", "—", "n/a", "空签名")
        is_signed = False
        if not empty_st:
            if st in ("missing", "notsigned", "unsigned", "error", "unknown", "hashmismatch", "nottrusted"):
                is_signed = False
            else:
                is_signed = st == "valid" or st == "signed" or ("valid" in st)
        elif signed_flag is True:
            is_signed = True

        if is_signed:
            parts.extend(["signed", "已签名", "Valid"])
            ty = str(item.get("sig_type") or item.get("SigType") or "").strip().lower()
            if ty == "catalog":
                parts.extend(["Valid(目录)", "目录签名"])
            elif ty == "authenticode":
                parts.extend(["Valid(文件)", "文件签名"])
        elif empty_st:
            # signed=false 但无 status → 仍算空签名，不挂「未签名」
            parts.extend(["空签名", "empty", "nosig", "无状态"])
        else:
            parts.extend(["unsigned", "未签名", "无签名"])

        dll = item.get("service_dll") or item.get("ServiceDll") or item.get("serviceDll")
        if dll:
            parts.append("ServiceDll")
            parts.append(str(dll))
        mods = item.get("modules")
        if mods is None:
            mods = item.get("Modules")
        if isinstance(mods, list):
            parts.append(f"模块({len(mods)})")
            parts.append("模块")
            for m in mods:
                walk(m, 0)
        dlls = item.get("dlls")
        if dlls is None:
            dlls = item.get("DLLs")
        if isinstance(dlls, list) and dlls:
            parts.append("DLL")
            for d in dlls:
                walk(d, 0)
        pid = item.get("pid") if item.get("pid") is not None else item.get("PID")
        if pid is not None and str(pid).strip() not in ("", "-"):
            parts.extend([str(pid), "PID"])
    return " ".join(parts).lower()
