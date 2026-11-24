# -*- coding: utf-8 -*-
"""Formatting helpers for bounded finding evidence returned to list views."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set

_EVIDENCE_LIST_PREVIEW = 5


def _norm_evidence_list(ev: Any) -> List[str]:
    raw: List[Any] = []
    if isinstance(ev, list):
        raw = ev
    elif isinstance(ev, str) and ev.strip():
        raw = [ev.strip()]
    elif ev:
        s = str(ev).strip()
        if s:
            raw = [s]
    out: List[str] = []
    seen: Set[str] = set()
    for item in raw:
        for ln in str(item or "").splitlines():
            s = ln.strip()
            if not s:
                continue
            key = s[:400].lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(s)
    return _coalesce_black_mod_evidence(out)


_BLACK_MOD_HDR = re.compile(r"^(?:黑模块|黑DLL|黑dll|黑文件|未签名文件|未签名模块)\s*[:：]?\s*$", re.I)
_UNSIGNED_FILE_LABEL = "未签名文件"
_BLACK_DLL_LABEL = "黑DLL"


def _coalesce_black_mod_evidence(lines: List[str]) -> List[str]:
    """把「进程行 / 未签名文件: / - dll」拆散行重新拼成一条证据（兼容旧「黑模块」）。"""
    if not lines:
        return lines
    out: List[str] = []
    i = 0
    n = len(lines)
    while i < n:
        cur = lines[i]
        nxt_hdr = i + 1 < n and bool(_BLACK_MOD_HDR.match(lines[i + 1]))
        if _BLACK_MOD_HDR.match(cur) or nxt_hdr:
            base = "" if _BLACK_MOD_HDR.match(cur) else cur
            hdr = cur if _BLACK_MOD_HDR.match(cur) else lines[i + 1]
            label = _BLACK_DLL_LABEL if re.match(r"^(?:黑DLL|黑dll|黑文件|黑模块)", str(hdr or "").strip(), re.I) else _UNSIGNED_FILE_LABEL
            if not _BLACK_MOD_HDR.match(cur):
                i += 1
            i += 1  # skip header
            mods: List[str] = []
            while i < n and (
                lines[i].startswith("-")
                or lines[i].startswith("•")
                or lines[i].startswith("*")
                or _looks_like_mod_line(lines[i])
            ):
                mods.append(lines[i].lstrip("-•* ").strip())
                i += 1
            block = (f"{label}:\n- " + "\n- ".join(mods)) if mods else f"{label}:"
            if base:
                out.append(f"{base}\n{block}")
            elif out:
                out[-1] = f"{out[-1]}\n{block}"
            else:
                out.append(block)
            continue
        if _looks_like_mod_line(cur) and out:
            prev = out[-1]
            if (
                f"\n{_UNSIGNED_FILE_LABEL}" in prev
                or "\n黑模块" in prev
                or "\n黑DLL" in prev
                or "\n黑文件" in prev
                or f"| {_UNSIGNED_FILE_LABEL}" in prev
                or "| 黑模块" in prev
                or "| 黑DLL" in prev
                or "| 黑文件" in prev
                or f"|{_UNSIGNED_FILE_LABEL}" in prev
                or "|黑模块" in prev
                or "|黑DLL" in prev
                or "|黑文件" in prev
            ):
                out[-1] = f"{prev}\n- {cur.lstrip('-•* ').strip()}"
            else:
                out[-1] = f"{prev}\n{_UNSIGNED_FILE_LABEL}:\n- {cur.lstrip('-•* ').strip()}"
            i += 1
            continue
        out.append(cur)
        i += 1
    return out


def _looks_like_mod_line(s: str) -> bool:
    t = (s or "").strip()
    if not t or _BLACK_MOD_HDR.match(t):
        return False
    if re.search(r"\[[^\]]+\]", t) and re.search(r"\.(?:dll|exe|sys|ocx)\b", t, re.I):
        return True
    if re.match(r"^[\w.-]+\.(?:dll|exe|sys|ocx)\b", t, re.I) and ("@" in t or "=>" in t or "[" in t):
        return True
    return False



def slim_finding_for_list(item: Any, preview: int = _EVIDENCE_LIST_PREVIEW) -> Dict[str, Any]:
    """压缩告警体积：列表只留证据预览，详情再按需拉取。"""
    if not isinstance(item, dict):
        return {"title": str(item or ""), "evidence": [], "evidence_total": 0}
    out = dict(item)
    out.pop("members", None)
    if isinstance(out.get("extra"), dict):
        ex = {k: v for k, v in out["extra"].items() if k != "members"}
        out["extra"] = ex
    fobj = out.get("file")
    if isinstance(fobj, dict):
        keep = ("full_path", "name", "ext", "size", "company", "product", "signed", "signer", "sig_status", "sig_type", "description")
        out["file"] = {k: fobj.get(k) for k in keep if fobj.get(k) is not None and fobj.get(k) != ""}

    ev = _norm_evidence_list(out.get("evidence"))
    # 合并后的长度为准；旧 evidence_total 常是「进程+黑模块头+dll」拆散条数
    total = len(ev)
    try:
        declared = int(out.get("evidence_total") or (out.get("extra") or {}).get("evidence_total") or 0)
    except Exception:
        declared = 0
    hit = int(out.get("count") or 0) or 0
    # 截断场景：声明总数明显大于当前列表且不像黑模块拆散（3→1）时保留
    if declared > total and not (declared <= total + 2 and any(("黑模块" in str(x) or "黑DLL" in str(x) or "黑文件" in str(x) or "未签名文件" in str(x)) for x in ev)):
        total = max(declared, total)
    if hit > total and declared <= 0:
        total = hit
    preview = max(1, int(preview or _EVIDENCE_LIST_PREVIEW))
    if len(ev) > preview:
        out["evidence"] = [x[:800] for x in ev[:preview]]
        out["evidence_lazy"] = True
    else:
        out["evidence"] = [x[:800] for x in ev]
        out["evidence_lazy"] = bool(total > len(out["evidence"]))
    out["evidence_total"] = total if total else len(out["evidence"])
    if not out.get("reason") and out["evidence"]:
        out["reason"] = out["evidence"][0]
    return out


def slim_findings_list(items: List[Any], preview: int = _EVIDENCE_LIST_PREVIEW) -> List[Dict[str, Any]]:
    return [slim_finding_for_list(x, preview=preview) for x in (items or []) if x is not None]


def slim_findings_by_module(by_mod: Any) -> Dict[str, Any]:
    """轻量视图去掉模块内 findings 样本，只保留 count/high，避免几百 KB～数 MB JSON。"""
    if not isinstance(by_mod, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, block in by_mod.items():
        if not isinstance(block, dict):
            out[k] = block
            continue
        items = block.get("findings") or []
        n = int(block.get("count") or (len(items) if isinstance(items, list) else 0) or 0)
        out[k] = {
            "matcher": block.get("matcher") or k,
            "count": n,
            "high": int(block.get("high") or 0),
            "truncated": True,
            "findings": [],
        }
    return out


