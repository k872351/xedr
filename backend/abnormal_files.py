# -*- coding: utf-8 -*-
"""异常文件：聚合当天新增（file_create / fim_add 等），并标注异常文件规则命中。"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from . import agent_edr
from . import agent_rules


_FILE_ETYPES = (
    "file_create", "file_write", "file_write_etw", "file_stream_create",
    "fim_add", "fim_modify", "fim_rename", "file_rename", "file_delete",
)


def _parse_detail(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        d = json.loads(raw or "{}")
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


def _base_name(path: str) -> str:
    s = str(path or "").replace("/", "\\")
    return s.rsplit("\\", 1)[-1] if s else ""


def _file_event_fields(detail: Dict[str, Any], summary: str = "") -> Dict[str, Any]:
    """Normalize common Windows/Linux file event shapes for display and rule matching."""
    raw = detail if isinstance(detail, dict) else {}
    # 兼容 detail / detail.detail / detail.file 多层嵌套
    fields: Dict[str, Any] = {}
    for nest_key in ("file", "detail"):
        nested = raw.get(nest_key)
        if isinstance(nested, dict):
            fields.update(nested)
    fields.update(raw)
    # 若仍嵌套一层 detail，再展开一次
    inner = fields.get("detail")
    if isinstance(inner, dict):
        merged = dict(inner)
        merged.update({k: v for k, v in fields.items() if k != "detail"})
        fields = merged
    path = next((str(fields.get(key) or "").strip() for key in (
        "path", "file_path", "target_path", "TargetFilename", "FileName",
        "filename", "full_path", "image", "ObjectName",
    ) if str(fields.get(key) or "").strip()), "")
    if not path:
        match = re.search(
            r"((?:[A-Za-z]:\\|/)[^\r\n\"']+)",
            str(summary or ""), re.I,
        )
        path = match.group(1).strip().rstrip(".,;") if match else ""
    name = str(fields.get("name") or fields.get("file_name") or fields.get("basename") or _base_name(path))
    ext = str(fields.get("ext") or fields.get("extension") or "").strip().lstrip(".").lower()
    if not ext and "." in name:
        ext = name.rsplit(".", 1)[-1].lower()
    fields.update({"path": path, "name": name, "ext": ext})
    return fields


def _day_start(now: Optional[datetime] = None) -> datetime:
    n = now or datetime.now()
    return datetime(n.year, n.month, n.day)


def _match_abfile_rules(item: Dict[str, Any], rules: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """对单条文件事件跑 category=abfile 规则。"""
    rules = [
        r for r in (agent_rules.list_rules(enabled_only=True, include_sensor=False) if rules is None else rules)
        if str(r.get("category") or "").lower() == "abfile"
        or (r.get("abfile") is True)
    ]
    if not rules:
        return []
    hits: List[Dict[str, Any]] = []
    for rule in rules:
        if not agent_rules._ext_allowed(item, list(rule.get("file_exts") or [])):  # noqa: SLF001
            continue
        if not agent_rules._signed_allowed(item, str(rule.get("signed_filter") or "")):  # noqa: SLF001
            continue
        if not agent_rules._path_prefix_allowed(item, list(rule.get("path_prefixes") or [])):  # noqa: SLF001
            continue
        blob = agent_rules._item_blob(item, list(rule.get("fields") or ["path", "name"]))  # noqa: SLF001
        pats = [p for p in list(rule.get("patterns") or []) if p and str(p).strip() != "*"]
        if str(rule.get("signed_filter") or "") == "unsigned" and not pats:
            hit_pat = f"signed={item.get('signed') or 'empty'}"
        elif not pats:
            # patterns 为 * 或空：仅靠路径前缀 / 扩展名 / 签名约束
            hit_pat = "scope"
        else:
            mode = str(rule.get("match") or "substring")
            if mode == "exact":
                hit_pat = next((hit for value in blob.splitlines()
                                if (hit := agent_rules._match_text(value, pats, mode))), None)
            else:
                hit_pat = agent_rules._match_text(blob, pats, mode)
        if not hit_pat:
            continue
        hits.append({
            "rule_id": rule.get("id"),
            "title": rule.get("title") or rule.get("id"),
            "severity": rule.get("severity") or "medium",
            "matched": hit_pat,
        })
    return hits[:5]


def list_abnormal_files(
    *,
    agent_id: str = "",
    hours: int = 0,
    q: str = "",
    only_rule_hit: bool = False,
    ext: str = "",
    unsigned_only: bool = False,
    limit: int = 300,
) -> Dict[str, Any]:
    """列出观察窗内新增文件。hours<=0 表示当天 0 点起。"""
    aid = str(agent_id or "").strip()
    now = datetime.now()
    if int(hours or 0) > 0:
        since = now - timedelta(hours=max(1, min(int(hours), 168)))
    else:
        since = _day_start(now)
    since_s = since.strftime("%Y-%m-%dT%H:%M:%S")

    agent_edr.ensure()
    with agent_edr._lock:  # noqa: SLF001
        conn = agent_edr._connect()  # noqa: SLF001
        try:
            et_ph = ",".join("?" for _ in _FILE_ETYPES)
            args: List[Any] = [since_s, *_FILE_ETYPES]
            where = f"ts >= ? AND etype IN ({et_ph})"
            if aid:
                where += " AND agent_id=?"
                args.append(aid)
            rows = conn.execute(
                f"""SELECT id, agent_id, hostname, etype, summary, severity, ts, detail_json
                    FROM agent_timeline
                    WHERE {where}
                    ORDER BY ts DESC LIMIT 2000""",
                args,
            ).fetchall()
        finally:
            conn.close()

    qlow = str(q or "").strip().lower()
    # 支持 "exe / dll"、"exe,dll"、"exe dll" 多扩展名
    ext_set = {
        x.strip().lstrip(".").lower()
        for x in re.split(r"[,;/\s]+", str(ext or ""))
        if x.strip() and x.strip() != "/"
    }
    items: List[Dict[str, Any]] = []
    seen_path: set = set()
    rule_hit_n = unsigned_n = 0
    rules = agent_rules.list_rules(enabled_only=True, include_sensor=False)
    active_rules = [r for r in rules if str(r.get("category") or "").lower() == "abfile" or r.get("abfile") is True]

    for r in rows or []:
        d = _parse_detail(r["detail_json"] if hasattr(r, "keys") else r.get("detail_json"))
        file_fields = _file_event_fields(d, str(r["summary"] or ""))
        path = str(file_fields.get("path") or "")
        if not path:
            continue
        # 去重：同终端同路径保留最新
        key = f"{r['agent_id']}|{path.lower()}"
        if key in seen_path:
            continue
        seen_path.add(key)

        name = str(file_fields.get("name") or _base_name(path))
        file_ext = str(file_fields.get("ext") or "").lstrip(".").lower()
        if ext_set and file_ext not in ext_set:
            continue
        if qlow and qlow not in path.lower() and qlow not in name.lower() and qlow not in str(r["hostname"] or "").lower():
            continue

        signed = file_fields.get("signed")
        size = file_fields.get("size")
        if size is None:
            size = file_fields.get("size_kb")
        item = {
            "id": r["id"],
            "agent_id": r["agent_id"],
            "hostname": r["hostname"] or "",
            "etype": r["etype"],
            "summary": r["summary"] or "",
            "severity": r["severity"] or "info",
            "ts": r["ts"],
            "path": path,
            "name": name,
            "ext": file_ext,
            "size": size,
            "mtime": file_fields.get("mtime") or file_fields.get("modified") or "",
            "label": file_fields.get("label") or "",
            "root": file_fields.get("root") or "",
            "old_path": file_fields.get("old_path") or "",
            "signed": signed,
            "signer": file_fields.get("signer") or "",
            "sha256": file_fields.get("sha256") or file_fields.get("old_sha256") or "",
            "md5": file_fields.get("md5") or "",
            "pid": file_fields.get("pid"),
            "process_name": (
                file_fields.get("process_name")
                or file_fields.get("parent_process")
                or file_fields.get("image")
                or ""
            ),
            "user": file_fields.get("user") or file_fields.get("username") or "",
        }
        if unsigned_only:
            sl = str(signed or "").lower()
            if sl in ("valid", "signed", "trusted"):
                continue

        rule_item = dict(file_fields)
        rule_item.update({
            "name": name, "path": path, "ext": file_ext,
            "signed": signed, "signer": file_fields.get("signer"),
            "sha256": file_fields.get("sha256"), "process_name": item["process_name"],
        })
        hits = _match_abfile_rules(rule_item, rules)
        item["rule_hits"] = hits
        item["rule_hit"] = bool(hits)
        if hits:
            rule_hit_n += 1
            item["severity"] = hits[0].get("severity") or item["severity"]
        sl = str(signed or "").lower()
        if sl in ("notsigned", "unsigned", "hashmismatch", "nottrusted", ""):
            unsigned_n += 1
        if only_rule_hit and not hits:
            continue
        items.append(item)
        if len(items) >= max(20, min(int(limit or 300), 800)):
            break

    hosts = sorted({str(x.get("hostname") or x.get("agent_id") or "") for x in items if x.get("hostname") or x.get("agent_id")})
    return {
        "ok": True,
        "since": since_s,
        "until": now.strftime("%Y-%m-%dT%H:%M:%S"),
        "agent_id": aid,
        "count": len(items),
        "query_info": {
            "source_rows": len(rows),
            "source_limit": 2000,
            "active_rules": len(active_rules),
            "result_limit": max(20, min(int(limit or 300), 800)),
        },
        "stats": {
            "files": len(items),
            "rule_hits": rule_hit_n,
            "unsigned": unsigned_n,
            "hosts": len(hosts),
        },
        "items": items,
    }
