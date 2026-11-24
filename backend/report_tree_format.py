"""Presentation helpers for persisted report file trees."""
from __future__ import annotations

from typing import Any, Dict, List


def _root_where_clause(root: str, root_sql: Dict[str, str]):
    tag = (root or "").strip()
    if not tag:
        return None
    if tag in root_sql:
        return root_sql[tag]
    if tag == "Other":
        parts = [f"NOT ({root_sql[key]})" for key in ("Users", "ProgramData", "ProgramFiles", "ProgramFilesX86", "Windows")]
        return "(" + " AND ".join(parts) + ")"
    return None


def _file_row_to_tree_item(r) -> Dict[str, Any]:
    item = {
        "full_path": r["full_path"], "name": r["name"], "path": r["path"],
        "ext": r["ext"] if "ext" in r.keys() else "",
        "size": r["size"] if "size" in r.keys() else 0,
    }
    for key in (
        "company", "product", "description", "file_version", "signer", "sig_status", "sig_type", "magic_hex",
        "md5", "sha1", "sha256", "mtime", "mode", "owner",
    ):
        if key in r.keys():
            item[key] = r[key] or ""
    if "file_group" in r.keys():
        item["group"] = item["file_group"] = r["file_group"] or ""
    for key in ("signed", "hidden", "system", "has_content"):
        if key in r.keys():
            item[key] = bool(r[key])
    return item


def _build_files_tree(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """在服务端一次构树，避免浏览器下载文件后又整包 POST 回来。"""
    root: Dict[str, Any] = {"name": "", "path": "", "dir": True, "children": [], "_map": {}}

    for f in files or []:
        full = str(f.get("full_path") or "").replace("\\", "/")
        parts = [p for p in full.split("/") if p]
        if not parts:
            continue
        node = root
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            bucket = node.setdefault("_map", {})
            child = bucket.get(part)
            if child is None:
                child = {
                    "name": part,
                    "path": f"{node.get('path')}/{part}".lstrip("/") if node.get("path") else part,
                    "children": [],
                    "_map": {},
                }
                if last:
                    child["file"] = True
                    child["size"] = f.get("size", 0)
                    child["ext"] = f.get("ext", "")
                    child["full_path"] = f.get("full_path", "")
                    child["name_path"] = f.get("path", "")
                    for k in (
                        "company", "product", "description", "file_version", "signed",
                        "signer", "sig_status", "magic_hex", "hidden", "system",
                    ):
                        if f.get(k) not in (None, ""):
                            child[k] = f.get(k)
                else:
                    child["dir"] = True
                bucket[part] = child
                node["children"].append(child)
            node = child

    def finish(node: Dict[str, Any]) -> None:
        node.pop("_map", None)
        children = node.get("children") or []
        for child in children:
            finish(child)
        children.sort(key=lambda x: (0 if x.get("dir") else 1, str(x.get("name") or "").lower()))

    finish(root)
    return root["children"]


def _parse_mtime_bound(raw: str) -> str:
    """把前端 datetime-local / ISO 时间规范成 'YYYY-MM-DD HH:MM:SS'，空则返回 ''。"""
    from datetime import datetime

    s = str(raw or "").strip().replace("T", " ").replace("Z", "")
    if not s:
        return ""
    if len(s) > 19 and s[19] in "+-.":
        s = s[:19]
    for n, fmt in ((19, "%Y-%m-%d %H:%M:%S"), (16, "%Y-%m-%d %H:%M"), (10, "%Y-%m-%d")):
        if len(s) < n:
            continue
        try:
            return datetime.strptime(s[:n], fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return ""
