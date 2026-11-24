"""File inventory query operations for report databases."""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from . import paths as P
from .db_store import _FILE_TREE_COLS, _file_row_to_tree_item
from .file_normalization import _norm_ext, _norm_file_path
from .report_db_connection import _connect
from .report_directory_index import _ensure_directory_index
from .report_schema import _init_schema


def query_files(
    rid: str,
    *,
    exts: Optional[List[str]] = None,
    path_contains: Optional[str] = None,
    name_contains: Optional[str] = None,
    name_like: Optional[str] = None,
    min_size: int = 0,
    limit: int = 80,
) -> List[Dict[str, Any]]:
    """按扩展名/路径/文件名从 files 表取候选，避免全表 Python 循环。"""
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return []
    where = ["1=1"]
    args: List[Any] = []
    if exts:
        norms = [_norm_ext(x) for x in exts if str(x).strip()]
        norms = [x for x in norms if x]
        if norms:
            ph = ",".join("?" * len(norms))
            where.append(f"ext IN ({ph})")
            args.extend(norms)
    if path_contains:
        # 用路径片段 LIKE，兼容单/双反斜杠与正斜杠。
        # 目录意图（原文以 \ / 结尾）时强制后接分隔符，避免 drivers ⊂ driverstore。
        raw_pc = str(path_contains).strip()
        parts = [p for p in re.split(r"[/\\]+", raw_pc) if p]
        if parts:
            core = "/".join(p.lower() for p in parts)
            if raw_pc.endswith(("/", "\\")):
                like = "%" + core + "/%"
            else:
                like = "%" + core + "%"
            where.append("lower(replace(full_path,'\\','/')) LIKE ?")
            args.append(like)
        else:
            where.append("instr(lower(replace(full_path,'/','\\')), ?) > 0")
            args.append(str(path_contains).lower().replace("/", "\\"))
    if name_contains:
        where.append("instr(lower(name), ?) > 0")
        args.append(str(name_contains).lower())
    if name_like:
        where.append("lower(name) LIKE ?")
        args.append(str(name_like).lower())
    if min_size and int(min_size) > 0:
        where.append("size >= ?")
        args.append(int(min_size))
    sql = (
        "SELECT full_path,name,path,ext,size,company,product,description,file_version,"
        "signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system,content "
        f"FROM files WHERE {' AND '.join(where)} LIMIT ?"
    )
    args.append(max(1, min(int(limit or 80), 5000)))
    conn = _connect(Path(dbp))
    try:
        try:
            rows = conn.execute(sql, args).fetchall()
        except sqlite3.OperationalError:
            # 旧库尚无 content 列
            sql_legacy = (
                "SELECT full_path,name,path,ext,size,company,product,description,file_version,"
                "signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system "
                f"FROM files WHERE {' AND '.join(where)} LIMIT ?"
            )
            rows = conn.execute(sql_legacy, args).fetchall()
        out = []
        for r in rows:
            keys = r.keys()
            item = {
                "full_path": r["full_path"] or "",
                "name": r["name"] or "",
                "path": r["path"] or "",
                "ext": r["ext"] or "",
                "size": r["size"] or 0,
                "company": r["company"] if "company" in keys else "",
                "product": r["product"] if "product" in keys else "",
                "description": r["description"] if "description" in keys else "",
                "file_version": r["file_version"] if "file_version" in keys else "",
                "signed": bool(r["signed"]),
                "signer": r["signer"] or "",
                "sig_status": r["sig_status"] or "",
                "sig_type": r["sig_type"] if "sig_type" in keys else "",
                "magic_hex": r["magic_hex"] or "",
                "md5": r["md5"] if "md5" in keys else "",
                "sha1": r["sha1"] if "sha1" in keys else "",
                "sha256": r["sha256"] if "sha256" in keys else "",
                "hidden": bool(r["hidden"]),
                "system": bool(r["system"]),
            }
            if "content" in keys and r["content"]:
                item["content"] = r["content"]
            out.append(item)
        return out
    except Exception:
        return []
    finally:
        conn.close()


def query_files_under_dir(
    rid: str, dir_path: str, limit: int = 300, offset: int = 0,
) -> Dict[str, Any]:
    """列出目录下的直接子文件（path 列 = 父目录），供可疑目录详情弹窗。"""
    d = (dir_path or "").replace("/", "\\")
    d = re.sub(r"\\+", r"\\", d).rstrip("\\")
    if not d:
        return {"items": [], "total": 0, "path": ""}
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return {"items": [], "total": 0, "path": d}
    needle = _norm_file_path(d)
    lim = max(1, min(int(limit or 300), 2000))
    off = max(0, int(offset or 0))
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        _ensure_directory_index(conn)
        cols = (
            "full_path,name,path,ext,size,company,product,description,file_version,"
            "signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system"
        )
        total = int(
            conn.execute(
                "SELECT COUNT(1) FROM files WHERE parent_path_norm=?", (needle,),
            ).fetchone()[0] or 0
        )
        rows = conn.execute(
            f"SELECT {cols} FROM files WHERE parent_path_norm=? "
            "ORDER BY name COLLATE NOCASE, full_path COLLATE NOCASE LIMIT ? OFFSET ?",
            (needle, lim, off),
        ).fetchall()
        items = []
        for r in rows:
            keys = r.keys()
            items.append({
                "full_path": r["full_path"] or "",
                "name": r["name"] or "",
                "path": r["path"] or "",
                "ext": r["ext"] or "",
                "size": r["size"] or 0,
                "company": r["company"] if "company" in keys else "",
                "product": r["product"] if "product" in keys else "",
                "description": r["description"] if "description" in keys else "",
                "file_version": r["file_version"] if "file_version" in keys else "",
                "signed": bool(r["signed"]),
                "signer": r["signer"] or "",
                "sig_status": r["sig_status"] or "",
                "sig_type": r["sig_type"] if "sig_type" in keys else "",
                "magic_hex": r["magic_hex"] or "",
                "md5": r["md5"] if "md5" in keys else "",
                "sha1": r["sha1"] if "sha1" in keys else "",
                "sha256": r["sha256"] if "sha256" in keys else "",
                "hidden": bool(r["hidden"]) if "hidden" in keys else False,
                "system": bool(r["system"]) if "system" in keys else False,
                "dir": False,
            })
        return {
            "items": items, "total": total, "offset": off, "limit": lim, "path": d,
            "has_next": off + len(items) < total, "truncated": off + len(items) < total,
        }
    except Exception as e:
        print(f"[db_store] query_files_under_dir: {e}")
        return {"items": [], "total": 0, "path": d}
    finally:
        conn.close()


def query_dir_subtree_stats(rid: str, dir_paths: Any) -> Dict[str, Dict[str, int]]:
    """按目录返回子树统计：direct_files / subtree_files / subdirs。

    目录聚合规则的 min/maxFileCount 原来只看直接子文件，
    「直接放 3 个文件、子目录里塞几十个」的大软件树会被当成小型白加黑目录命中。
    这里给出整棵子树的文件数与子目录数，供规则判定用。
    返回 key 为 _norm_file_path(dir) 归一化路径。

    子树用区间比较（>= 'dir\\' AND < 'dir\\' + U+FFFF）而不是 LIKE：
    parent_path_norm 已经是小写归一化值，区间谓词能走 idx_files_parent_norm，
    LIKE 因为默认大小写不敏感走不了索引。
    """
    if isinstance(dir_paths, str):
        dir_paths = [dir_paths]
    wanted: List[str] = []
    seen: Set[str] = set()
    for d in dir_paths or []:
        norm = _norm_file_path(d)
        if norm and norm not in seen:
            seen.add(norm)
            wanted.append(norm)
    if not wanted:
        return {}
    out: Dict[str, Dict[str, int]] = {
        d: {"direct_files": 0, "subtree_files": 0, "subdirs": 0} for d in wanted
    }
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return out
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        _ensure_directory_index(conn)
        for norm in wanted:
            lo = norm + "\\"
            hi = norm + "\\￿"
            direct = int(
                conn.execute(
                    "SELECT COUNT(1) FROM files WHERE parent_path_norm=?", (norm,),
                ).fetchone()[0] or 0
            )
            deep = int(
                conn.execute(
                    "SELECT COUNT(1) FROM files WHERE parent_path_norm>=? AND parent_path_norm<?",
                    (lo, hi),
                ).fetchone()[0] or 0
            )
            subdirs = int(
                conn.execute(
                    "SELECT COUNT(1) FROM file_directories "
                    "WHERE parent_path_norm=? OR (parent_path_norm>=? AND parent_path_norm<?)",
                    (norm, lo, hi),
                ).fetchone()[0] or 0
            )
            out[norm] = {
                "direct_files": direct,
                "subtree_files": direct + deep,
                "subdirs": subdirs,
            }
        return out
    except Exception as e:
        print(f"[db_store] query_dir_subtree_stats: {e}")
        return out
    finally:
        conn.close()


def query_file_directory(
    rid: str,
    dir_path: str = "",
    *,
    offset: int = 0,
    limit: int = 300,
    q: str = "",
    hidden_only: bool = False,
) -> Dict[str, Any]:
    """Return one directory level: child directories first, then direct files."""
    display_path = re.sub(
        r"\\+", r"\\", str(dir_path or "").replace("/", "\\").strip(),
    ).rstrip("\\")
    parent_norm = _norm_file_path(display_path)
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return {
            "items": [], "total": 0, "offset": 0, "limit": limit,
            "has_next": False, "path": display_path,
        }
    off = max(0, int(offset or 0))
    lim = max(1, min(2000, int(limit or 300)))
    ql = str(q or "").strip().lower()
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        _ensure_directory_index(conn)
        dir_where = ["d.parent_path_norm=?"]
        dir_args: List[Any] = [parent_norm]
        file_where = ["f.parent_path_norm=?"]
        file_args: List[Any] = [parent_norm]
        if ql:
            from .search_sql import LIKE_ESCAPE, classify, glob_to_like, has_glob_meta
            if has_glob_meta(ql):
                like = glob_to_like(ql).lower()
                esc = LIKE_ESCAPE
                dir_where.append(
                    f"(lower(d.name) LIKE ? ESCAPE '{esc}' OR lower(d.full_path) LIKE ? ESCAPE '{esc}')"
                )
                dir_args.extend([like, like])
                file_where.append(
                    f"(lower(f.name) LIKE ? ESCAPE '{esc}' OR lower(f.full_path) LIKE ? ESCAPE '{esc}')"
                )
                file_args.extend([like, like])
            else:
                dir_where.append("(lower(d.name) LIKE ? OR lower(d.full_path) LIKE ?)")
                dir_args.extend([f"%{ql}%", f"%{ql}%"])
                file_where.append(
                    "(lower(f.name) LIKE ? OR lower(f.full_path) LIKE ? "
                    "OR lower(IFNULL(f.company,'')) LIKE ? OR lower(IFNULL(f.signer,'')) LIKE ? "
                    "OR lower(IFNULL(f.ext,'')) LIKE ? OR lower(REPLACE(IFNULL(f.ext,''), '.', '')) LIKE ?)"
                )
                file_args.extend([f"%{ql}%", f"%{ql}%", f"%{ql}%", f"%{ql}%", f"%{ql}%", f"%{ql.lstrip('.')}%"])
        if hidden_only:
            file_where.append("(f.hidden=1 OR f.system=1)")
            dir_where.append(
                "EXISTS (SELECT 1 FROM files hf WHERE (hf.hidden=1 OR hf.system=1) AND "
                "(hf.parent_path_norm=d.path_norm OR "
                "substr(hf.parent_path_norm,1,length(d.path_norm)+1)=d.path_norm||'\\'))"
            )
        dir_sql_where = " AND ".join(dir_where)
        file_sql_where = " AND ".join(file_where)
        dir_total = int(
            conn.execute(
                f"SELECT COUNT(1) FROM file_directories d WHERE {dir_sql_where}", dir_args,
            ).fetchone()[0] or 0
        )
        file_total = int(
            conn.execute(
                f"SELECT COUNT(1) FROM files f WHERE {file_sql_where}", file_args,
            ).fetchone()[0] or 0
        )
        items: List[Dict[str, Any]] = []
        if off < dir_total:
            directory_rows = conn.execute(
                "SELECT d.path_norm,d.parent_path_norm,d.name,d.full_path,"
                "EXISTS(SELECT 1 FROM file_directories c WHERE c.parent_path_norm=d.path_norm) "
                "OR EXISTS(SELECT 1 FROM files f WHERE f.parent_path_norm=d.path_norm) AS has_children "
                f"FROM file_directories d WHERE {dir_sql_where} "
                "ORDER BY d.name COLLATE NOCASE LIMIT ? OFFSET ?",
                dir_args + [lim, off],
            ).fetchall()
            items.extend({
                "name": r["name"] or "",
                "full_path": r["full_path"] or "",
                "path": str(r["full_path"] or "").replace("\\", "/"),
                "dir": True,
                "has_children": bool(r["has_children"]),
                "children": [],
            } for r in directory_rows)
        remaining = lim - len(items)
        file_offset = max(0, off - dir_total)
        if remaining > 0 and file_offset < file_total:
            rows = conn.execute(
                f"SELECT {_FILE_TREE_COLS},(IFNULL(f.content,'')!='') AS has_content "
                f"FROM files f WHERE {file_sql_where} "
                "ORDER BY f.name COLLATE NOCASE,f.full_path COLLATE NOCASE LIMIT ? OFFSET ?",
                file_args + [remaining, file_offset],
            ).fetchall()
            for row in rows:
                item = _file_row_to_tree_item(row)
                item["name_path"] = item.get("path") or ""
                item["path"] = str(item.get("full_path") or "").replace("\\", "/")
                item["file"] = True
                item["dir"] = False
                items.append(item)
        total = dir_total + file_total
        return {
            "items": items,
            "total": total,
            "offset": off,
            "limit": lim,
            "has_next": off + len(items) < total,
            "path": display_path,
            "directory_total": dir_total,
            "file_total": file_total,
        }
    finally:
        conn.close()
