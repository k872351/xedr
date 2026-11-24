# -*- coding: utf-8 -*-
"""告警加白：所有告警入库前（report_event）统一匹配 agent_whitelist，命中则不再产生告警。

条目语义：kind/value 指定对象（进程、路径、哈希、注册表键……），
可选 agent_id 限定主机、rule 限定告警标题（通配），三者同时满足才抑制。
"""
from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

KINDS: Tuple[str, ...] = (
    "title", "process", "path", "hash", "signer", "cmdline", "registry", "domain", "ip",
)

KIND_LABELS = {
    "title": "告警标题", "process": "进程名", "path": "文件路径", "hash": "文件哈希",
    "signer": "签名者", "cmdline": "命令行", "registry": "注册表键", "domain": "域名", "ip": "IP",
}

_FIELD_KEYS: Dict[str, Tuple[str, ...]] = {
    "hash": ("sha256", "hash", "md5", "sha1", "file_sha256", "image_sha256", "process_sha256"),
    "path": ("path", "image", "image_path", "exe", "file_path", "process_path", "target_path",
             "target", "dll", "dll_path", "module_path", "file", "Image", "OriginalFileName"),
    "process": ("process_name", "name", "image_name", "process", "OriginalFileName"),
    "signer": ("signer", "publisher"),
    "cmdline": ("command_line", "cmdline", "command", "CommandLine"),
    "registry": ("key", "reg_key", "registry_key"),
    "domain": ("domain", "query", "qname"),
    "ip": ("remote_ip", "dst_ip", "ip", "remote", "remote_addr"),
}

_PATH_LIKE = ("path", "registry")
# 仅匹配盘符路径，避免从 matched 文本里把 \SOFTWARE\...\xxx.exe 误当成 UNC
_WIN_PATH_RE = re.compile(
    r'(?P<p>[a-zA-Z]:\\[^"<>|\r\n→]+?\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|msi|com))',
    re.I,
)
_ENV_PATH_RE = re.compile(
    r'(?P<p>%(?:windir|systemroot)%\\[^"<>|\r\n→]+?\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|msi|com))',
    re.I,
)
_EXE_EXT = (".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".msi", ".com")


def _expand_env_path(p: str) -> str:
    s = str(p or "")
    low = s.lower()
    if low.startswith("%windir%\\") or low.startswith("%systemroot%\\"):
        return "C:\\Windows\\" + s.split("\\", 1)[1]
    return s


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _norm(s: Any) -> str:
    return str(s or "").strip().lower().replace("/", "\\")


def _basename(p: str) -> str:
    p = str(p or "").replace("/", "\\").rstrip("\\")
    return p.rsplit("\\", 1)[-1]


def _looks_like_win_path(v: str) -> bool:
    s = str(v or "").strip().strip('"')
    if not s:
        return False
    low = s.replace("/", "\\").lower()
    if re.match(r"^[a-z]:\\", low) or low.startswith("\\\\"):
        return True
    if low.startswith("\\device\\harddiskvolume"):
        return True
    return False


def coerce_kind_value(kind: str, value: str) -> Tuple[str, str]:
    """纠正常见误选：完整路径被建成 process/registry → 改成 path。"""
    k = str(kind or "").strip().lower()
    v = str(value or "").strip()
    if not k or not v:
        return k, v
    if k == "process" and _looks_like_win_path(v):
        return "path", v.strip('"')
    if k == "registry" and _looks_like_win_path(v) and not re.match(r"^hk(ey_|[lcmu])", v, re.I):
        return "path", v.strip('"')
    if k == "path":
        v2 = v.strip('"')
        # 通配目录：*\Foo\Bar\ → *\Foo\Bar\*（否则 fnmatch 要求精确以 \ 结尾，盖不住目录下文件）
        if ("*" in v2 or "?" in v2) and v2.endswith("\\"):
            v2 = v2 + "*"
        # 目录加白：无后缀且未以 \ 结尾时自动加 \，按前缀匹配
        elif _looks_like_win_path(v2) and not v2.endswith("\\"):
            base = _basename(v2).lower()
            if "." not in base or not any(base.endswith(ext) for ext in _EXE_EXT):
                v2 = v2.rstrip("\\") + "\\"
        return k, v2
    return k, v


def _path_from_cmdline(cmd: str) -> str:
    s = str(cmd or "").strip()
    if not s:
        return ""
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 1:
            return s[1:end]
    m = _WIN_PATH_RE.search(s)
    return m.group("p") if m else ""


def _strip_port(v: str) -> str:
    v = str(v or "").strip()
    if v.startswith("[") and "]" in v:
        return v[1:v.index("]")]
    if v.count(":") == 1:
        return v.split(":", 1)[0]
    return v


def _flatten(detail: Any) -> Dict[str, Any]:
    if not isinstance(detail, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, v in detail.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if not isinstance(v2, (dict, list)):
                    out.setdefault(str(k2), v2)
        elif isinstance(v, list):
            # PTM chain 等：从列表元素里抽出 path/value，便于加白
            for it in v[:30]:
                if not isinstance(it, dict):
                    continue
                for k2, v2 in it.items():
                    if not isinstance(v2, (dict, list)) and v2 not in (None, ""):
                        out.setdefault(str(k2), v2)
        else:
            out[str(k)] = v
    # 顶层优先于嵌套（evidence 等）
    for k, v in detail.items():
        if not isinstance(v, (dict, list)):
            out[str(k)] = v
    return out


def parse_detail(detail: Any) -> Dict[str, Any]:
    if isinstance(detail, dict):
        return detail
    s = str(detail or "")
    if not s.startswith("{"):
        return {}
    try:
        d = json.loads(s)
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


def _title_display_tail(title: str) -> str:
    t = str(title or "").strip()
    for sep in ("：", ": ", ":"):
        if sep in t:
            tail = t.split(sep, 1)[1].strip()
            if tail:
                return tail
    return ""


def extract_fields(title: str, detail: Any) -> Dict[str, List[str]]:
    """从告警标题 + 详情抽取可加白的对象值。"""
    flat = _flatten(parse_detail(detail))
    fields: Dict[str, List[str]] = {k: [] for k in KINDS}
    fields["title"] = [str(title or "")]
    for kind, keys in _FIELD_KEYS.items():
        for k in keys:
            v = flat.get(k)
            if v in (None, "") or isinstance(v, bool):
                continue
            sv = str(v).strip().strip('"')
            if not sv:
                continue
            if kind == "ip":
                sv = _strip_port(sv)
            if kind == "path" and "\\" not in sv and "/" not in sv:
                continue
            fields[kind].append(sv)
    # 命令行 / 注册表 value / matched 串里常带映像路径，补进 path（PTM 注册表告警尤其如此）
    blob_srcs: List[str] = list(fields["cmdline"])
    for k in ("value", "matched", "summary", "evidence", "Details", "details", "data"):
        v = flat.get(k)
        if v not in (None, "") and not isinstance(v, (dict, list, bool)):
            blob_srcs.append(str(v))
    raw_detail = detail if isinstance(detail, str) else json.dumps(parse_detail(detail), ensure_ascii=False)
    if raw_detail:
        blob_srcs.append(raw_detail)
    for blob in blob_srcs:
        p = _path_from_cmdline(blob)
        if p:
            fields["path"].append(_expand_env_path(p))
        for m in _WIN_PATH_RE.finditer(str(blob)):
            fields["path"].append(m.group("p"))
        for m in _ENV_PATH_RE.finditer(str(blob)):
            fields["path"].append(_expand_env_path(m.group("p")))
    # 注册表键误入 path 时挪回 registry，避免 path 加白对不上真正的 exe
    cleaned_paths: List[str] = []
    for p in fields["path"]:
        low = _norm(p)
        if low.startswith(("hklm\\", "hkcu\\", "hkcr\\", "hku\\", "hkey_")):
            fields["registry"].append(p)
            continue
        cleaned_paths.append(p)
        b = _basename(p)
        if b.lower().endswith(_EXE_EXT):
            fields["process"].append(b)
    fields["path"] = cleaned_paths
    # 标题里偶发带路径
    for m in _WIN_PATH_RE.finditer(str(title or "")):
        fields["path"].append(m.group("p"))
        fields["process"].append(_basename(m.group("p")))
    vn = str(flat.get("value_name") or "").strip()
    if vn:
        for k in list(fields["registry"]):
            fields["registry"].append(k.rstrip("\\") + "\\" + vn)
    label = str(flat.get("label") or "").strip()
    if label and vn:
        fields["registry"].append(label + "\\" + vn)
    tail = _title_display_tail(title)
    if tail:
        fields["registry"].append(tail)
        if "\\" in tail:
            parent = tail.rsplit("\\", 1)[0]
            if parent:
                fields["registry"].append(parent + "\\")
    for kind in fields:
        seen, uniq = set(), []
        for v in fields[kind]:
            n = _norm(v)
            if n and n not in seen:
                seen.add(n)
                uniq.append(v)
        fields[kind] = uniq
    return fields


def _glob(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase(value, pattern.replace("[", "[[]"))


def match_value(kind: str, pattern: str, value: str) -> bool:
    p = _norm(pattern).strip('"')
    raw = str(value or "")
    v = _norm(raw).strip('"')
    if not p or not v:
        return False
    if "*" in p or "?" in p:
        return _glob(p, v) or (kind == "cmdline" and _glob(p, _norm(raw)))
    if kind in _PATH_LIKE:
        if p.endswith("\\"):
            if v.startswith(p):
                return True
            extracted = _norm(_path_from_cmdline(raw))
            if extracted and extracted.startswith(p):
                return True
            # 命令行未抽出路径时，仍允许目录前缀出现在整串中
            return p in _norm(raw)
        # 完整文件路径：精确，或其目录下的文件，或出现在命令行
        if v == p or v.startswith(p + "\\"):
            return True
        if kind == "path" and p in _norm(raw):
            return True
        return False
    if kind == "cmdline":
        return p in v or p in _norm(raw)
    return v == p


def _candidate_values(kind: str, value: str, fields: Dict[str, List[str]]) -> List[str]:
    """按条目类型收集待匹配值；path 同时看命令行抽出的映像路径。"""
    vals = list(fields.get(kind) or [])
    if kind == "path":
        for c in fields.get("cmdline") or []:
            vals.append(c)
            p = _path_from_cmdline(c)
            if p:
                vals.append(p)
    if kind == "process" and _looks_like_win_path(value):
        # 历史误建：process=完整路径 → 按 path + 进程名双通道
        vals.extend(fields.get("path") or [])
        vals.extend(fields.get("cmdline") or [])
        bn = _basename(value)
        if bn:
            vals.extend(fields.get("process") or [])
    if kind == "registry" and _looks_like_win_path(value):
        vals.extend(fields.get("path") or [])
        vals.extend(fields.get("cmdline") or [])
    # 去重保序
    seen, out = set(), []
    for x in vals:
        n = _norm(x)
        if n and n not in seen:
            seen.add(n)
            out.append(x)
    return out


_TRUSTED_PATH_PREFIXES = (
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\windows\\",
)


def normalize_rule(rule: Any) -> str:
    """UI「全部」/空/* 均视为不限定告警标题。"""
    r = str(rule or "").strip()
    if not r:
        return ""
    low = r.lower()
    if low in ("*", "全部", "全部告警", "全部告警标题", "all", "any"):
        return ""
    return r


def entry_matches(entry: Dict[str, Any], agent_id: str, title: str, fields: Dict[str, List[str]]) -> bool:
    if not int(entry.get("enabled", 1) or 0):
        return False
    scope = str(entry.get("agent_id") or "").strip()
    if scope and scope != str(agent_id or ""):
        return False
    rule = normalize_rule(entry.get("rule"))
    if rule and not match_value("title", rule, title):
        return False
    kind = str(entry.get("kind") or "").strip().lower()
    value = str(entry.get("value") or "")
    kind, value = coerce_kind_value(kind, value)
    if kind not in KINDS:
        return False
    # 误建成 process/registry 的路径：匹配时按 path
    match_kind = kind
    if kind in ("process", "registry") and _looks_like_win_path(str(entry.get("value") or "")):
        match_kind = "path"
        value = str(entry.get("value") or "").strip().strip('"')
        _, value = coerce_kind_value("path", value)
    cands = _candidate_values(match_kind, value, fields)
    if any(match_value(match_kind, value, v) for v in cands):
        return True
    # IOC 等告警有时只有进程名、没有路径：对 Program Files / Windows 下的 path 加白
    # 允许用映像名兜底（避免 Edge 路径加白了仍被纯进程名 IOC 打出）
    if match_kind == "path":
        pn = _norm(value)
        if any(pn.startswith(pref) for pref in _TRUSTED_PATH_PREFIXES):
            bn = _basename(value.rstrip("\\"))
            if bn.lower().endswith(_EXE_EXT):
                if any(match_value("process", bn, v) for v in fields.get("process") or []):
                    return True
            elif pn.endswith("\\"):
                # 目录前缀：进程名无法可靠判断，跳过
                pass
    return False
def _entries(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    try:
        rows = conn.execute("SELECT * FROM agent_whitelist WHERE enabled=1").fetchall()
    except sqlite3.Error:
        return []
    return [dict(r) for r in rows]


def find_match(conn: sqlite3.Connection, agent_id: str, title: str, detail: Any) -> Optional[Dict[str, Any]]:
    entries = _entries(conn)
    if not entries:
        return None
    fields = extract_fields(title, detail)
    for e in entries:
        if entry_matches(e, agent_id, title, fields):
            return e
    return None


def record_hit(conn: sqlite3.Connection, entry_id: str) -> None:
    try:
        conn.execute(
            "UPDATE agent_whitelist SET hits=COALESCE(hits,0)+1, last_hit_at=? WHERE id=?",
            (_now(), str(entry_id)),
        )
        conn.commit()
    except sqlite3.Error:
        pass


def rule_prefix(title: str) -> str:
    """告警标题去掉具体对象部分，得到「同类告警」通配，如「注册表安全项变更*」。"""
    t = str(title or "").strip()
    for sep in ("：", ": ", ":"):
        if sep in t:
            head = t.split(sep, 1)[0].strip()
            if head:
                return head + "*"
    return t


def candidates(event: Dict[str, Any]) -> List[Dict[str, str]]:
    """告警详情页「加白」可选项：按价值排序，越具体越靠前。"""
    title = str(event.get("title") or "")
    detail_raw = event.get("detail_obj") or event.get("detail")
    fields = extract_fields(title, detail_raw)
    flat = _flatten(parse_detail(detail_raw))
    et = str(flat.get("etype") or "").lower()
    out: List[Dict[str, str]] = []
    order = ("hash", "path", "process", "registry", "cmdline", "signer", "domain", "ip")
    for kind in order:
        for v in fields.get(kind, [])[:3]:
            out.append({"kind": kind, "value": v[:500], "label": KIND_LABELS[kind]})
    out.append({"kind": "title", "value": title[:500], "label": "完全相同的告警"})
    rp = rule_prefix(title)
    if rp and rp != title:
        out.append({"kind": "title", "value": rp[:500], "label": "同类告警（标题通配）"})
    if et in ("registry_set", "registry_delete", "persist_add", "persist_modify", "persist_delete"):
        tail = _title_display_tail(title)
        if tail and not any(x.get("value") == tail for x in out):
            out.insert(0, {
                "kind": "registry",
                "value": tail[:500],
                "label": "监控项（标题中的 FIM/持久化路径，推荐同类）",
            })
        if label := str(flat.get("label") or "").strip():
            prefix = label + "\\"
            if not any(x.get("value") == prefix for x in out):
                out.insert(0, {
                    "kind": "registry",
                    "value": prefix[:500],
                    "label": f"整类监控标签「{label}」（其下所有子项）",
                })
    return out


def default_allow_pick_indices(items: List[Dict[str, str]], event: Dict[str, Any]) -> List[int]:
    """加白对话框默认勾选：注册表/FIM 类优先「标题通配」或监控标签前缀。"""
    if not items:
        return []
    title = str(event.get("title") or "")
    detail_raw = event.get("detail_obj") or event.get("detail")
    flat = _flatten(parse_detail(detail_raw))
    et = str(flat.get("etype") or "").lower()
    if et not in ("registry_set", "registry_delete", "persist_add", "persist_modify", "persist_delete"):
        return [0]
    rp = rule_prefix(title)
    for i, it in enumerate(items):
        if it.get("kind") == "title" and it.get("value") == rp and "通配" in str(it.get("label") or ""):
            return [i]
    for i, it in enumerate(items):
        if it.get("kind") == "registry" and "整类监控标签" in str(it.get("label") or ""):
            return [i]
    return [0]


def repair_misclassified_entries(conn: sqlite3.Connection) -> int:
    """把已入库的错误类型（完整路径写成 process/registry）改成 path，并规范目录前缀。"""
    try:
        rows = conn.execute("SELECT id, kind, value FROM agent_whitelist").fetchall()
    except sqlite3.Error:
        return 0
    fixed = 0
    for r in rows:
        old_k = str(r["kind"] or "")
        old_v = str(r["value"] or "")
        new_k, new_v = coerce_kind_value(old_k, old_v)
        if new_k == old_k and new_v == old_v:
            continue
        try:
            conn.execute("UPDATE agent_whitelist SET kind=?, value=? WHERE id=?", (new_k, new_v, r["id"]))
            fixed += 1
        except sqlite3.Error:
            pass
    if fixed:
        try:
            conn.commit()
        except sqlite3.Error:
            pass
    return fixed


def apply_all_enabled(conn: sqlite3.Connection, *, limit: int = 5000) -> int:
    """把当前全部启用的加白条目套到未处置告警上。"""
    repair_misclassified_entries(conn)
    n = 0
    for entry in _entries(conn):
        n += apply_to_open_events(conn, entry, limit=limit)
    return n


def apply_to_open_events(conn: sqlite3.Connection, entry: Dict[str, Any], *, limit: int = 5000) -> int:
    """新加白条目回溯：把已存在、命中的未处置告警标为「无需处置」。"""
    rows = conn.execute(
        "SELECT id, agent_id, title, detail FROM agent_events WHERE status='open' ORDER BY id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    ids: List[int] = []
    for r in rows:
        if entry_matches(entry, r["agent_id"], r["title"] or "", extract_fields(r["title"] or "", r["detail"])):
            ids.append(int(r["id"]))
    now = _now()
    for chunk in _chunks(ids, 400):
        conn.execute(
            f"UPDATE agent_events SET status='ignored', updated_at=? WHERE id IN ({','.join('?' * len(chunk))})",
            (now, *chunk),
        )
    if ids:
        conn.commit()
    return len(ids)


def _chunks(seq: List[int], n: int) -> Iterable[List[int]]:
    for i in range(0, len(seq), n):
        yield seq[i:i + n]
