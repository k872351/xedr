"""Normalize process family details for report presentation."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


def _proc_pid(item: Dict[str, Any]) -> int:
    try:
        return int(item.get("pid") if item.get("pid") is not None else item.get("PID") or 0)
    except (TypeError, ValueError):
        return 0


def _proc_ppid(item: Dict[str, Any]) -> int:
    try:
        return int(item.get("ppid") if item.get("ppid") is not None else item.get("PPID") or 0)
    except (TypeError, ValueError):
        return 0


def _enrich_process_family(target: Dict[str, Any], all_procs: List[Any]) -> Dict[str, Any]:
    """把 children 的纯 PID 列表解析成带 name/path 的 child_details，并补全父进程。"""
    by_pid: Dict[int, Dict[str, Any]] = {}
    for p in all_procs or []:
        if not isinstance(p, dict):
            continue
        pid = _proc_pid(p)
        if pid:
            by_pid[pid] = p

    out = dict(target)
    my_pid = _proc_pid(out)
    ppid = _proc_ppid(out)
    parent = by_pid.get(ppid) if ppid and ppid != my_pid else None
    if parent:
        out["parent_name"] = str(parent.get("name") or out.get("parent_name") or "")
        out["parent_path"] = str(parent.get("path") or "")
        out["parent_command_line"] = str(
            parent.get("command_line") or parent.get("command") or parent.get("CommandLine") or ""
        )

    kids_raw = out.get("children") if out.get("children") is not None else out.get("Children")
    if not isinstance(kids_raw, list):
        kids_raw = []
    child_details: List[Dict[str, Any]] = []
    seen: Set[int] = set()

    def _push_child(cpid: int, src: Optional[Dict[str, Any]] = None) -> None:
        if not cpid or cpid in seen or cpid == my_pid:
            return
        seen.add(cpid)
        ch = src or by_pid.get(cpid) or {}
        child_details.append({
            "pid": cpid,
            "name": str(ch.get("name") or ""),
            "path": str(ch.get("path") or ""),
            "command_line": str(ch.get("command_line") or ch.get("command") or ch.get("CommandLine") or ""),
            "user": str(ch.get("user") or ch.get("User") or ""),
        })

    for k in kids_raw:
        if isinstance(k, dict):
            _push_child(_proc_pid(k), k)
            continue
        try:
            _push_child(int(k))
        except (TypeError, ValueError):
            continue

    # 按 PPID 回扫，避免旧报告 children 为空或不全
    if my_pid:
        for p in all_procs or []:
            if not isinstance(p, dict):
                continue
            if _proc_ppid(p) == my_pid:
                _push_child(_proc_pid(p), p)

    child_details.sort(key=lambda x: int(x.get("pid") or 0))
    out["child_details"] = child_details
    out["children"] = [int(c["pid"]) for c in child_details if c.get("pid")]
    return out
def _slim_process_for_list(
    item: Any,
    *,
    sig_index: Optional[Dict[str, Dict[str, Any]]] = None,
    rid: str = "",
) -> Dict[str, Any]:
    """进程列表不下发 DLL/模块明细；点击详情时再按 PID 读取。预聚合白加黑计数。"""
    if not isinstance(item, dict):
        return {}
    out = dict(item)
    raw_for_count = dict(item)
    if sig_index:
        try:
            from .matchers.windows_process import enrich_process_modules_from_file_sigs
            enrich_process_modules_from_file_sigs(raw_for_count, sig_index)
        except Exception:
            pass
    out.pop("modules", None)
    out.pop("Modules", None)
    out.pop("dlls", None)
    out.pop("DLLs", None)
    try:
        from .matchers.windows_process import _iter_modules, _unsigned_modules, _process_host_signed_ok
    except Exception:
        _iter_modules = None  # type: ignore
        _unsigned_modules = None  # type: ignore
        _process_host_signed_ok = None  # type: ignore

    mods = _iter_modules(raw_for_count) if _iter_modules else []
    out["module_count"] = len(mods)
    unsigned_n = 0
    report_ctx: Optional[Dict[str, Any]] = None
    if rid:
        report_ctx = {
            "_rid": rid,
            "_files_rid": rid,
            "file_scans": [],
            "processes": [raw_for_count],
            "startup_items": [raw_for_count],
        }
    if _unsigned_modules:
        try:
            rule = {
                "moduleSameDirOnly": True,
                "moduleExcludeSystemPaths": True,
                "moduleExtAny": ["exe", "dll", "sys"],
                "moduleRequireExplicitUnsigned": True,
            }
            unsigned_n = len(_unsigned_modules(raw_for_count, rule, report_ctx))
        except Exception:
            unsigned_n = 0
    out["unsigned_module_count"] = unsigned_n
    out["dirty_unsigned_module_count"] = unsigned_n
    host_signed = False
    st = str(out.get("sig_status") or out.get("SigStatus") or "").strip().lower()
    if out.get("signed") is True or st in ("valid", "signed") or "valid" in st:
        host_signed = True
    elif _process_host_signed_ok:
        try:
            host_signed = bool(_process_host_signed_ok(
                raw_for_count,
                {"requireHostSigned": True, "requireUnsignedModule": True},
                report_ctx,
            ))
        except Exception:
            pass
    # Linux：软件包归属 ≠ Authenticode 白加黑
    path0 = str(out.get("path") or out.get("image_path") or "")
    if path0.startswith("/") or str(out.get("sig_type") or "") in ("package", "kernel"):
        out["sideload_suspect"] = False
        out["unsigned_module_count"] = 0
        out["dirty_unsigned_module_count"] = 0
    else:
        out["sideload_suspect"] = bool(host_signed and unsigned_n > 0)
    out["process_detail_lazy"] = True
    return out
