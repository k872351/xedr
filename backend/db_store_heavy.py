# -*- coding: utf-8 -*-
"""报告超大 file_scans / event_logs 的暂存、装回与入库剥离（从 db_store 拆出）。

暂存格式：gzip 压缩 JSON（禁止 pickle 反序列化，规避任意代码执行风险）。
兼容读取历史 `_park_*.pkl` 时仅允许安全 Unpickler，读后改写为 JSON 并删除 pkl。
"""
from __future__ import annotations

import gzip
import io
import json
import pickle
from pathlib import Path
from typing import Any, Dict, List

from . import paths as P
from .report_blob_metadata import _derive_file_scan_roots
from .report_db_connection import _connect
from .report_ingest import _meta_int, ingest_event_logs, ingest_file_scans
from .report_json import _jdump

_PARK_FILES = "_park_file_scans.json.gz"
_PARK_EVENTS = "_park_event_logs.json.gz"
_LEGACY_FILES = "_park_file_scans.pkl"
_LEGACY_EVENTS = "_park_event_logs.pkl"

_SAFE_PICKLE = frozenset({
    ("builtins", "list"), ("builtins", "dict"), ("builtins", "str"),
    ("builtins", "int"), ("builtins", "float"), ("builtins", "bool"),
    ("builtins", "tuple"), ("builtins", "set"),
    ("collections", "OrderedDict"),
})


class _SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):  # noqa: ANN001
        if (module, name) in _SAFE_PICKLE:
            return getattr(__import__(module, fromlist=[name]), name)
        raise pickle.UnpicklingError(f"refusing to unpickle {module}.{name}")


def _park_path(rid: str, name: str) -> Path:
    return P.report_dir(rid, create=True) / name


def _dump_json_gz(path: Path, data: List[Any]) -> None:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with gzip.open(path, "wb", compresslevel=3) as fh:
        fh.write(raw)


def _load_json_gz(path: Path) -> List[Any]:
    with gzip.open(path, "rb") as fh:
        data = json.loads(fh.read().decode("utf-8"))
    if not isinstance(data, list):
        raise ValueError("parked payload must be a list")
    return data


def _load_legacy_pickle(path: Path) -> List[Any]:
    with open(path, "rb") as fh:
        data = _SafeUnpickler(fh).load()
    if not isinstance(data, list):
        raise ValueError("legacy parked payload must be a list")
    return data


def _load_parked_list(rid: str, json_name: str, legacy_name: str) -> List[Any]:
    jp = P.report_dir(rid) / json_name
    if jp.is_file():
        return _load_json_gz(jp)
    lp = P.report_dir(rid) / legacy_name
    if not lp.is_file():
        return []
    try:
        data = _load_legacy_pickle(lp)
        # 迁移到安全格式后删除旧 pickle
        try:
            _dump_json_gz(_park_path(rid, json_name), data)
            lp.unlink(missing_ok=True)
        except Exception:
            pass
        return data
    except Exception as e:
        print(f"[db_store] refuse unsafe/corrupt legacy park {legacy_name}: {e}")
        try:
            lp.unlink(missing_ok=True)
        except OSError:
            pass
        return []


def park_heavy_arrays(rid: str, report: Dict[str, Any]) -> Dict[str, int]:
    """上传热路径：把超大 file_scans / event_logs 暂存为 gzip JSON，立刻瘦身。"""
    files = report.get("file_scans") if isinstance(report.get("file_scans"), list) else []
    events = report.get("event_logs") if isinstance(report.get("event_logs"), list) else []
    n_files = len(files) if isinstance(files, list) else 0
    n_ev = len(events) if isinstance(events, list) else 0
    if n_files:
        _dump_json_gz(_park_path(rid, _PARK_FILES), files)
        report["file_scans"] = []
    if n_ev:
        _dump_json_gz(_park_path(rid, _PARK_EVENTS), events)
        report["event_logs"] = []
    if n_files:
        report["_files_count"] = n_files
        report["_files_ingested"] = False
    if n_ev:
        report["_event_logs_count"] = n_ev
        report["_event_logs_ingested"] = False
    if n_files or n_ev:
        report["_heavy_parked"] = True
    return {"files": n_files, "event_logs": n_ev}


def load_parked_heavy(rid: str, report: Dict[str, Any]) -> Dict[str, int]:
    """分析任务：把上传时暂存的大数组装回 report，供 ingest。"""
    n_files = 0
    n_ev = 0
    files = report.get("file_scans") if isinstance(report.get("file_scans"), list) else []
    events = report.get("event_logs") if isinstance(report.get("event_logs"), list) else []
    if not files:
        try:
            parked = _load_parked_list(rid, _PARK_FILES, _LEGACY_FILES)
            if parked:
                report["file_scans"] = parked
                n_files = len(parked)
        except Exception as e:
            print(f"[db_store] load parked files: {e}")
    if not events:
        try:
            parked = _load_parked_list(rid, _PARK_EVENTS, _LEGACY_EVENTS)
            if parked:
                report["event_logs"] = parked
                n_ev = len(parked)
        except Exception as e:
            print(f"[db_store] load parked events: {e}")
    return {"files": n_files, "event_logs": n_ev}


def clear_parked_heavy(rid: str) -> None:
    for name in (_PARK_FILES, _PARK_EVENTS, _LEGACY_FILES, _LEGACY_EVENTS):
        p = P.report_dir(rid) / name
        try:
            if p.is_file():
                p.unlink()
        except OSError:
            pass


def detach_and_ingest_heavy(rid: str, report: Dict[str, Any], cancel_check=None) -> Dict[str, int]:
    """把超大 file_scans / event_logs 写入 SQLite，并从 report 字典剥离，便于瘦身落盘。"""
    from .db_store import _patch_index_file_count

    files = report.get("file_scans") if isinstance(report.get("file_scans"), list) else []
    events = report.get("event_logs") if isinstance(report.get("event_logs"), list) else []
    roots = report.get("file_scan_roots") if isinstance(report.get("file_scan_roots"), dict) else None

    n_files = 0
    n_ev = 0
    try:
        if files:
            if not roots:
                roots = _derive_file_scan_roots(files)
            n_files = ingest_file_scans(rid, files, cancel_check=cancel_check)
        else:
            n_files = _meta_int(rid, "count_file_scans", 0)
            if n_files <= 0:
                dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
                if Path(dbp).is_file():
                    conn = _connect(Path(dbp))
                    try:
                        n_files = int(conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"] or 0)
                    except Exception:
                        n_files = 0
                    finally:
                        conn.close()
        if events:
            n_ev = ingest_event_logs(rid, events, cancel_check=cancel_check)
        else:
            n_ev = _meta_int(rid, "count_event_logs", 0)
            if n_ev <= 0:
                dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
                if Path(dbp).is_file():
                    conn = _connect(Path(dbp))
                    try:
                        n_ev = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
                    except Exception:
                        n_ev = 0
                    finally:
                        conn.close()
    except InterruptedError:
        raise
    except Exception as e:
        print(f"[db_store] detach_and_ingest_heavy: {e}")

    if roots:
        report["file_scan_roots"] = roots
        try:
            dbp = P.db_path_for_write(rid)
            if Path(dbp).is_file():
                conn = _connect(dbp)
                try:
                    conn.execute(
                        "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                        ("file_scan_roots", _jdump(roots)),
                    )
                    conn.commit()
                finally:
                    conn.close()
        except Exception:
            pass

    report["file_scans"] = []
    report["event_logs"] = []
    report["_files_count"] = int(n_files or 0)
    report["_files_ingested"] = True
    report["_event_logs_count"] = int(n_ev or 0)
    report["_event_logs_ingested"] = True
    try:
        if n_files:
            _patch_index_file_count(rid, int(n_files))
    except Exception:
        pass
    return {"files": int(n_files or 0), "event_logs": int(n_ev or 0)}


def rewrite_report_json_slim(rid: str, report: Dict[str, Any]) -> None:
    """覆盖写入瘦身 report.json（无大数组），降低后续分析加载成本。"""
    try:
        from .store import save_report
        save_report(report, rid, ingest_heavy=False)
    except Exception as e:
        print(f"[db_store] rewrite slim report: {e}")


def ensure_heavy_ready(rid: str, report: Dict[str, Any], cancel_check=None) -> Dict[str, int]:
    """分析加载时：若内存/磁盘仍有大数组则入库并剥离；已入库则只打标记。"""
    from .stage_timer import StageTimer
    t = StageTimer("job_timing", "heavy_ready", rid=rid)
    pack_stats = {"files": 0, "event_logs": 0}
    try:
        from .collect_pack import ingest_pack_jsonl
        with t.step("pack_jsonl"):
            pack_stats = ingest_pack_jsonl(rid, cancel_check=cancel_check) or {}
    except InterruptedError:
        raise
    except Exception as e:
        print(f"[db_store] pack jsonl ingest: {e}")
    with t.step("unpark"):
        load_parked_heavy(rid, report)
    files = report.get("file_scans") if isinstance(report.get("file_scans"), list) else []
    events = report.get("event_logs") if isinstance(report.get("event_logs"), list) else []
    fat = len(files) >= 500 or len(events) >= 200
    if files or events:
        t.set(files=len(files), events=len(events))
        with t.step("ingest"):
            stats = detach_and_ingest_heavy(rid, report, cancel_check=cancel_check)
        if fat:
            with t.step("slim"):
                rewrite_report_json_slim(rid, report)
        with t.step("cleanup"):
            clear_parked_heavy(rid)
        t.emit()
        return stats
    n_files = _meta_int(rid, "count_file_scans", 0)
    n_ev = _meta_int(rid, "count_event_logs", 0)
    if n_files <= 0:
        dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
        if Path(dbp).is_file():
            conn = _connect(Path(dbp))
            try:
                n_files = int(conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"] or 0)
            except Exception:
                pass
            finally:
                conn.close()
    if n_ev <= 0:
        dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
        if Path(dbp).is_file():
            conn = _connect(Path(dbp))
            try:
                n_ev = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
            except Exception:
                pass
            finally:
                conn.close()
    report["file_scans"] = []
    report["event_logs"] = []
    report["_files_count"] = n_files
    report["_files_ingested"] = True
    report["_event_logs_count"] = n_ev
    report["_event_logs_ingested"] = True
    if t.total_ms >= 50:
        t.emit(files=n_files, events=n_ev)
    _ = pack_stats
    return {"files": n_files, "event_logs": n_ev}
