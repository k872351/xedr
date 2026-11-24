"""日志检测规则包：log_rules（精选）+ logrules（hayabusa/sigma）。"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from . import config

_ROOT = Path(config.ROOT)
_CONTROLS_PATH = _ROOT / "config" / "logrules_controls.json"

_DEFAULT_CONTROLS: Dict[str, Any] = {
    "version": 1,
    "groups": {
        "log_rules_curated": True,
        "logrules_hayabusa": True,
        "logrules_sigma": True,
    },
    # sigma 体量大：默认只加载 medium+；no_eid 规则上限防拖慢匹配
    "sigma_min_level": "medium",
    "max_no_eid": 240,
}

_GROUP_LABELS = {
    "log_rules_curated": "精选包 log_rules/rules",
    "logrules_hayabusa": "logrules/hayabusa",
    "logrules_sigma": "logrules/sigma（builtin/sysmon）",
}


def load_controls() -> Dict[str, Any]:
    if not _CONTROLS_PATH.is_file():
        return dict(_DEFAULT_CONTROLS)
    try:
        raw = json.loads(_CONTROLS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return dict(_DEFAULT_CONTROLS)
    if not isinstance(raw, dict):
        return dict(_DEFAULT_CONTROLS)
    out = dict(_DEFAULT_CONTROLS)
    grp = raw.get("groups")
    if isinstance(grp, dict):
        g = dict(out["groups"])
        for k in g:
            if k in grp and isinstance(grp[k], bool):
                g[k] = grp[k]
        out["groups"] = g
    if isinstance(raw.get("sigma_min_level"), str) and raw["sigma_min_level"].strip():
        out["sigma_min_level"] = raw["sigma_min_level"].strip().lower()
    try:
        n = int(raw.get("max_no_eid") or out["max_no_eid"])
        out["max_no_eid"] = max(0, min(n, 2000))
    except Exception:
        pass
    out["updated_at"] = str(raw.get("updated_at") or "")
    return out


def save_controls(doc: Dict[str, Any]) -> Dict[str, Any]:
    cur = load_controls()
    grp_in = doc.get("groups")
    if isinstance(grp_in, dict):
        g = dict(cur["groups"])
        for k in g:
            if k in grp_in and isinstance(grp_in[k], bool):
                g[k] = grp_in[k]
        cur["groups"] = g
    if isinstance(doc.get("sigma_min_level"), str) and doc["sigma_min_level"].strip():
        cur["sigma_min_level"] = doc["sigma_min_level"].strip().lower()
    if "max_no_eid" in doc:
        try:
            cur["max_no_eid"] = max(0, min(int(doc["max_no_eid"]), 2000))
        except Exception:
            pass
    cur["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _CONTROLS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONTROLS_PATH.write_text(json.dumps(cur, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        from . import eventlog_rules
        eventlog_rules.reload_eventlog_rules()
    except Exception:
        pass
    return cur


_FILE_COUNT_CACHE: Dict[str, tuple] = {}  # path -> (mtime_key, count)


def _count_rule_files(path: Path, *, recursive: bool) -> int:
    """统计 yml/yaml 数量；按目录 mtime 缓存，避免每次全盘 rglob。"""
    if not path.is_dir():
        return 0
    try:
        mt = path.stat().st_mtime_ns
    except OSError:
        mt = 0
    key = f"{path}|{1 if recursive else 0}"
    hit = _FILE_COUNT_CACHE.get(key)
    if hit and hit[0] == mt:
        return int(hit[1])
    n = 0
    try:
        it = path.rglob("*.yml") if recursive else path.glob("*.yml")
        n = sum(1 for _ in it)
        it2 = path.rglob("*.yaml") if recursive else path.glob("*.yaml")
        n += sum(1 for _ in it2)
    except OSError:
        n = 0
    _FILE_COUNT_CACHE[key] = (mt, n)
    return n


def pack_roots(controls: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    """返回启用的规则根目录（按加载顺序）。"""
    controls = controls or load_controls()
    groups = controls.get("groups") or {}
    rows: List[Dict[str, Any]] = []
    curated = _ROOT / "log_rules" / "rules"
    hayabusa = _ROOT / "logrules" / "hayabusa"
    sigma = _ROOT / "logrules" / "sigma"
    specs = [
        ("log_rules_curated", curated, False, "low"),
        ("logrules_hayabusa", hayabusa, True, "low"),
        ("logrules_sigma", sigma, True, str(controls.get("sigma_min_level") or "medium")),
    ]
    for gid, path, recursive, min_lv in specs:
        enabled = groups.get(gid, True) is not False
        file_n = _count_rule_files(path, recursive=recursive) if path.is_dir() else 0
        rows.append({
            "id": gid,
            "label": _GROUP_LABELS.get(gid, gid),
            "path": str(path),
            "rel": str(path.relative_to(_ROOT)).replace("\\", "/") if path.is_absolute() else str(path),
            "enabled": enabled,
            "present": path.is_dir(),
            "recursive": recursive,
            "min_level": min_lv,
            "file_count": file_n,
        })
    return rows


def list_pack(*, reload: bool = False) -> Dict[str, Any]:
    controls = load_controls()
    roots = pack_roots(controls)
    try:
        from . import eventlog_rules
        pack = eventlog_rules.reload_eventlog_rules() if reload else eventlog_rules.load_eventlog_rules()
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "controls": controls,
            "group_labels": _GROUP_LABELS,
            "roots": roots,
        }
    by_src: Dict[str, int] = {}
    level_hist: Dict[str, int] = {}
    sample: List[Dict[str, Any]] = []
    for r in pack.get("rules") or []:
        src = str(r.get("source_group") or "unknown")
        by_src[src] = by_src.get(src, 0) + 1
        lv = str(r.get("level") or "medium").lower()
        level_hist[lv] = level_hist.get(lv, 0) + 1
        if len(sample) < 80:
            sample.append({
                "id": r.get("id"),
                "title": r.get("title"),
                "level": r.get("level"),
                "source_group": src,
                "event_ids": (r.get("event_ids") or [])[:6],
                "channels": (r.get("channels") or [])[:4],
            })
    return {
        "ok": True,
        "controls": controls,
        "group_labels": _GROUP_LABELS,
        "roots": roots,
        "loaded": {
            "count": int(pack.get("count") or 0),
            "errors": int(pack.get("errors") or 0),
            "dirs": pack.get("dirs") or [pack.get("dir")],
            "min_level": pack.get("min_level"),
            "by_source": by_src,
            "by_level": level_hist,
            "no_eid": len(pack.get("no_eid") or []),
        },
        "sample": sample,
        "note": "时间线入库时用本包匹配 EventID/通道；命中 medium+ 晋升威胁。AI 日志取证共用同一索引。",
    }
