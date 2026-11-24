"""Optional enrichments applied when assembling report pages."""
from __future__ import annotations

from typing import Any, List

from .report_blob_metadata import _conn_os_family, _load_one_blob


def _enrich_linux_section_sigs(conn, section: str, items: List[Any]) -> List[Any]:
    """读取侧补全 Linux 进程/服务/任务的软件包归属字段。"""
    if not isinstance(items, list) or not items:
        return items or []
    if section not in ("processes", "services", "scheduled_tasks", "startup_items"):
        return items
    fam = _conn_os_family(conn)
    looks = fam == "linux"
    if not looks:
        sample = next((x for x in items if isinstance(x, dict)), None)
        if sample:
            p = str(sample.get("path") or "")
            looks = p.startswith("/") or str(sample.get("name") or "").endswith(".service")
    if not looks:
        return items
    try:
        from .linux_sc_import import enrich_linux_entity_sigs
        svcs = items if section == "services" else (_load_one_blob(conn, "services") or [])
        key = section
        pack = {
            "os_family": "linux",
            "services": svcs if isinstance(svcs, list) else [],
            "processes": [],
            "scheduled_tasks": [],
            "startup_items": [],
        }
        pack[key] = items
        enrich_linux_entity_sigs(pack)
        return pack.get(key) or items
    except Exception:
        return items


def _annotate_persist_sideload_list(section: str, items: List[Any], rid: str = "") -> List[Any]:
    """服务/计划任务/启动项列表标注 sideload_suspect，供前端「含未签模块」筛选。"""
    try:
        from .matchers.persistence import annotate_persist_sideload_list
        return annotate_persist_sideload_list(section, items, rid=rid)
    except Exception:
        return items or []
