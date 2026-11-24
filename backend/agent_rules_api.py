"""Rule, detection-corpus, and Agent sync API routes."""
from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query, Request

from .agent_auth import _agent_auth
from .edr_session_routes import _audit, _require_admin, _require_user

router = APIRouter()


@router.get("/api/agent/rules")
def api_agent_rules(request: Request):
    _require_user(request)
    from . import agent_rules
    return agent_rules.list_platform_rule_stats()


@router.get("/api/agent/rules/coverage")
def api_agent_rules_coverage(request: Request, include_items: bool = Query(False)):
    """规则覆盖率五态：已导入 / 可编译 / 字段齐全 / 已回放 / 生产有命中。"""
    _require_user(request)
    from . import agent_rules
    return agent_rules.rule_coverage_stats(include_items=bool(include_items))


@router.post("/api/agent/sync")
def api_agent_sync(request: Request, payload: dict = Body(default_factory=dict)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from . import agent_sync
    aid = str((payload or {}).get("agent_id") or "").strip()
    since = int((payload or {}).get("since_rev") or 0)
    parts = (payload or {}).get("parts")
    if isinstance(parts, list):
        parts = [str(p) for p in parts][:16]
    else:
        parts = None
    return agent_sync.bundle(aid, since, parts=parts)


@router.get("/api/edr/agent-sync/manifest")
def api_edr_agent_sync_manifest(request: Request):
    _require_user(request)
    from . import agent_sync
    return agent_sync.manifest()


@router.post("/api/edr/agent-sync/bump")
def api_edr_agent_sync_bump(request: Request, payload: dict = Body(default_factory=dict)):
    """管理员手动递增 sync_rev，强制在线 Agent 下次轮询全量/增量同步。"""
    _require_admin(request)
    from . import agent_sync
    part = str((payload or {}).get("part") or "manual")[:32]
    rev = agent_sync.bump_sync(part)
    return {"ok": True, "sync_rev": rev, "manifest": agent_sync.manifest()}


@router.get("/api/edr/agent-integrations")
def api_edr_agent_integrations_get(request: Request):
    _require_user(request)
    from . import agent_sync
    return agent_sync.get_integrations_document()


@router.put("/api/edr/agent-integrations")
def api_edr_agent_integrations_put(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_sync
    body = payload or {}
    updates = body.get("defaults") if isinstance(body.get("defaults"), dict) else {}
    if not updates and isinstance(body, dict) and "server" not in body:
        updates = {k: v for k, v in body.items() if isinstance(v, bool)}
    server = body.get("server") if isinstance(body.get("server"), dict) else None
    return agent_sync.save_integrations_defaults(
        updates if isinstance(updates, dict) else {},
        server_updates=server,
    )


@router.post("/api/agent/memory-yara")
def api_agent_memory_yara(request: Request, payload: dict = Body(default_factory=dict)):
    _agent_auth(request, str((payload or {}).get("agent_id") or ""))
    from . import memory_yara
    rev = str((payload or {}).get("rev") or "").strip()
    out = memory_yara.bundle(rev)
    if not out.get("ok"):
        raise HTTPException(404, detail=out.get("error") or "规则包不可用")
    return out


@router.get("/api/edr/memory-yara")
def api_edr_memory_yara_list(request: Request):
    _require_user(request)
    from . import memory_yara
    return memory_yara.list_rules()


@router.put("/api/edr/memory-yara/controls")
def api_edr_memory_yara_controls_set(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import memory_yara
    doc = memory_yara.save_controls(payload or {})
    return {"ok": True, "controls": doc, "pack": memory_yara.list_rules()}


@router.get("/api/edr/logrules")
def api_edr_logrules_list(request: Request, reload: int = 0):
    """日志检测规则包状态：log_rules + logrules/hayabusa + logrules/sigma。"""
    _require_user(request)
    from . import logrules_pack
    return logrules_pack.list_pack(reload=bool(reload))


@router.put("/api/edr/logrules/controls")
def api_edr_logrules_controls_set(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import logrules_pack
    doc = logrules_pack.save_controls(payload or {})
    return {"ok": True, "controls": doc, "pack": logrules_pack.list_pack(reload=True)}


@router.post("/api/agent/rules")
def api_agent_rules_create(request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_rules
    try:
        return agent_rules.create_rule(payload or {})
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.put("/api/agent/rules/{rule_id}")
def api_agent_rules_update(rule_id: str, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_rules
    try:
        return agent_rules.update_rule(rule_id, payload or {})
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.patch("/api/agent/rules/{rule_id}")
def api_agent_rules_patch(rule_id: str, request: Request, payload: dict = Body(...)):
    _require_admin(request)
    from . import agent_rules
    try:
        if "enabled" in (payload or {}):
            return agent_rules.set_rule_enabled(rule_id, bool(payload.get("enabled")))
        return agent_rules.update_rule(rule_id, payload or {})
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.delete("/api/agent/rules/{rule_id}")
def api_agent_rules_delete(rule_id: str, request: Request):
    _require_admin(request)
    from . import agent_rules
    try:
        return agent_rules.delete_rule(rule_id)
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.post("/api/agent/rules/bulk-enabled")
def api_agent_rules_bulk_enabled(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import agent_rules

    body = payload or {}
    enabled = bool(body.get("enabled", True))
    ids = body.get("rule_ids") or body.get("ids")
    if ids is not None and not isinstance(ids, list):
        raise HTTPException(400, detail="rule_ids 须为数组")
    source = str(body.get("source") or "")
    if body.get("all_filtered") and isinstance(ids, list):
        out = agent_rules.bulk_set_rules_enabled(enabled, rule_ids=[str(x) for x in ids], source=source)
    elif body.get("all_elastic"):
        out = agent_rules.bulk_set_rules_enabled(enabled, source="elastic")
    elif body.get("all_custom"):
        out = agent_rules.bulk_set_rules_enabled(enabled, source="custom")
    elif body.get("all_sensor"):
        out = agent_rules.bulk_set_rules_enabled(enabled, source="sensor")
    elif body.get("all"):
        out = agent_rules.bulk_set_rules_enabled(
            enabled,
            rule_ids=[str(r.get("id")) for r in agent_rules.list_rules() if r.get("id")],
        )
    elif isinstance(ids, list) and ids:
        out = agent_rules.bulk_set_rules_enabled(enabled, rule_ids=[str(x) for x in ids], source=source)
    else:
        raise HTTPException(400, detail="需要 rule_ids、all_filtered、all_elastic 等参数")
    user = getattr(request.state, "user", None) or {}
    _audit("agent_rules_bulk", user, detail=f"enabled={enabled} changed={out.get('changed')}")
    return out


@router.post("/api/edr/elastic-detection/evm/bulk-enabled")
def api_elastic_evm_bulk_enabled(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import elastic_detection_import as edi

    body = payload or {}
    out = edi.bulk_set_evm_enabled(
        bool(body.get("enabled", True)),
        rule_ids=[str(x) for x in (body.get("rule_ids") or [])] if body.get("rule_ids") else None,
        all_rules=bool(body.get("all")),
    )
    return out


@router.get("/api/edr/elastic-detection/es/status")
def api_elastic_detection_es_status(request: Request):
    _require_user(request)
    from . import elastic_detection_es as edes
    return edes.status()


@router.post("/api/edr/elastic-detection/es/run")
def api_elastic_detection_es_run(request: Request):
    _require_admin(request)
    from . import elastic_detection_es as edes
    return edes.run_detection_cycle(force=True)


@router.post("/api/edr/elastic-detection/es/publish-rules")
def api_elastic_detection_es_publish(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import elastic_detection_es as edes
    max_r = int((payload or {}).get("max_rules") or 2000)
    return edes.publish_detection_rules_to_es(max_rules=max_r)


@router.get("/api/edr/elastic-detection/rule/{rule_id}")
def api_elastic_detection_rule_detail(request: Request, rule_id: str):
    _require_user(request)
    from . import elastic_detection_import as edi

    return edi.get_official_rule_detail(rule_id)


@router.get("/api/edr/elastic-detection/catalog")
def api_elastic_detection_catalog(
    request: Request,
    q: str = "",
    platform: str = "",
    status: str = "",
    limit: int = 100,
    offset: int = 0,
    refresh: bool = False,
):
    _require_user(request)
    from . import elastic_detection_import as edi

    if refresh:
        cat = edi.scan_catalog(platform=platform)
        edi.save_catalog(cat)
    else:
        cat = edi.load_catalog()
    items = list(cat.get("items") or [])
    qn = str(q or "").strip().lower()
    st = str(status or "").strip().lower()
    plat = str(platform or "").strip().lower()
    if plat:
        items = [x for x in items if str(x.get("platform") or "").lower() == plat]
    if st:
        items = [x for x in items if str(x.get("status") or "").lower() == st]
    if qn:
        items = [
            x for x in items
            if qn in str(x.get("name") or "").lower()
            or qn in str(x.get("id") or "").lower()
            or qn in str(x.get("rel_path") or "").lower()
        ]
    total = len(items)
    off = max(0, int(offset or 0))
    lim = max(1, min(int(limit or 100), 500))
    return {
        "ok": True,
        "stats": cat.get("stats") or {},
        "scanned_at": cat.get("scanned_at"),
        "total": total,
        "items": items[off : off + lim],
    }


@router.post("/api/edr/elastic-detection/scan")
def api_elastic_detection_scan(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import elastic_detection_import as edi

    platform = str((payload or {}).get("platform") or "")
    max_files = int((payload or {}).get("max_files") or 0)
    cat = edi.scan_catalog(platform=platform, max_files=max_files)
    path = edi.save_catalog(cat)
    user = getattr(request.state, "user", None) or {}
    _audit("elastic_detection_scan", user, detail=str(path))
    return {"ok": True, "path": str(path), **cat}


@router.post("/api/edr/elastic-detection/import")
def api_elastic_detection_import(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import elastic_detection_import as edi

    body = payload or {}
    ids = body.get("rule_ids") or body.get("ids") or []
    if not isinstance(ids, list):
        raise HTTPException(400, detail="rule_ids 须为数组")
    enable = bool(body.get("enable", False))
    dry_run = bool(body.get("dry_run", True))
    mode = str(body.get("mode") or "both")
    en_a = body.get("enable_agent")
    en_e = body.get("enable_evm")
    out = edi.import_rules(
        [str(x) for x in ids],
        enable=enable,
        enable_agent=en_a if "enable_agent" in body else None,
        enable_evm=en_e if "enable_evm" in body else None,
        mode=mode,
        dry_run=dry_run,
    )
    user = getattr(request.state, "user", None) or {}
    _audit(
        "elastic_detection_import",
        user,
        detail=f"dry_run={dry_run} enable={enable} n={len(ids)} created={len(out.get('created') or [])}",
    )
    return out


@router.get("/api/edr/wazuh-sca/catalog")
def api_wazuh_sca_catalog(
    request: Request,
    q: str = "",
    platform: str = "",
    limit: int = 100,
    offset: int = 0,
    refresh: bool = False,
):
    _require_user(request)
    from . import wazuh_ruleset as wr

    cat = wr.scan_catalog(platform=platform) if refresh else wr.load_catalog()
    if refresh:
        wr.save_catalog(cat)
    items = list(cat.get("items") or [])
    qn = str(q or "").strip().lower()
    plat = str(platform or "").strip().lower()
    if plat:
        items = [x for x in items if str(x.get("platform") or "").lower() == plat]
    if qn:
        items = [
            x for x in items
            if qn in str(x.get("name") or "").lower()
            or qn in str(x.get("policy_id") or "").lower()
            or qn in str(x.get("file") or "").lower()
        ]
    total = len(items)
    off = max(0, int(offset or 0))
    lim = max(1, min(int(limit or 100), 500))
    return {
        "ok": True,
        "stats": cat.get("stats") or {},
        "mitre_json": wr.mitre_enterprise_path(),
        "total": total,
        "items": items[off : off + lim],
    }


@router.post("/api/edr/wazuh-sca/scan")
def api_wazuh_sca_scan(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import wazuh_ruleset as wr

    platform = str((payload or {}).get("platform") or "")
    max_files = int((payload or {}).get("max_files") or 0)
    cat = wr.scan_catalog(platform=platform, max_files=max_files)
    path = wr.save_catalog(cat)
    user = getattr(request.state, "user", None) or {}
    _audit("wazuh_sca_scan", user, detail=str(path))
    return {"ok": True, "path": str(path), **cat}


@router.get("/api/edr/detection-corpus/status")
def api_detection_corpus_status(request: Request):
    _require_user(request)
    from .detection_corpus_bootstrap import corpus_status
    return corpus_status()


@router.post("/api/edr/detection-corpus/bootstrap")
def api_detection_corpus_bootstrap(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from .detection_corpus_bootstrap import ensure_detection_corpus

    body = payload or {}
    out = ensure_detection_corpus(
        force=bool(body.get("force")),
        skip_elastic_import=bool(body.get("skip_elastic_import")),
    )
    user = getattr(request.state, "user", None) or {}
    _audit("detection_corpus_bootstrap", user, detail=str(out.get("marker") or ""))
    return out


@router.post("/api/edr/wazuh-sca/build-bundle")
def api_wazuh_sca_build_bundle(request: Request, payload: dict = Body(default_factory=dict)):
    _require_admin(request)
    from . import agent_sync, wazuh_ruleset as wr

    body = payload or {}
    ids = body.get("policy_ids") or body.get("policies")
    if ids is not None and not isinstance(ids, list):
        raise HTTPException(400, detail="policy_ids 须为数组")
    max_per = int(body.get("max_checks_per_policy") or 0)
    doc = wr.build_agent_bundle(
        policy_ids=[str(x) for x in ids] if isinstance(ids, list) else None,
        platform=str(body.get("platform") or "windows"),
        max_checks_per_policy=max_per,
    )
    if "max_checks_per_run" in body:
        doc["max_checks_per_run"] = int(body.get("max_checks_per_run") or 48)
    path = wr.save_agent_bundle(doc)
    agent_sync.bump_sync("sca")
    user = getattr(request.state, "user", None) or {}
    _audit("wazuh_sca_build_bundle", user, detail=str(path))
    return {"ok": True, "path": str(path), "policies": len(doc.get("policies") or []), "bundle": doc}
