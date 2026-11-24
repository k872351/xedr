"""Report view and section queries extracted from db_store."""
from __future__ import annotations

from . import db_store as _store


def load_section_page(report_file: str, section: str, offset: int=0, limit: int=100, q: str='', channel: str='', hits_only: bool=False) -> Optional[Dict[str, Any]]:
    """按需分页：只读对应 blob / findings，不组装整包 view。"""
    section = (section or '').strip()
    rid = _store.P.report_id(report_file)
    offset = max(0, int(offset or 0))
    _INVENTORY_SECTIONS = {'processes', 'services', 'scheduled_tasks', 'startup_items', 'drivers', 'driver_entries', 'users', 'groups', 'accounts', 'installed_programs', 'hotfixes', 'shares', 'prefetch', 'amcache', 'shimcache', 'userassist', 'run_mru', 'established_connections', 'open_ports', 'network_adapters', 'wmi_namespaces', 'wmi_subscriptions', 'browser_artifacts'}
    if section == 'event_logs':
        cap = 2000
    elif section in _INVENTORY_SECTIONS:
        cap = 20000
    else:
        cap = 2000
    limit = max(1, min(cap, int(limit or 100)))
    if section == 'findings' or section == 'findings_aggregated':
        items: List[Any] = _store._load_fresh_findings(report_file)
        if q:
            ql = q.lower()
            items = [x for x in items if ql in str(x.get('title') or x.get('name') or '').lower() or ql in str(x.get('category') or x.get('type') or '').lower() or ql in str(x.get('reason') or '').lower() or (ql in str(x.get('severity') or '').lower()) or (ql in str(x.get('evidence') or '').lower()) or (ql in str(x.get('sources') or '').lower()) or (ql in str(x.get('rule_id') or '').lower()) or (ql in str(x.get('matcher') or '').lower())]
        total = len(items)
        severity_stats = {'high': 0, 'medium': 0, 'low': 0}
        for item in items:
            sev = str(item.get('severity') or 'medium').strip().lower()
            if sev in ('critical', 'high', 'h', '严重', '高', '高危'):
                severity_stats['high'] += 1
            elif sev in ('low', 'l', 'info', 'informational', '低', '低危'):
                severity_stats['low'] += 1
            else:
                severity_stats['medium'] += 1
        page_items = items[offset:offset + limit]
        return {'section': 'findings', 'total': total, 'offset': offset, 'limit': limit, 'items': _store.slim_findings_list(page_items), 'severity_stats': severity_stats, 'has_next': offset + len(page_items) < total, 'file': rid}
    dbp = _store._resolve_db_path(report_file)
    if not dbp:
        return None
    conn = _store._connect(dbp)
    try:
        _store._init_schema(conn)
        if section in ('processes', 'services', 'scheduled_tasks', 'startup_items'):
            try:
                from .entity_lists import query_or_build_entity_list_page
                page = query_or_build_entity_list_page(conn, section, rid=str(rid or ''), offset=offset, limit=limit, q=q or '')
                if page is not None:
                    page['file'] = rid
                    return page
            except Exception:
                pass
        if section == 'file_scans':
            try:
                if q:
                    ql = f'%{q}%'
                    total = conn.execute('SELECT COUNT(1) AS c FROM files WHERE full_path LIKE ? OR name LIKE ?', (ql, ql)).fetchone()['c']
                    rows = conn.execute('SELECT full_path,name,path,ext,size,company,product,description,file_version,signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system FROM files WHERE full_path LIKE ? OR name LIKE ? ORDER BY full_path LIMIT ? OFFSET ?', (ql, ql, limit, offset)).fetchall()
                else:
                    total = None
                    try:
                        row = conn.execute("SELECT value FROM meta WHERE key='count_file_scans' LIMIT 1").fetchone()
                        if row and str(row['value'] or '').strip().isdigit():
                            total = int(row['value'])
                    except Exception:
                        total = None
                    if total is None:
                        total = conn.execute('SELECT COUNT(1) AS c FROM files').fetchone()['c']
                    rows = conn.execute('SELECT full_path,name,path,ext,size,company,product,description,file_version,signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system FROM files ORDER BY full_path LIMIT ? OFFSET ?', (limit, offset)).fetchall()
                items = []
                for r in rows:
                    keys = r.keys()
                    items.append({'full_path': r['full_path'], 'name': r['name'], 'path': r['path'], 'ext': r['ext'], 'size': r['size'], 'company': r['company'] or '', 'product': r['product'] or '', 'description': r['description'] or '', 'file_version': r['file_version'] or '', 'signed': bool(r['signed']), 'signer': r['signer'] or '', 'sig_status': r['sig_status'] or '', 'sig_type': (r['sig_type'] if 'sig_type' in keys else '') or '', 'magic_hex': r['magic_hex'] or '', 'md5': (r['md5'] if 'md5' in keys else '') or '', 'sha1': (r['sha1'] if 'sha1' in keys else '') or '', 'sha256': (r['sha256'] if 'sha256' in keys else '') or '', 'hidden': bool(r['hidden']) if 'hidden' in keys else False, 'system': bool(r['system']) if 'system' in keys else False})
                return {'section': section, 'total': int(total or 0), 'offset': offset, 'limit': limit, 'items': items, 'file': rid}
            except _store.sqlite3.OperationalError:
                pass
        if section == 'event_logs':
            try:
                pack = _store._query_event_logs_page(conn, offset=offset, limit=limit, q=q, channel=channel, rid=rid, hits_only=bool(hits_only))
                out = {'section': section, 'total': int(pack.get('total') or 0), 'total_approx': bool(pack.get('total_approx')), 'offset': offset, 'limit': limit, 'items': pack.get('items') or [], 'file': rid, 'hits_only': bool(hits_only or pack.get('hits_only'))}
                if offset == 0:
                    try:
                        out['channel_stats'] = _store._event_log_channel_stats(conn)
                    except Exception:
                        pass
                return out
            except _store.sqlite3.OperationalError:
                pass
        raw = None if section in _store.RETIRED_BLOB_KEYS else _store._load_one_blob(conn, section)
        if raw is None:
            return {'section': section, 'total': 0, 'offset': 0, 'limit': limit, 'items': [], 'file': rid}
        if isinstance(raw, list):
            items = raw
            if section == 'processes':
                total = len(items)
                if not q:
                    items = items[offset:offset + limit]
                try:
                    from .text_fix import sanitize_process_modules, fix_tree
                    pack = sanitize_process_modules({'processes': fix_tree(items, depth=0)})
                    items = pack.get('processes') or items
                except Exception:
                    pass
                items = _store._enrich_linux_section_sigs(conn, 'processes', items)
                if not q:
                    sig_idx = _store._file_sig_index_for_processes(conn, items, rid=str(rid or ''))
                    return {'section': section, 'total': total, 'offset': offset, 'limit': limit, 'items': [_store._slim_process_for_list(x, sig_index=sig_idx, rid=str(rid or '')) for x in items], 'file': rid}
            if section == 'scheduled_tasks':
                total = len(items)
                if not q:
                    page = items[offset:offset + limit]
                    page = _store._resolve_task_paths_from_conn(conn, page)
                    page = _store._enrich_linux_section_sigs(conn, section, page)
                    page = _store._annotate_persist_sideload_list(section, page, rid=str(rid or ''))
                    try:
                        from .ingest import normalize_item_sig_fields
                        page = [normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x for x in page]
                    except Exception:
                        pass
                    return {'section': section, 'total': total, 'offset': offset, 'limit': limit, 'items': page, 'file': rid, 'has_next': offset + len(page) < total}
                items = _store._resolve_task_paths_from_conn(conn, items)
            if section == 'startup_items' and isinstance(items, list) and items:
                total = len(items)
                if not q:
                    page = items[offset:offset + limit]
                    page = _store._resolve_startup_paths_from_conn(conn, page)
                    try:
                        from .linux_sc_import import enrich_linux_startups
                        fam = ''
                        try:
                            row = conn.execute("SELECT value FROM meta WHERE key='os_family'").fetchone()
                            fam = str((row['value'] if row else '') or '')
                        except Exception:
                            fam = ''
                        looks_linux = fam.lower() == 'linux' or any((str(x.get('name') or '').endswith('.service') for x in page[:20] if isinstance(x, dict)))
                        if looks_linux:
                            svc_raw = _store._load_one_blob(conn, 'services') or []
                            pack = enrich_linux_startups({'os_family': 'linux', 'collector': 'linuxsc', 'startup_items': page, 'services': svc_raw if isinstance(svc_raw, list) else []})
                            page = pack.get('startup_items') or page
                    except Exception:
                        pass
                    page = _store._enrich_linux_section_sigs(conn, section, page)
                    page = _store._annotate_persist_sideload_list(section, page, rid=str(rid or ''))
                    try:
                        from .ingest import normalize_item_sig_fields
                        page = [normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x for x in page]
                    except Exception:
                        pass
                    return {'section': section, 'total': total, 'offset': offset, 'limit': limit, 'items': page, 'file': rid, 'has_next': offset + len(page) < total}
                try:
                    page_all = _store._resolve_startup_paths_from_conn(conn, items)
                    items = page_all
                except Exception:
                    pass
                try:
                    from .linux_sc_import import enrich_linux_startups
                    fam = ''
                    try:
                        row = conn.execute("SELECT value FROM meta WHERE key='os_family'").fetchone()
                        fam = str((row['value'] if row else '') or '')
                    except Exception:
                        fam = ''
                    looks_linux = fam.lower() == 'linux' or any((str(x.get('name') or '').endswith('.service') for x in items[:20] if isinstance(x, dict)))
                    if looks_linux:
                        svc_raw = _store._load_one_blob(conn, 'services') or []
                        pack = enrich_linux_startups({'os_family': 'linux', 'collector': 'linuxsc', 'startup_items': items, 'services': svc_raw if isinstance(svc_raw, list) else []})
                        items = pack.get('startup_items') or items
                except Exception:
                    pass
            if section in ('established_connections', 'open_ports', 'listening_ports'):
                try:
                    from .net_process import enrich_conn_list
                    enrich_conn_list(items, _store._process_index_from_conn(conn))
                except Exception:
                    pass
        elif isinstance(raw, dict):
            return {'section': section, 'total': 1, 'offset': 0, 'limit': 1, 'items': [raw], 'file': rid, 'as_object': True}
        else:
            val = '' if raw is None else raw
            return {'section': section, 'total': 1 if val != '' else 0, 'offset': 0, 'limit': 1, 'items': [val] if val != '' else [], 'file': rid, 'as_scalar': True}
        if q:
            items = [x for x in items if _store._item_match_q(x, q)]
        if section == 'event_logs' and hits_only and isinstance(items, list) and items:
            try:
                idx = _store._eventlog_hit_index_for_rid(rid) if rid else {}
                from .eventlog_rules import event_hit_key
                matched = []
                seen: Set[str] = set()
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    hk = event_hit_key(it.get('channel'), it.get('event_id'), it.get('time'))
                    info = idx.get(hk) if hk else None
                    if not hk or not info or hk in seen:
                        continue
                    seen.add(hk)
                    it = dict(it)
                    it['hit_rule'] = info
                    matched.append(it)
                items = matched
            except Exception:
                pass
            total = len(items)
            return {'section': section, 'total': total, 'offset': offset, 'limit': limit, 'items': items[offset:offset + limit], 'file': rid, 'hits_only': True}
        total = len(items)
        if not q:
            try:
                conn.execute('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (f'count_{section}', str(total)))
                conn.commit()
            except Exception:
                pass
        page_items = items[offset:offset + limit]
        if section in ('processes', 'services', 'scheduled_tasks', 'startup_items'):
            page_items = _store._enrich_linux_section_sigs(conn, section, page_items)
        if section in ('services', 'scheduled_tasks', 'startup_items'):
            page_items = _store._annotate_persist_sideload_list(section, page_items, rid=str(rid or ''))
            try:
                from .ingest import normalize_item_sig_fields
                page_items = [normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x for x in page_items]
            except Exception:
                pass
        return {'section': section, 'total': total, 'offset': offset, 'limit': limit, 'items': page_items, 'file': rid}
    finally:
        conn.close()


def load_summary_view(report_file: str) -> Optional[Dict[str, Any]]:
    """轻量视图：只读 meta + findings + 少量摘要 blob，不加载进程/文件等大数组。"""
    dbp = _store._resolve_db_path(report_file)
    if not dbp:
        return None
    conn = _store._connect(dbp)
    try:
        _store._init_schema(conn)
        meta = {r['key']: r['value'] for r in conn.execute('SELECT key,value FROM meta')}
        findings = _store.slim_findings_list(_store._load_fresh_findings(report_file))
        blobs_small = {}
        for name in _store._SUMMARY_BLOB_NAMES:
            row = conn.execute('SELECT data FROM blobs WHERE name=?', (name,)).fetchone()
            if row and row['data']:
                blobs_small[name] = _store._jload(row['data'])
        fbm_raw = blobs_small.get('findings_by_module') or {}
        timeline = blobs_small.get('timeline') or []
        if isinstance(timeline, list) and len(timeline) > 120:
            timeline = timeline[:120]
        analysis = {'findings_aggregated': findings, 'findings': _store.slim_findings_list(blobs_small.get('findings_raw_sample') or [], preview=3), 'findings_by_module': _store.slim_findings_by_module(fbm_raw), 'summary': blobs_small.get('summary') or {}, 'summary_aggregated': blobs_small.get('summary_aggregated') or {'total': len(findings)}, 'pipeline': blobs_small.get('pipeline') or {}, 'timeline': timeline, 'ai': blobs_small.get('ai'), 'meta': blobs_small.get('analysis_meta') or {}, 'ioc_hits': {}}
        if 'raw_total' not in analysis['summary_aggregated']:
            analysis['summary_aggregated']['raw_total'] = int(meta.get('raw_findings_total') or len(analysis['findings']))
        try:
            from .mysql_store import load_analysis_from_mysql
            ma = load_analysis_from_mysql(report_file)
            if ma:
                local_findings = list(findings or [])
                for key in ('summary', 'summary_aggregated', 'pipeline', 'timeline', 'findings_by_module', 'meta', 'ai'):
                    if ma.get(key) is not None and ma.get(key) != {} and (ma.get(key) != []):
                        if key == 'findings_by_module' and analysis.get('findings_by_module'):
                            continue
                        analysis[key] = ma[key]
                if local_findings:
                    analysis['findings_aggregated'] = local_findings
                    analysis['findings'] = _store.slim_findings_list(analysis.get('findings') or local_findings, preview=3)
                    findings = local_findings
                elif ma.get('findings_aggregated'):
                    analysis['findings_aggregated'] = _store.slim_findings_list(ma.get('findings_aggregated') or [])
                    analysis['findings'] = _store.slim_findings_list(ma.get('findings') or [], preview=3)
                    findings = analysis['findings_aggregated']
                if ma.get('_findings_total') is not None and (not local_findings):
                    analysis['_findings_total'] = ma['_findings_total']
                analysis['findings_by_module'] = _store.slim_findings_by_module(analysis.get('findings_by_module') or {})
                tl = analysis.get('timeline') or []
                if isinstance(tl, list) and len(tl) > 120:
                    analysis['timeline'] = tl[:120]
        except Exception as e:
            print('[summary] mysql overlay:', e)
        try:
            from .pipeline import prune_inactive_modules
            analysis = prune_inactive_modules(analysis)
            findings = analysis.get('findings_aggregated') or findings
        except Exception:
            pass
        try:
            from .text_fix import fix_analysis_text
            analysis = fix_analysis_text(analysis)
            findings = analysis.get('findings_aggregated') or findings
        except Exception:
            pass
        if not findings:
            try:
                rp = _store.P.resolve_result_json(_store.P.report_id(report_file))
                if rp and rp.is_file():
                    with open(rp, encoding='utf-8') as fh:
                        data = _store.json.load(fh)
                    an = data.get('analysis') if isinstance(data, dict) else None
                    if isinstance(an, dict):
                        raw = an.get('findings_aggregated') or an.get('findings') or []
                        if raw:
                            findings = _store.slim_findings_list(raw)
                            analysis['findings_aggregated'] = findings
                            if an.get('summary_aggregated'):
                                analysis['summary_aggregated'] = an.get('summary_aggregated')
                            if an.get('pipeline'):
                                analysis['pipeline'] = an.get('pipeline')
                            analysis['summary'] = an.get('summary') or analysis.get('summary') or {}
            except Exception:
                pass
        counts: Dict[str, int] = {}
        for k in _store.HEAVY_VIEW_KEYS:
            n = _store._count_blob_fast(conn, k, meta)
            if n:
                counts[k] = n
        for nest_name in ('execution_artifacts', 'remote_access', 'security_extras'):
            if counts.get(nest_name):
                continue
            try:
                nest = _store._load_one_blob(conn, nest_name)
                n = _store._nested_artifact_count(nest)
                if n:
                    counts[nest_name] = n
            except Exception:
                pass
        try:
            rid0 = _store.P.report_id(report_file)
            if _store.INDEX_DB.exists():
                ic = _store._connect(_store.INDEX_DB)
                try:
                    _store._init_index(ic)
                    ir = ic.execute('SELECT processes,services,files FROM reports WHERE file=?', (rid0,)).fetchone()
                    if ir:
                        if not counts.get('processes') and ir['processes']:
                            counts['processes'] = int(ir['processes'] or 0)
                        if not counts.get('services') and ir['services']:
                            counts['services'] = int(ir['services'] or 0)
                        if not counts.get('file_scans') and ir['files']:
                            counts['file_scans'] = int(ir['files'] or 0)
                finally:
                    ic.close()
        except Exception:
            pass
        for k in ('processes', 'services', 'scheduled_tasks', 'startup_items', 'installed_programs', 'users', 'usb_devices', 'prefetch_files', 'file_scans', 'established_connections', 'wmi_namespaces', 'driver_entries', 'drivers', 'event_logs', 'browser_artifacts', 'office_artifacts', 'ps_history'):
            counts.setdefault(k, 0)
        roots = {}
        try:
            raw_roots = meta.get('file_scan_roots') or ''
            if raw_roots:
                roots = _store._jload(raw_roots) or {}
        except Exception:
            roots = {}
        if not isinstance(roots, dict):
            roots = {}
        if not roots and counts.get('file_scans'):
            try:
                row = conn.execute("\n                    SELECT\n                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), '\\users\\')>0\n                                 OR lower(full_path) LIKE 'c:\\users%' THEN 1 ELSE 0 END) AS users,\n                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), 'programdata')>0 THEN 1 ELSE 0 END) AS pd,\n                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), 'program files (x86)')>0 THEN 1 ELSE 0 END) AS pfx86,\n                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), 'program files')>0\n                                AND instr(lower(replace(full_path,'/','\\')), 'program files (x86)')=0 THEN 1 ELSE 0 END) AS pf,\n                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), '\\windows\\')>0\n                                 OR lower(full_path) LIKE 'c:\\windows%' THEN 1 ELSE 0 END) AS win\n                    FROM files\n                    ").fetchone()
                if row:
                    roots = {'Users': int(row['users'] or 0), 'ProgramData': int(row['pd'] or 0), 'ProgramFilesX86': int(row['pfx86'] or 0), 'ProgramFiles': int(row['pf'] or 0), 'Windows': int(row['win'] or 0)}
                    roots = {k: v for k, v in roots.items() if v}
            except Exception:
                pass
        out: Dict[str, Any] = {'hostname': meta.get('hostname'), 'ip': meta.get('ip'), 'os': meta.get('os'), 'os_family': meta.get('os_family') or '', 'collect_time': meta.get('collect_time'), 'analysis': analysis, 'suspicious_items': [{'type': x.get('category'), 'name': x.get('title'), 'reason': x.get('reason') or x.get('title'), 'severity': x.get('severity', 'medium'), 'count': x.get('count', 1)} for x in findings], 'collection_quality': blobs_small.get('collection_quality') or (analysis.get('meta') or {}).get('collection_quality'), 'file_scan_roots': roots, '_source': 'db+summary', '_report_file': meta.get('report_file') or report_file, '_db': str(dbp.name), '_counts': counts, '_light': True}
        try:
            from .quality_gate import evaluate_quality_gate
            cq = out.get('collection_quality') if isinstance(out.get('collection_quality'), dict) else None
            gate = (analysis.get('meta') or {}).get('quality_gate')
            if not isinstance(gate, dict) or not gate.get('confidence'):
                gate = evaluate_quality_gate({'os_family': out.get('os_family') or '', 'os': out.get('os') or '', 'collection_quality': cq or {}}, quality=cq, counts=counts, os_family=str(out.get('os_family') or ''))
                analysis.setdefault('meta', {})['quality_gate'] = gate
                out['analysis'] = analysis
            out['quality_gate'] = gate
        except Exception as e:
            print('[summary] quality_gate:', e)
        try:
            from .collect_pack import load_pack_manifest
            man = load_pack_manifest(_store.P.report_id(report_file))
            if man:
                out['_pack'] = True
                mods = man.get('modules') if isinstance(man.get('modules'), dict) else {}
                for mk, ck in (('eventlog', 'event_logs'), ('files', 'file_scans'), ('processes', 'processes'), ('network', 'established_connections')):
                    n = int((mods.get(mk) or {}).get('count') or 0)
                    if n and (not int(counts.get(ck) or 0)):
                        counts[ck] = n
                out['_counts'] = counts
        except Exception:
            pass
        for k in ('processes', 'services', 'scheduled_tasks', 'startup_items', 'installed_programs', 'users', 'usb_devices', 'prefetch_files', 'file_scans', 'established_connections', 'wmi_namespaces', 'driver_entries', 'drivers', 'event_logs'):
            out[k] = []
        return out
    finally:
        conn.close()


def load_sections_batch(report_file: str, names: List[str], limit: int=600) -> Dict[str, Any]:
    """一次打开 DB，批量取多个 section（减少重复连接与重复解析）。"""
    rid = _store.P.report_id(report_file)
    limit = max(1, min(2000, int(limit or 600)))
    want = [(n or '').strip() for n in names or [] if (n or '').strip()]
    out: Dict[str, Any] = {}
    if not want:
        return {'file': rid, 'sections': out}
    need_findings = [n for n in want if n in ('findings', 'findings_aggregated')]
    blob_names = [n for n in want if n not in ('findings', 'findings_aggregated')]
    for n in need_findings:
        page = _store.load_section_page(report_file, n, offset=0, limit=limit)
        if page is not None:
            out[n if n != 'findings_aggregated' else 'findings'] = page
    if not blob_names:
        return {'file': rid, 'sections': out}
    dbp = _store._resolve_db_path(report_file)
    if not dbp:
        for n in blob_names:
            page = _store.load_section_page(report_file, n, offset=0, limit=limit)
            if page is not None:
                out[n] = page
        return {'file': rid, 'sections': out}
    conn = _store._connect(dbp)
    try:
        _store._init_schema(conn)
        net_idx = None
        if any((s in ('established_connections', 'open_ports', 'listening_ports') for s in blob_names)):
            try:
                net_idx = _store._process_index_from_conn(conn)
            except Exception:
                net_idx = {}
        for section in blob_names:
            if section == 'file_scans':
                try:
                    total = conn.execute('SELECT COUNT(1) AS c FROM files').fetchone()['c']
                    rows = conn.execute('SELECT full_path,name,path,ext,size,company,product,description,file_version,signed,signer,sig_status,sig_type,magic_hex,hidden,system FROM files ORDER BY full_path LIMIT ?', (limit,)).fetchall()
                    items = [{'full_path': r['full_path'], 'name': r['name'], 'path': r['path'], 'ext': r['ext'], 'size': r['size'], 'company': r['company'] or '', 'product': r['product'] or '', 'description': r['description'] or '', 'file_version': r['file_version'] or '', 'signed': bool(r['signed']), 'signer': r['signer'] or '', 'sig_status': r['sig_status'] or '', 'sig_type': (r['sig_type'] if 'sig_type' in r.keys() else '') or '', 'magic_hex': r['magic_hex'] or '', 'hidden': bool(r['hidden']) if 'hidden' in r.keys() else False, 'system': bool(r['system']) if 'system' in r.keys() else False} for r in rows]
                    out[section] = {'section': section, 'total': int(total or 0), 'offset': 0, 'limit': limit, 'items': items, 'file': rid}
                    continue
                except _store.sqlite3.OperationalError:
                    pass
            if section == 'event_logs':
                try:
                    pack = _store._query_event_logs_page(conn, offset=0, limit=limit, q='')
                    out[section] = {'section': section, 'total': int(pack.get('total') or 0), 'offset': 0, 'limit': limit, 'items': pack.get('items') or [], 'file': rid}
                    continue
                except _store.sqlite3.OperationalError:
                    pass
            if section in ('processes', 'services', 'scheduled_tasks', 'startup_items'):
                try:
                    from .entity_lists import query_or_build_entity_list_page
                    page = query_or_build_entity_list_page(conn, section, rid=str(rid or ''), offset=0, limit=limit, q='')
                    if page is not None:
                        page['file'] = rid
                        out[section] = page
                        continue
                except Exception:
                    pass
            raw = None if section in _store.RETIRED_BLOB_KEYS else _store._load_one_blob(conn, section)
            if raw is None:
                out[section] = {'section': section, 'total': 0, 'offset': 0, 'limit': limit, 'items': [], 'file': rid}
            elif isinstance(raw, list):
                if section == 'processes':
                    total_raw = len(raw)
                    raw = raw[:limit]
                    try:
                        from .text_fix import sanitize_process_modules, fix_tree
                        pack = sanitize_process_modules({'processes': fix_tree(raw, depth=0)})
                        raw = pack.get('processes') or raw
                    except Exception:
                        pass
                    sig_idx = _store._file_sig_index_for_processes(conn, raw, rid=str(rid or ''))
                    raw = [_store._slim_process_for_list(x, sig_index=sig_idx, rid=str(rid or '')) for x in raw]
                else:
                    total_raw = len(raw)
                if section == 'scheduled_tasks':
                    raw = _store._resolve_task_paths_from_conn(conn, raw[:limit])
                if section == 'startup_items':
                    raw = _store._resolve_startup_paths_from_conn(conn, raw[:limit])
                if section in ('services', 'scheduled_tasks', 'startup_items'):
                    raw = _store._annotate_persist_sideload_list(section, raw[:limit] if section != 'processes' else raw, rid=str(rid or ''))
                    try:
                        from .ingest import normalize_item_sig_fields
                        raw = [normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x for x in raw]
                    except Exception:
                        pass
                if section in ('established_connections', 'open_ports', 'listening_ports') and net_idx is not None:
                    try:
                        from .net_process import enrich_conn_list
                        enrich_conn_list(raw, net_idx)
                    except Exception:
                        pass
                out[section] = {'section': section, 'total': total_raw, 'offset': 0, 'limit': limit, 'items': raw[:limit], 'file': rid}
                try:
                    conn.execute('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (f'count_{section}', str(total_raw)))
                except Exception:
                    pass
            elif isinstance(raw, dict):
                out[section] = {'section': section, 'total': 1, 'offset': 0, 'limit': 1, 'items': [raw], 'file': rid, 'as_object': True}
            else:
                val = '' if raw is None else raw
                out[section] = {'section': section, 'total': 1 if val != '' else 0, 'offset': 0, 'limit': 1, 'items': [val] if val != '' else [], 'file': rid, 'as_scalar': True}
        try:
            conn.commit()
        except Exception:
            pass
    finally:
        conn.close()
    return {'file': rid, 'sections': out}
