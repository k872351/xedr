"""Timeline, IOC and ATT&CK analytics extracted from agent_edr."""
from __future__ import annotations

from . import agent_edr as _store


def match_iocs(agent_id: str, hostname: str, *, blob: str='', events: Optional[List[Any]]=None, module: str='ioc') -> int:
    """IOC 匹配：本地白名单式 agent_ioc + 情报库 ioc_data.db（经 ioc_db.lookup）。"""
    _store.ensure()
    written = 0
    low = (blob or '').lower()
    local_hits: List[Dict[str, Any]] = []
    if low:
        with _store._lock:
            conn = _store._connect()
            try:
                rows = conn.execute('SELECT * FROM agent_ioc WHERE enabled=1').fetchall()
                for r in rows:
                    val = str(r['value'] or '').lower()
                    if val and val in low:
                        local_hits.append(dict(r))
                        conn.execute('UPDATE agent_ioc SET hits=hits+1, updated_at=? WHERE id=?', (_store._now(), r['id']))
                conn.commit()
            finally:
                conn.close()
    for h in local_hits[:20]:
        ev = _store.agent_protocol.report_event({'agent_id': agent_id, 'hostname': hostname, 'module': module, 'severity': h.get('severity') or 'high', 'title': f"IOC 命中：{h.get('ioc_type')} {h.get('value')}", 'detail': _store.json.dumps({'ioc_id': h.get('id'), 'ioc_type': h.get('ioc_type'), 'value': h.get('value'), 'note': h.get('note'), 'source': 'agent_ioc'}, ensure_ascii=False)[:1500]})
        if ev.get('ok') and (not ev.get('deduped')) and (not ev.get('suppressed')):
            written += 1
    candidates = _store._extract_ioc_candidates(events or [], blob)
    if not candidates:
        return written
    try:
        from . import ioc_db
    except Exception:
        return written
    lib_hits = 0
    for c in candidates:
        try:
            hits = ioc_db.lookup(c['value'], c['ioc_type'])
        except Exception:
            hits = []
        if not hits:
            if c['ioc_type'] == 'file_hash':
                try:
                    hits = ioc_db.lookup(c['value'], None)
                except Exception:
                    hits = []
        for hit in (hits or [])[:2]:
            malware = str(hit.get('malware') or hit.get('family') or '')[:80]
            src = str(hit.get('source') or '')[:80]
            val = str(hit.get('value') or c['value'])[:200]
            itype = str(hit.get('type') or hit.get('match_type') or c['ioc_type'])[:32]
            title = f'情报 IOC 命中：{val}（{_store._IOC_TYPE_CN.get(itype, itype)}）'
            fams = [x.strip() for x in malware.split(',') if x.strip()]
            if fams:
                title += f' · {fams[0]}' + (f' 等 {len(fams)} 个家族' if len(fams) > 1 else '')
            ctx = c.get('ctx') or {}
            src_etype = str(ctx.get('etype') or '').strip()
            detail_body = {**{k: v for k, v in ctx.items() if k not in ('summary', 'etype')}, 'etype': 'ioc_hit', 'source_etype': src_etype, 'ioc_type': itype, 'ioc_value': val, 'malware': malware, 'intel_source': src, 'matched_from': c.get('src'), 'matched': f'{itype}={val}' if itype else val, 'trigger': ctx.get('summary') or '', 'ioc_id': hit.get('id'), 'lib': 'ioc_data'}
            if itype in ('file_hash', 'md5', 'sha1', 'sha256', 'hash') or (isinstance(val, str) and _store.re.fullmatch('[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', val)):
                hk = 'md5' if len(val) == 32 else 'sha1' if len(val) == 40 else 'sha256'
                detail_body.setdefault(hk, val)
            ev = _store.agent_protocol.report_event({'agent_id': agent_id, 'hostname': hostname, 'module': 'ioc', 'severity': 'high', 'title': title[:200], 'detail': detail_body})
            if ev.get('ok') and (not ev.get('deduped')) and (not ev.get('suppressed')):
                written += 1
                lib_hits += 1
            if lib_hits >= 15:
                return written
    return written


def apply_timeline_rules(agent_id: str, host: str, events: List[Any]) -> int:
    """时间线实时事件也走 Agent 规则（保存规则后下一条即可命中，不必等快照）。"""
    try:
        from . import agent_rules
    except Exception:
        return 0
    by_mod: Dict[str, List[Dict[str, Any]]] = {}
    lol_items: List[Dict[str, Any]] = []
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        et = str(ev.get('etype') or '')
        mod = _store._etype_to_rule_module(et)
        if not mod:
            continue
        detail = ev.get('detail') if isinstance(ev.get('detail'), dict) else {}
        if mod == 'process' and 'exit' not in et:
            detail = agent_rules.enrich_process_event_detail(agent_id, detail, str(ev.get('summary') or ''))
        try:
            from . import agent_sync as _asy
            lol_on = _asy.server_detection_enabled('lolbin_ingest')
        except Exception:
            lol_on = True
        if lol_on and mod == 'process' and ('exit' not in et) and (detail.get('command_line') or detail.get('parent_name') or detail.get('name')):
            lol_items.append(dict(detail))
        sev = str(ev.get('severity') or 'info').lower()
        if mod == 'process' and sev in ('info', 'low') and ('可疑' not in str(ev.get('summary') or '')):
            continue
        item = dict(detail)
        if not item.get('name') and ev.get('summary'):
            item.setdefault('summary', ev.get('summary'))
        if et and (not item.get('etype')):
            item['etype'] = et
        by_mod.setdefault(mod, []).append(item)
    written = 0
    for mod, items in by_mod.items():
        if not items:
            continue
        try:
            r = agent_rules.apply_snapshot_rules(agent_id, mod, items, hostname=host) or {}
            written += int(r.get('events') or 0)
        except Exception:
            continue
    if lol_items:
        try:
            r = agent_rules.apply_lolbin(agent_id, lol_items, hostname=host) or {}
            written += int(r.get('events') or 0)
        except Exception as e:
            print('[lolbin]', e)
    return written


def sync_threats_from_timeline(*, limit: int=300, force: bool=False) -> Dict[str, Any]:
    """把近期中危+时间线补晋升为威胁事件（修复首页有数据、威胁事件为空）。"""
    global _LAST_THREAT_SYNC_AT
    _store.ensure()
    from . import agent_protocol as ap
    now_ts = _store.time.time()
    if not force and now_ts - _store._LAST_THREAT_SYNC_AT < _store._THREAT_SYNC_MIN_INTERVAL:
        return {'ok': True, 'skipped': True, 'reason': 'throttled', 'retry_after_sec': int(_store._THREAT_SYNC_MIN_INTERVAL - (now_ts - _store._LAST_THREAT_SYNC_AT))}
    _LAST_THREAT_SYNC_AT = now_ts
    purged = _store.purge_agent_self_noise_events()
    orphans = _store.purge_orphan_agent_data()
    lim = max(50, min(int(limit or 300), 800))
    with ap._lock:
        conn = ap._connect()
        try:
            rows = conn.execute("SELECT t.agent_id, t.hostname, t.etype, t.summary, t.severity, t.detail_json, t.ts\n                   FROM agent_timeline t JOIN agents a ON a.agent_id = t.agent_id\n                   LEFT JOIN agent_event_deletions d ON d.agent_id = t.agent_id AND d.title = t.summary\n                   WHERE lower(t.severity) IN ('medium','high','critical')\n                     AND (d.deleted_at IS NULL OR t.created_at > d.deleted_at)\n                     AND NOT EXISTS (\n                         SELECT 1 FROM agent_events e\n                         WHERE e.agent_id = t.agent_id AND e.title = substr(t.summary, 1, 200)\n                     )\n                   ORDER BY t.id DESC LIMIT ?", (lim,)).fetchall()
        finally:
            conn.close()
    by_agent: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        d = dict(r)
        aid = str(d.get('agent_id') or '')
        if not aid:
            continue
        detail = d.get('detail_json')
        if isinstance(detail, str):
            try:
                detail = _store.json.loads(detail) if detail else {}
            except Exception:
                continue
        if not isinstance(detail, dict):
            continue
        by_agent.setdefault(aid, []).append({'etype': d.get('etype'), 'summary': d.get('summary'), 'severity': d.get('severity'), 'detail': detail, 'ts': d.get('ts')})
    total = 0
    for aid, evs in by_agent.items():
        host = ''
        try:
            host = ap._host_of(aid)
        except Exception:
            host = str((evs[0] or {}).get('hostname') or '')
        if not host:
            for row in rows:
                if str(row['agent_id']) == aid and row['hostname']:
                    host = str(row['hostname'])
                    break
        clean = [e for e in evs if not _store._is_agent_self_noise(str(e.get('etype') or ''), str(e.get('summary') or ''), e.get('detail') if isinstance(e.get('detail'), dict) else {})]
        total += _store._promote_sensor_alerts(aid, host, clean)
    try:
        repaired = ap.repair_broken_event_details()
    except Exception:
        repaired = 0
    return {'ok': True, 'promoted': total, 'agents': len(by_agent), 'scanned': len(rows), 'purged': purged, 'orphans': orphans, 'repaired': repaired}


def attack_story(agent_id: str='', *, event_id: int=0, limit: int=80) -> Dict[str, Any]:
    """单主机 / 单事件的攻击故事链：时间升序节点 + ATT&CK 标注 + 战术泳道。"""
    _store.ensure()
    aid = str(agent_id or '').strip()
    nodes: List[Dict[str, Any]] = []
    host = ''
    if event_id:
        try:
            got = _store.agent_protocol.get_event(int(event_id))
            ev = (got or {}).get('item') if (got or {}).get('ok') else None
        except Exception:
            ev = None
        if ev and ev.get('id'):
            aid = aid or str(ev.get('agent_id') or '')
            host = str(ev.get('hostname') or '')
            mapped = _store._map_attck(str(ev.get('title') or ''), str(ev.get('module') or ''))
            detail = ev.get('detail_obj') or ev.get('detail') or {}
            if isinstance(detail, str):
                try:
                    detail = _store.json.loads(detail)
                except Exception:
                    detail = {}
            nodes.append({'kind': 'threat', 'ts': ev.get('created_at') or ev.get('updated_at'), 'title': ev.get('title'), 'severity': ev.get('severity'), 'module': ev.get('module'), 'technique': mapped['technique'], 'tactic': mapped['tactic'], 'technique_label': _store._tech_label(mapped['technique']), 'id': ev.get('id'), 'detail': detail if isinstance(detail, dict) else {}, 'process_name': _store._story_process_name(detail, str(ev.get('title') or ''))})
    if aid:
        tl = _store.list_timeline(aid, limit=max(limit, 120)).get('items') or []
        for t in reversed(tl):
            mapped = _store._map_attck(str(t.get('summary') or ''), etype=str(t.get('etype') or ''))
            host = host or str(t.get('hostname') or '')
            detail = t.get('detail') if isinstance(t.get('detail'), dict) else {}
            nodes.append({'kind': 'timeline', 'ts': t.get('ts') or t.get('created_at'), 'title': t.get('summary'), 'severity': t.get('severity'), 'etype': t.get('etype'), 'technique': mapped['technique'], 'tactic': mapped['tactic'], 'technique_label': _store._tech_label(mapped['technique']), 'detail': detail, 'process_name': _store._story_process_name(detail, str(t.get('summary') or ''))})
        try:
            evs = _store.agent_protocol.list_events(agent_id=aid, limit=40)
            for e in evs.get('items') or []:
                mapped = _store._map_attck(str(e.get('title') or ''), str(e.get('module') or ''))
                detail = e.get('detail_obj') or e.get('detail') or {}
                if isinstance(detail, str):
                    try:
                        detail = _store.json.loads(detail)
                    except Exception:
                        detail = {}
                nodes.append({'kind': 'threat', 'ts': e.get('created_at'), 'title': e.get('title'), 'severity': e.get('severity'), 'module': e.get('module'), 'technique': mapped['technique'], 'tactic': mapped['tactic'], 'technique_label': _store._tech_label(mapped['technique']), 'id': e.get('id'), 'detail': detail if isinstance(detail, dict) else {}, 'process_name': _store._story_process_name(detail, str(e.get('title') or ''))})
        except Exception:
            pass
    nodes.sort(key=lambda x: str(x.get('ts') or ''))
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for n in nodes:
        k = (n.get('kind'), n.get('title'), n.get('ts'))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(n)
    sliced = uniq[-limit:]
    techniques = []
    tseen = set()
    for n in sliced:
        tid = n.get('technique')
        if tid and tid not in tseen:
            tseen.add(tid)
            techniques.append({'id': tid, 'label': n.get('technique_label') or tid, 'tactic': n.get('tactic')})
    lanes = _store._build_story_lanes(sliced)
    return {'ok': True, 'agent_id': aid, 'hostname': host, 'nodes': sliced, 'techniques': techniques, 'tactics': [{'id': a, 'name': b} for a, b in _store._ATTCK_TACTICS], 'lanes': lanes.get('lanes') or [], 'lane_nodes': lanes.get('lane_nodes') or [], 'lane_edges': lanes.get('lane_edges') or []}


def attck_board(*, limit_events: int=2000, agent_id: str='', days: int=0) -> Dict[str, Any]:
    """全局 ATT&CK 看板：按战术聚合近期威胁；可按主机 / 天数过滤，附技术热力矩阵。"""
    _store.ensure()
    cells: Dict[str, List[Dict[str, Any]]] = {t[0]: [] for t in _store._ATTCK_TACTICS}
    tech_count: Dict[str, int] = {}
    matrix: Dict[str, Dict[str, int]] = {t[0]: {} for t in _store._ATTCK_TACTICS}
    hosts: Dict[str, int] = {}
    tactic_names = dict(_store._ATTCK_TACTICS)
    tactic_count: Dict[str, int] = {t[0]: 0 for t in _store._ATTCK_TACTICS}
    tactic_high: Dict[str, int] = {t[0]: 0 for t in _store._ATTCK_TACTICS}
    tech_tactic: Dict[str, str] = {}
    host_aid: Dict[str, str] = {}
    rows: List[Dict[str, Any]] = []
    high = open_n = unmapped = 0
    items = _store._attck_source_events(agent_id=agent_id, days=days, limit=limit_events)
    for e in items:
        mapped = _store._map_attck(str(e.get('title') or ''), str(e.get('module') or ''))
        tid = mapped.get('technique') or ''
        tactic = mapped.get('tactic') or ''
        if tactic not in tactic_names:
            tactic = ''
        sev = str(e.get('severity') or '').lower()
        is_high = sev in ('high', 'critical')
        high += is_high
        open_n += str(e.get('status') or 'open') == 'open'
        if tid and tactic:
            tech_count[tid] = tech_count.get(tid, 0) + 1
            tech_tactic.setdefault(tid, tactic)
            matrix[tactic][tid] = matrix[tactic].get(tid, 0) + 1
            tactic_count[tactic] += 1
            tactic_high[tactic] += is_high
        else:
            unmapped += 1
        hn = str(e.get('hostname') or e.get('agent_id') or '')
        if hn:
            hosts[hn] = hosts.get(hn, 0) + 1
            host_aid.setdefault(hn, str(e.get('agent_id') or ''))
        row = {'id': e.get('id'), 'title': e.get('title'), 'severity': e.get('severity'), 'hostname': e.get('hostname'), 'agent_id': e.get('agent_id'), 'ts': e.get('created_at'), 'technique': tid, 'technique_label': _store._tech_label(tid) if tid else '', 'technique_name': _store._tech_name(tid), 'tactic': tactic, 'tactic_name': tactic_names.get(tactic, '未映射'), 'status': e.get('status')}
        rows.append(row)
        if tactic:
            cells[tactic].append(row)
    columns = [{'id': tac, 'name': name, 'count': tactic_count[tac], 'items': cells[tac][:30]} for tac, name in _store._ATTCK_TACTICS]
    top_tech = sorted([{'id': k, 'count': v, 'label': _store._tech_label(k), 'name': _store._tech_name(k), 'tactic': tech_tactic.get(k, ''), 'tactic_name': tactic_names.get(tech_tactic.get(k, ''), '')} for k, v in tech_count.items()], key=lambda x: (-x['count'], x['id']))
    heat = []
    for tac, name in _store._ATTCK_TACTICS:
        techs = sorted([{'id': k, 'count': v, 'label': _store._tech_label(k), 'name': _store._tech_name(k)} for k, v in (matrix.get(tac) or {}).items()], key=lambda x: (-x['count'], x['id']))
        heat.append({'tactic': tac, 'name': name, 'count': tactic_count[tac], 'high': tactic_high[tac], 'techniques': techs})
    top_hosts = sorted([{'host': k, 'agent_id': host_aid.get(k, ''), 'count': v} for k, v in hosts.items()], key=lambda x: -x['count'])[:10]
    covered = sum((1 for h in heat if h['techniques']))
    rows.sort(key=lambda r: str(r.get('ts') or ''), reverse=True)
    return {'ok': True, 'columns': columns, 'top_techniques': top_tech, 'heat': heat, 'top_hosts': top_hosts, 'tactics_covered': covered, 'event_total': len(items), 'high_total': high, 'open_total': open_n, 'unmapped_total': unmapped, 'items': rows}
