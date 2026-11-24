"""Timeline ingestion, listing and rule application extracted from agent_edr."""
from __future__ import annotations

from . import agent_edr as _store


def ingest_timeline(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Agent 批量写入时间线条目。"""
    _store.ensure()
    agent_id = str(payload.get('agent_id') or '').strip()
    if not agent_id:
        return {'ok': False, 'error': '缺少 agent_id'}
    events = payload.get('events')
    if not isinstance(events, list):
        events = []
    events = events[:800]
    host = str(payload.get('hostname') or '').strip()[:128] or _store.agent_protocol._host_of(agent_id)
    now = _store._now()
    n = 0
    rows: List[Dict[str, Any]] = []
    tele: List[Any] = []
    detect_events: List[Dict[str, Any]] = []
    with _store._lock:
        conn = _store._connect()
        try:
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                etype = str(ev.get('etype') or ev.get('type') or 'event')[:64]
                summary = str(ev.get('summary') or ev.get('title') or '')[:300]
                if not summary:
                    continue
                detail = ev.get('detail') if isinstance(ev.get('detail'), dict) else {'raw': ev.get('detail')}
                if _store._is_agent_self_noise(etype, summary, detail if isinstance(detail, dict) else {}):
                    continue
                if _store.timeline_filter.is_collector_noise(agent_id, etype, detail) or _store.timeline_filter.is_generated_script(etype, detail):
                    continue
                if etype == 'process_cmd_patch' and isinstance(detail, dict):
                    try:
                        _store._apply_process_cmd_patch(conn, agent_id, detail, str(ev.get('ts') or now)[:32])
                    except Exception:
                        pass
                    tele.append((etype, detail, str(ev.get('ts') or now)[:32]))
                    continue
                detect_events.append(ev)
                tele.append((etype, detail, str(ev.get('ts') or now)[:32]))
                try:
                    from . import agent_rules as _ar
                    if not _ar.sensor_event_allowed(etype, summary, detail):
                        if _store.timeline_filter.etype_kind(etype) != 'exit':
                            continue
                except Exception:
                    pass
                if _store.timeline_filter.is_duplicate(agent_id, etype, detail):
                    continue
                sev = str(ev.get('severity') or 'info')[:16]
                ts = _store.timeline_filter.fix_etw_ts(etype, str(ev.get('ts') or now)[:32], now)
                detail_s = _store.agent_protocol.fit_detail(detail or {})
                ent = str((detail or {}).get('entity_id') or '')[:64] if isinstance(detail, dict) else ''
                insert = conn.execute('INSERT INTO agent_timeline(agent_id, hostname, etype, summary, detail_json, severity, ts, created_at, entity_id)\n                       VALUES(?,?,?,?,?,?,?,?,?)', (agent_id, host, etype, summary, detail_s, sev, ts, now, ent))
                rows.append({'agent_id': agent_id, 'hostname': host, 'etype': etype, 'summary': summary, 'detail_json': detail_s, 'severity': sev, 'ts': ts, 'created_at': now})
                from . import elastic_detection_es as _edes
                if _edes.detection_enabled():
                    from .es_event_queue import enqueue_timeline_event
                    enqueue_timeline_event(conn=conn, source_id=f"timeline:{insert.lastrowid}",
                                           agent_id=agent_id, hostname=host, etype=etype, summary=summary, detail=detail, ts=ts)
                n += 1
            if tele:
                from . import agent_telemetry
                agent_telemetry.apply(conn, agent_id, tele)
            try:
                from . import beacon_timeline as _bt
                _bt.maybe_emit_beacon_events(conn, agent_id, host)
            except Exception:
                pass
            try:
                from . import agent_seq_gap as _asg
                gaps = _asg.note_and_gaps(agent_id, events if isinstance(events, list) else [])
                _asg.maybe_emit_gap_event(conn, agent_id, host, gaps)
            except Exception:
                pass
            if n:
                _store.agent_protocol.mark_telemetry_received(conn, agent_id, now)
            conn.commit()
        finally:
            conn.close()
    elastic_reported = 0
    if detect_events:
        try:
            from . import agent_rules as _ar
            from . import agent_sync as _asy
            from . import elastic_detection_import as _edi
            do_elastic = _asy.server_detection_enabled('elastic_evm_ingest')
            do_custom_evm = _asy.server_detection_enabled('evm_ingest')
            for ev in detect_events[:400]:
                if elastic_reported >= 12:
                    break
                if not isinstance(ev, dict):
                    continue
                det0 = ev.get('detail') if isinstance(ev.get('detail'), dict) else {}
                if str(ev.get('etype') or '').startswith('process_create'):
                    det0 = _ar.enrich_process_event_detail(agent_id, det0, str(ev.get('summary') or ''))
                    ev = {**ev, 'detail': det0}
                matched = False
                if do_elastic:
                    for r in _edi.match_timeline_event(ev):
                        title = str(r.get('title') or 'Elastic 时间线命中')[:200]
                        src = str(r.get('source') or 'elastic')
                        if src != 'protections-artifacts' and str(r.get('id') or '').endswith('.prot.evm'):
                            src = 'protections'
                        prefix = 'Protections EVM' if src.startswith('protections') else 'Elastic EVM'
                        detail = _store._timeline_rule_hit_detail(ev, rule_id=r.get('id'), rule_title=title, rule_source=src, building_block=True, extra={'elastic_rule_id': r.get('elastic_rule_id') or r.get('protections_rule_id')})
                        _store.agent_protocol.report_event({'agent_id': agent_id, 'hostname': host, 'module': _store._timeline_rule_hit_module(ev, detail), 'severity': str(r.get('severity') or 'medium'), 'title': f'{prefix}：{title}'[:200], 'detail': detail})
                        elastic_reported += 1
                        matched = True
                        break
                if not matched and do_custom_evm:
                    for r in _ar.match_live_evm_events(ev):
                        title = str(r.get('title') or 'EVM 命中')[:200]
                        rid = str(r.get('id') or '')
                        src = 'custom'
                        if rid.startswith('elastic-'):
                            src = 'elastic'
                        elif '.prot.evm' in rid:
                            src = 'protections'
                        detail = _store._timeline_rule_hit_detail(ev, rule_id=rid, rule_title=title, rule_source=src, building_block=bool(r.get('building_block')))
                        _store.agent_protocol.report_event({'agent_id': agent_id, 'hostname': host, 'module': _store._timeline_rule_hit_module(ev, detail), 'severity': str(r.get('severity') or 'high'), 'title': f'EVM：{title}'[:200], 'detail': detail})
                        elastic_reported += 1
                        break
        except Exception:
            pass
    if n:
        _store.agent_protocol.bump_live('timeline', agent_id=agent_id, count=n)
        try:
            from . import agent_store
            _store.threading.Thread(target=agent_store.write_timeline_batch, args=(rows,), daemon=True).start()
            agent_store.maybe_purge()
        except Exception:
            pass
    return {'ok': True, 'inserted': n, 'elastic_hits': elastic_reported, '_detect_events': detect_events}


def list_timeline(agent_id: str='', *, etype: str='', q: str='', kind: str='', source: str='', event_id: str='', limit: int=100) -> Dict[str, Any]:
    _store.ensure()
    limit = max(1, min(int(limit or 100), 500))
    clauses = []
    args: List[Any] = []
    if agent_id:
        clauses.append('agent_id=?')
        args.append(agent_id)
    if etype:
        clauses.append('etype=?')
        args.append(etype)
    if q:
        clauses.append('(summary LIKE ? OR detail_json LIKE ? OR hostname LIKE ?)')
        like = f'%{q}%'
        args.extend([like, like, like])
    src_f = str(source or '').strip().lower()
    eid_f = str(event_id or '').strip()
    if src_f:
        clauses.append('detail_json LIKE ?')
        args.append(f'%"source"%{src_f}%')
    if eid_f:
        clauses.append('detail_json LIKE ?')
        args.append(f'%"event_id"%{eid_f}%')
    kind = str(kind or '').strip().lower()
    with _store._lock:
        conn = _store._connect()
        try:
            base = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
            kinds: Dict[str, int] = {k: 0 for k in _store.timeline_filter.KIND_ORDER}
            etypes_by_kind: Dict[str, List[str]] = {}
            total = 0
            for et, cnt in conn.execute(f'SELECT etype, COUNT(*) FROM agent_timeline{base} GROUP BY etype', args):
                k = _store.timeline_filter.etype_kind(et)
                kinds[k] = kinds.get(k, 0) + int(cnt)
                etypes_by_kind.setdefault(k, []).append(et)
                total += int(cnt)
            where_clauses, where_args = (list(clauses), list(args))
            if kind:
                ets = etypes_by_kind.get(kind) or []
                if not ets:
                    return {'ok': True, 'items': [], 'kinds': kinds, 'total': total}
                where_clauses.append(f"etype IN ({','.join('?' * len(ets))})")
                where_args.extend(ets)
            where = ' WHERE ' + ' AND '.join(where_clauses) if where_clauses else ''
            fetch_n = limit * 3 if src_f or eid_f else limit
            rows = conn.execute(f'SELECT * FROM agent_timeline{where} ORDER BY ts DESC, id DESC LIMIT ?', (*where_args, fetch_n)).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                try:
                    d['detail'] = _store.json.loads(d.pop('detail_json') or '{}')
                except Exception:
                    d['detail'] = {}
                det = d.get('detail') if isinstance(d.get('detail'), dict) else {}
                if src_f and str(det.get('source') or '').lower() != src_f:
                    continue
                if eid_f and str(det.get('event_id') or '') != eid_f:
                    continue
                items.append(d)
                if len(items) >= limit:
                    break
            return {'ok': True, 'items': items, 'kinds': kinds, 'total': total}
        finally:
            conn.close()


def apply_log_rules(agent_id: str, host: str, events: List[Any], *, max_promote: int=40) -> int:
    """用 log_rules（Sigma/EventID）对照本批时间线，命中 medium+ 晋升为威胁事件。"""
    linux_rows = []
    for ev in events or []:
        if not isinstance(ev, dict) or ev.get('etype') != 'linux_journal':
            continue
        detail = ev.get('detail') if isinstance(ev.get('detail'), dict) else {}
        if detail.get('source') != 'linux_journal' or not detail.get('message'):
            continue
        linux_rows.append({'channel': detail.get('channel') or 'journal',
                           'provider': detail.get('provider') or 'journal',
                           'message': str(detail['message'])[:2048], 'time': ev.get('ts') or ''})
    linux_promoted = 0
    if linux_rows and max_promote > 0:
        from .linux_journal import match_linux_journal
        hits, _ = match_linux_journal(linux_rows, max_hits=max_promote)
        for hit in hits:
            level = str(hit.get('level') or 'medium').lower()
            if level not in ('medium', 'high', 'critical'):
                continue
            detail = {'etype': 'log_rule_hit', 'source': 'log_rules', 'platform': 'linux',
                      'rule_id': hit.get('rule_id'), 'channel': hit.get('channel'),
                      'event_ts': hit.get('time'), 'provider': hit.get('provider'),
                      'evidence': str(hit.get('evidence') or '')[:4000],
                      'hit_count': hit.get('hit_count', 1)}
            result = _store.agent_protocol.report_event({
                'agent_id': agent_id, 'hostname': host, 'module': 'audit', 'severity': level,
                'title': f"Linux 日志规则：{hit.get('title') or '命中'}"[:200], 'detail': detail,
            })
            if result.get('ok') and not result.get('deduped') and not result.get('suppressed'):
                linux_promoted += 1
            if linux_promoted >= max_promote:
                return linux_promoted
    shaped: List[Dict[str, Any]] = []
    for ev in events or []:
        row = _store._timeline_to_eventlog_shape(ev if isinstance(ev, dict) else {})
        if row:
            shaped.append(row)
        if len(shaped) >= 120:
            break
    if not shaped:
        return linux_promoted
    try:
        from .eventlog_rules import match_events
    except Exception:
        return linux_promoted
    hits, _meta = match_events(shaped, max_hits=80)
    if not hits:
        return linux_promoted
    n = linux_promoted
    for h in hits:
        lv = str(h.get('level') or 'medium').lower()
        if lv == 'informational':
            lv = 'low'
        if lv not in ('medium', 'high', 'critical'):
            continue
        title = f"日志规则：{h.get('title') or 'EventID 命中'}"[:200]
        evid = h.get('evidence') or ''
        if not isinstance(evid, str):
            try:
                evid = _store.json.dumps(evid, ensure_ascii=False)
            except Exception:
                evid = str(evid)
        fields = h.get('fields') if isinstance(h.get('fields'), dict) else {}
        detail = {'etype': 'log_rule_hit', 'rule_id': h.get('rule_id') or '', 'rule_title': h.get('title') or '', 'event_id': h.get('event_id'), 'channel': h.get('channel') or '', 'evidence': evid, 'matched': evid, 'message': str(h.get('message') or '')[:2000], 'provider': h.get('provider') or '', 'event_ts': h.get('time') or '', 'matcher': 'log_rules', 'level': lv, 'source': 'log_rules'}
        for fk in ('Image', 'CommandLine', 'TargetFilename', 'User', 'ProcessId', 'ParentImage', 'DestinationIp', 'DestinationPort', 'QueryName', 'TargetObject', 'GrantedAccess'):
            if fields.get(fk) not in (None, ''):
                detail.setdefault(str(fk).lower() if fk in ('ProcessId',) else {'Image': 'path', 'CommandLine': 'command_line', 'TargetFilename': 'path', 'ProcessId': 'pid', 'ParentImage': 'parent_path', 'DestinationIp': 'remote_ip', 'DestinationPort': 'remote_port', 'QueryName': 'query', 'TargetObject': 'reg_key', 'GrantedAccess': 'access', 'User': 'user'}.get(fk, fk.lower()), fields.get(fk))
        r = _store.agent_protocol.report_event({'agent_id': agent_id, 'hostname': host, 'module': 'audit', 'severity': lv, 'title': title, 'detail': detail})
        if r.get('ok') and (not r.get('deduped')) and (not r.get('suppressed')):
            n += 1
        if n >= max_promote:
            break
    return n


def match_sequences(agent_id: str, hostname: str='') -> int:
    """在最近时间线上匹配行为序列。"""
    _store.ensure_seq_rules()
    rules = [r for r in _store.list_seq_rules().get('items') or [] if r.get('enabled')]
    if not rules:
        return 0
    tl = _store.list_timeline(agent_id, limit=80).get('items') or []
    tl = list(reversed(tl))
    written = 0
    for rule in rules:
        steps = rule.get('steps') or []
        if len(steps) < 2:
            continue
        win = int(rule.get('window_sec') or 120)
        for i, ev in enumerate(tl):
            if not _store._step_match(ev, steps[0]):
                continue
            t0 = _store._parse_ts(ev.get('ts'))
            idx = 1
            chain = [ev]
            for ev2 in tl[i + 1:]:
                t1 = _store._parse_ts(ev2.get('ts'))
                if t1 - t0 > win:
                    break
                if _store._step_match(ev2, steps[idx]) and _store._seq_link_ok(chain[-1], ev2):
                    chain.append(ev2)
                    idx += 1
                    if idx >= len(steps):
                        detail = _store._seq_event_detail(rule, chain)
                        evr = _store.agent_protocol.report_event({'agent_id': agent_id, 'hostname': hostname or ev.get('hostname') or '', 'module': 'sequence', 'severity': rule.get('severity') or 'high', 'title': f"行为序列：{rule.get('title')}", 'detail': _store.json.dumps(detail, ensure_ascii=False)[:3500]})
                        if evr.get('ok') and (not evr.get('deduped')) and (not evr.get('suppressed')):
                            written += 1
                        break
            if idx >= len(steps):
                break
    return written
