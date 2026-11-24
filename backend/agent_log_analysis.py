"""Log investigation and diagnostic workflows extracted from agent_edr."""
from __future__ import annotations

from . import agent_edr as _store


def diagnose_log_rules(agent_id: str='', *, limit: int=300) -> Dict[str, Any]:
    """日志规则命中诊断：EventID 采集 / 规则匹配 / 级别门槛 / 加白抑制。"""
    _store.ensure()
    limit = max(50, min(int(limit or 300), 500))
    aid = str(agent_id or '').strip()
    tl = _store.list_timeline(aid, limit=limit)
    recent = tl.get('items') or []
    eid_items = _store._list_timeline_with_event_id(aid, limit=limit)
    by_id: Dict[Any, Dict[str, Any]] = {}
    for ev in eid_items + list(recent):
        if isinstance(ev, dict) and ev.get('id') is not None:
            by_id[ev['id']] = ev
    items = list(by_id.values())
    total = len(recent)
    with_eid = 0
    without_eid = 0
    shaped: List[Dict[str, Any]] = []
    channels: Dict[str, int] = {}
    for ev in items:
        if not isinstance(ev, dict):
            without_eid += 1
            continue
        row = _store._timeline_to_eventlog_shape(ev)
        if row:
            with_eid += 1
            shaped.append(row)
            ch = str(row.get('channel') or '—')[:80]
            channels[ch] = channels.get(ch, 0) + 1
        else:
            without_eid += 1
    agent_sysmon = False
    agent_winevent_on = None
    winevt_manifest: List[str] = []
    winevt_stats: List[Any] = []
    winevent_status_sum = ''
    try:
        if aid:
            with _store._lock:
                conn = _store._connect()
                try:
                    row = conn.execute('SELECT health_json FROM agents WHERE agent_id=?', (aid,)).fetchone()
                finally:
                    conn.close()
            if row:
                try:
                    h = _store.json.loads(row['health_json'] or '{}')
                except Exception:
                    h = {}
                if isinstance(h, dict):
                    sens = h.get('sensors') if isinstance(h.get('sensors'), dict) else {}
                    cs = sens.get('capture_status') if isinstance(sens.get('capture_status'), dict) else {}
                    agent_sysmon = bool(cs.get('sysmon_present') or (cs.get('sysmon') or {}).get('present'))
                    winevt_manifest = list(sens.get('winevent_manifest') or [])
                    winevt_stats = list(sens.get('winevent_stats') or [])
                    comps = sens.get('components') or h.get('components') or []
                    if isinstance(comps, list):
                        for c in comps:
                            if not isinstance(c, dict):
                                continue
                            if str(c.get('name') or '').lower() == 'winevent':
                                agent_winevent_on = str(c.get('state') or '').upper() == 'OK'
                            if str(c.get('name') or '').lower() == 'sysmon' and str(c.get('state') or '').upper() == 'OK':
                                agent_sysmon = True
    except Exception:
        pass
    for ev in recent[:80]:
        if isinstance(ev, dict) and str(ev.get('etype') or '') == 'winevent_status':
            winevent_status_sum = str(ev.get('summary') or '')
            det = ev.get('detail') if isinstance(ev.get('detail'), dict) else {}
            srcs = det.get('sources')
            if isinstance(srcs, list) and srcs:
                winevt_manifest = [str(x) for x in srcs]
            break
    pack_info: Dict[str, Any] = {}
    groups_on = 0
    groups_off: List[str] = []
    try:
        from . import logrules_pack
        pack = logrules_pack.list_pack(reload=False) or {}
        pack_info = {'loaded': int((pack.get('loaded') or {}).get('count') or 0), 'no_eid': int((pack.get('loaded') or {}).get('no_eid') or 0), 'min_level': (pack.get('loaded') or {}).get('min_level') or 'low', 'by_level': (pack.get('loaded') or {}).get('by_level') or {}}
        for r in pack.get('roots') or []:
            label = str(r.get('label') or r.get('id') or '')
            if r.get('enabled') is False:
                groups_off.append(label)
            elif r.get('present'):
                groups_on += 1
    except Exception as e:
        pack_info = {'error': str(e), 'loaded': 0}
    hits: List[Dict[str, Any]] = []
    match_meta: Dict[str, Any] = {}
    if shaped:
        try:
            from .eventlog_rules import match_events
            hits, match_meta = match_events(shaped, max_hits=80)
        except Exception as e:
            match_meta = {'error': str(e)}
    by_level: Dict[str, int] = {}
    promoteable = 0
    low_only = 0
    sample_hits: List[Dict[str, Any]] = []
    suppressed = 0
    sample_suppressed: List[Dict[str, Any]] = []
    from . import alert_allow
    with _store._lock:
        conn = _store._connect()
        try:
            for h in hits or []:
                lv = str(h.get('level') or 'medium').lower()
                if lv == 'informational':
                    lv = 'low'
                by_level[lv] = by_level.get(lv, 0) + 1
                title = f"日志规则：{h.get('title') or 'EventID 命中'}"[:200]
                detail = {'etype': 'log_rule_hit', 'rule_title': h.get('title') or '', 'event_id': h.get('event_id'), 'channel': h.get('channel') or '', 'level': lv}
                allow = None
                try:
                    allow = alert_allow.find_match(conn, aid or '', title, detail)
                except Exception:
                    allow = None
                if allow:
                    suppressed += 1
                    if len(sample_suppressed) < 5:
                        sample_suppressed.append({'title': title, 'level': lv, 'allow_id': allow.get('id'), 'allow_value': allow.get('value') or allow.get('rule') or ''})
                    continue
                if lv in ('medium', 'high', 'critical'):
                    promoteable += 1
                    if len(sample_hits) < 8:
                        sample_hits.append({'title': h.get('title') or '', 'level': lv, 'event_id': h.get('event_id'), 'channel': h.get('channel') or ''})
                else:
                    low_only += 1
        finally:
            conn.close()
    open_log_alerts = 0
    with _store._lock:
        conn = _store._connect()
        try:
            q = "SELECT COUNT(*) AS c FROM agent_events WHERE title LIKE '日志规则：%' AND status!='ignored'"
            args: List[Any] = []
            if aid:
                q += ' AND agent_id=?'
                args.append(aid)
            open_log_alerts = int(conn.execute(q, args).fetchone()['c'] or 0)
        except Exception:
            open_log_alerts = 0
        finally:
            conn.close()
    reasons: List[Dict[str, str]] = []
    if pack_info.get('loaded', 0) <= 0:
        reasons.append({'code': 'no_rules', 'level': 'bad', 'text': '日志规则包未加载或加载为 0，请到规则页确认三组开关与目录。'})
    if groups_off:
        reasons.append({'code': 'groups_off', 'level': 'warn', 'text': f"有规则组已关闭：{', '.join(groups_off)}"})
    sysmon_n = sum((v for k, v in channels.items() if 'sysmon' in str(k).lower()))
    has_sysmon_ch = sysmon_n > 0
    manifest_has_sysmon = any(('sysmon' in str(x).lower() for x in winevt_manifest))
    sysmon_delivered = 0
    for st in winevt_stats:
        if not isinstance(st, dict):
            continue
        if str(st.get('id') or '').lower() == 'sysmon' or 'sysmon' in str(st.get('channel') or '').lower():
            try:
                sysmon_delivered += int(st.get('delivered') or 0) + int(st.get('catchup_parsed') or 0)
            except Exception:
                pass
    if total <= 0:
        reasons.append({'code': 'no_timeline', 'level': 'bad', 'text': '近期没有时间线数据。请确认终端在线并已上报事件。'})
    elif with_eid <= 0:
        if agent_sysmon and agent_winevent_on is False:
            reasons.append({'code': 'winevent_off', 'level': 'bad', 'text': '终端 Sysmon 组件为 OK，但 winevent 采集未开启。日志规则依赖 winevent 订阅 EventID，请在策略/集成里打开 winevent。'})
        elif agent_sysmon and (not manifest_has_sysmon):
            reasons.append({'code': 'sysmon_not_subscribed', 'level': 'bad', 'text': 'Sysmon 已安装，但 winevent 订阅列表里没有 sysmon 通道（常见：装好后未重订通道）。请重启 Agent 或等 Sysmon 自愈周期触发重订；升级后会自动 catch-up 回补。'})
        elif agent_sysmon:
            reasons.append({'code': 'sysmon_no_events', 'level': 'bad', 'text': f"Sysmon 已装且组件 OK，但时间线仍无带 EventID 的事件（库内专查 0 条）。多半是 winevent 只订了「未来事件」未回补，或解析/压噪后为空。请更新 Agent 后重启；当前通道状态：{winevent_status_sum or ('manifest=' + ','.join(winevt_manifest[:8]) if winevt_manifest else '未知')}。"})
        else:
            reasons.append({'code': 'no_event_id', 'level': 'bad', 'text': '时间线里没有带 EventID 的 winevent 事件。日志规则无法匹配（需开启 winevent，并安装/托管 Sysmon）。'})
    elif not has_sysmon_ch:
        reasons.append({'code': 'no_sysmon', 'level': 'warn', 'text': f'已有 {with_eid} 条带 EventID 的事件，但没有 Sysmon 通道。请确认终端已安装 Sysmon，且 winevent 订阅了 Microsoft-Windows-Sysmon/Operational。'})
        if not hits:
            reasons.append({'code': 'no_match', 'level': 'warn', 'text': '当前通道未命中规则（命中 0）。可先装 Sysmon 或检查规则组是否覆盖现有通道。'})
    elif not hits:
        reasons.append({'code': 'sysmon_no_hit', 'level': 'warn', 'text': f'已采到 Sysmon/Winlog 事件（EventID {with_eid} 条，其中 Sysmon 约 {sysmon_n}），但未命中当前规则包——通道有数据、规则未覆盖或级别/字段不匹配。'})
    elif promoteable <= 0 and low_only > 0:
        reasons.append({'code': 'level_too_low', 'level': 'warn', 'text': f'有 {low_only} 条规则命中，但级别低于 medium，不会晋升威胁事件。'})
    if suppressed > 0:
        reasons.append({'code': 'whitelisted', 'level': 'warn', 'text': f'有 {suppressed} 条命中会被告警加白抑制，不会出现在威胁列表。'})
    if promoteable > 0 and suppressed < promoteable + suppressed:
        reasons.append({'code': 'ok_promote', 'level': 'ok', 'text': f'有 {promoteable} 条 medium+ 命中可通过晋升（已有日志规则告警约 {open_log_alerts} 条；若仍看不到，检查威胁事件筛选/去重）。'})
    if not reasons:
        reasons.append({'code': 'unknown', 'level': 'warn', 'text': '暂无明确结论，请换一台在线主机或加大时间线样本后再诊。'})
    top_channels = sorted(channels.items(), key=lambda x: -x[1])[:8]
    return {'ok': True, 'agent_id': aid, 'sample_size': total, 'with_event_id': with_eid, 'without_event_id': without_eid, 'eid_ratio': round(with_eid / max(total, 1) * 100, 1) if total else 0, 'eid_pool': len(eid_items), 'sysmon_events': sysmon_n, 'has_sysmon': has_sysmon_ch, 'agent_sysmon': agent_sysmon, 'agent_winevent_on': agent_winevent_on, 'winevent_manifest': winevt_manifest, 'winevent_stats': winevt_stats[:12], 'sysmon_delivered': sysmon_delivered, 'channels': [{'name': k, 'count': v} for k, v in top_channels], 'pack': pack_info, 'groups_on': groups_on, 'groups_off': groups_off, 'match_hits': len(hits or []), 'by_level': by_level, 'promoteable': promoteable, 'low_only': low_only, 'suppressed': suppressed, 'open_log_alerts': open_log_alerts, 'sample_hits': sample_hits, 'sample_suppressed': sample_suppressed, 'reasons': reasons, 'match_meta': match_meta if isinstance(match_meta, dict) else {}}


def investigate_logs(*, q: str='', agent_id: str='', hostname: str='', etype: str='', nature: str='', path: str='', hash_q: str='', source: str='', event_id: str='', topic: str='', range_key: str='today', limit: int=200, offset: int=0, hide_proc_noise: bool=False) -> Dict[str, Any]:
    """日志调查：Agent 实时时间线检索 + 直方分布 + 分桶计数。默认不过滤普通进程创建。"""
    _store.ensure()
    limit = max(1, min(int(limit or 200), 500))
    offset = max(0, int(offset or 0))
    now = _store.time.time()
    cut = ''
    rk = str(range_key or 'today').lower()
    if rk in ('1h', 'hour'):
        cut = _store.time.strftime('%Y-%m-%dT%H:%M:%S', _store.time.localtime(now - 3600))
    elif rk in ('24h', 'today', 'day'):
        cut = _store.time.strftime('%Y-%m-%dT00:00:00', _store.time.localtime(now))
    elif rk in ('7d', 'week'):
        cut = _store.time.strftime('%Y-%m-%dT%H:%M:%S', _store.time.localtime(now - 7 * 86400))
    elif rk in ('30d', 'month'):
        cut = _store.time.strftime('%Y-%m-%dT%H:%M:%S', _store.time.localtime(now - 30 * 86400))
    clauses: List[str] = []
    args: List[Any] = []
    if cut:
        clauses.append('ts >= ?')
        args.append(cut)
    if agent_id:
        clauses.append('agent_id=?')
        args.append(agent_id)
    if hostname:
        clauses.append('hostname LIKE ?')
        args.append(f'%{hostname}%')
    if etype:
        clauses.append('etype LIKE ?')
        args.append(f'%{etype}%')
    topic_f = str(topic or '').strip().lower()
    if topic_f and topic_f in _store._INV_TOPIC_LABELS and (not etype):
        if topic_f == 'file_create':
            # Sysmon 文件创建/ADS/删除 + FIM/ETW 文件类
            clauses.append(
                "("
                "etype LIKE 'file_%' OR etype LIKE 'fim_%' "
                "OR IFNULL(summary,'') LIKE ? OR IFNULL(summary,'') LIKE ? OR IFNULL(summary,'') LIKE ? "
                "OR IFNULL(summary,'') LIKE ? OR IFNULL(summary,'') LIKE ? "
                "OR detail_json LIKE ? OR detail_json LIKE ? OR detail_json LIKE ?"
                ")"
            )
            args.extend([
                '%文件创建%', '%ADS%', '%文件删除%', '%FileCreate%', '%落地%',
                '%file_create%', '%file_stream%', '%file_delete%',
            ])
        elif topic_f == 'service':
            clauses.append("(etype LIKE 'win_service%' OR detail_json LIKE ? OR IFNULL(summary,'') LIKE ? OR detail_json LIKE ?)")
            args.extend(['%\\\\Services\\\\%', '%服务%', '%"topic":"service"%'])
        elif topic_f == 'task':
            clauses.append("(etype LIKE 'win_task%' OR detail_json LIKE ? OR IFNULL(summary,'') LIKE ? OR detail_json LIKE ?)")
            args.extend(['%\\\\Tasks%', '%计划任务%', '%"topic":"task"%'])
        elif topic_f == 'startup':
            clauses.append("(etype LIKE 'persist_%' OR etype LIKE 'wmi_persist%' OR detail_json LIKE ? OR detail_json LIKE ? OR detail_json LIKE ? OR IFNULL(summary,'') LIKE ? OR detail_json LIKE ?)")
            args.extend(['%CurrentVersion\\\\Run%', '%\\\\Startup\\\\%', '%Start Menu%', '%启动%', '%"topic":"startup"%'])
    src_f = str(source or '').strip().lower()
    eid_f = str(event_id or '').strip()
    if src_f == 'sysmon':
        clauses.append("(LOWER(IFNULL(detail_json,'')) LIKE ? OR LOWER(IFNULL(etype,'')) LIKE ? OR IFNULL(summary,'') LIKE ? OR detail_json LIKE ? OR detail_json LIKE ? OR detail_json LIKE ? OR detail_json LIKE ? OR detail_json LIKE ? OR detail_json LIKE ?)")
        args.extend(['%sysmon%', '%sysmon%', '%Sysmon%', '%"etype":"file_create"%', '%"etype":"file_delete%', '%"etype":"file_stream_create"%', '%"etype":"pipe_created"%', '%"etype":"process_tampering"%', '%"etype":"process_create_sysmon"%'])
    elif src_f:
        clauses.append('detail_json LIKE ?')
        args.append(f'%"source"%{src_f}%')
    if eid_f:
        clauses.append('(detail_json LIKE ? OR detail_json LIKE ? OR detail_json LIKE ?)')
        args.extend([f'%"event_id": {eid_f}%', f'%"event_id":{eid_f}%', f'%"event_id": "{eid_f}"%'])
    _PROC_NOISE_PRED = "severity IN ('info','low') AND etype LIKE 'process_create%' AND etype NOT LIKE '%sysmon%' AND IFNULL(summary,'') NOT LIKE '%可疑%'"
    if hide_proc_noise and (not etype) and (not topic_f):
        clauses.append(f'NOT ({_PROC_NOISE_PRED})')
    if q:
        clauses.append('(summary LIKE ? OR detail_json LIKE ? OR hostname LIKE ? OR etype LIKE ?)')
        like = f'%{q}%'
        args.extend([like, like, like, like])
    if path:
        clauses.append('detail_json LIKE ?')
        args.append(f'%{path}%')
    if hash_q:
        clauses.append('detail_json LIKE ?')
        args.append(f'%{hash_q}%')
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    fetch_n = min(2500 if (not hide_proc_noise) or topic_f or src_f else 900, max(limit + offset + 50, 400))
    if topic_f or src_f:
        fetch_n = min(2500, max(fetch_n, limit * 5))
    _TL_COLS = 'id, agent_id, hostname, etype, summary, severity, detail_json, ts, created_at, entity_id'
    with _store._lock:
        conn = _store._connect()
        try:
            if not hide_proc_noise and (not etype):
                c_imp = [*clauses, f'NOT ({_PROC_NOISE_PRED})']
                c_noise = [*clauses, _PROC_NOISE_PRED]
                w_imp = ' WHERE ' + ' AND '.join(c_imp)
                w_noise = ' WHERE ' + ' AND '.join(c_noise)
                imp_n = min(1800, fetch_n)
                noise_n = min(900, max(300, fetch_n // 2))
                rows_imp = conn.execute(f'SELECT {_TL_COLS} FROM agent_timeline{w_imp} ORDER BY ts DESC, id DESC LIMIT ?', (*args, imp_n)).fetchall()
                rows_noise = conn.execute(f'SELECT {_TL_COLS} FROM agent_timeline{w_noise} ORDER BY ts DESC, id DESC LIMIT ?', (*args, noise_n)).fetchall()
                by_id: Dict[int, Any] = {}
                for r in rows_imp:
                    by_id[int(r['id'])] = r
                for r in rows_noise:
                    by_id[int(r['id'])] = r
                rows = sorted(by_id.values(), key=lambda x: (str(x['ts'] or ''), int(x['id'] or 0)), reverse=True)[:fetch_n]
            else:
                rows = conn.execute(f'SELECT {_TL_COLS} FROM agent_timeline{where} ORDER BY ts DESC, id DESC LIMIT ?', (*args, fetch_n)).fetchall()
        finally:
            conn.close()
    etype_set: Dict[str, int] = {}
    host_set: Dict[str, int] = {}
    hist: Dict[str, Dict[str, int]] = {}
    counts = {'all': 0, 'threat': 0, 'risk': 0, 'minor': 0, 'surface': 0}
    items: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        detail = _store._parse_detail(d.pop('detail_json', None))
        d['detail'] = detail
        et = str(d.get('etype') or '')
        sum_s = str(d.get('summary') or '')
        if src_f == 'sysmon':
            if not _store._inv_involves_sysmon(et, detail, sum_s):
                continue
        elif src_f and str(detail.get('source') or '').lower() != src_f:
            continue
        if eid_f and str(detail.get('event_id') or '') != eid_f:
            continue
        if topic_f and (not _store._inv_match_topic(topic_f, et, detail, sum_s)):
            continue
        nat = _store._log_nature(d.get('severity') or 'info', et, sum_s)
        d['nature'] = nat
        d['topics'] = _store._inv_topics(et, detail, sum_s)
        counts['all'] += 1
        counts[nat] = counts.get(nat, 0) + 1
        if et:
            etype_set[et] = etype_set.get(et, 0) + 1
        hn = str(d.get('hostname') or d.get('agent_id') or '')
        if hn:
            host_set[hn] = host_set.get(hn, 0) + 1
        buck = _store._hour_bucket(d.get('ts') or '')
        hist.setdefault(buck, {'threat': 0, 'risk': 0, 'minor': 0, 'surface': 0, 'total': 0})
        hist[buck][nat] = hist[buck].get(nat, 0) + 1
        hist[buck]['total'] += 1
        if nature and nat != nature:
            continue
        items.append(d)
    items_page = items[offset:offset + limit]
    out_items = []
    for it in items_page:
        det = it.get('detail') or {}
        extra = _store._inv_list_fields(str(it.get('etype') or ''), det, str(it.get('summary') or ''))
        topics = it.get('topics') or _store._inv_topics(str(it.get('etype') or ''), det, str(it.get('summary') or ''))
        out_items.append({'id': it.get('id'), 'agent_id': it.get('agent_id'), 'hostname': it.get('hostname'), 'etype': it.get('etype'), 'summary': it.get('summary'), 'severity': it.get('severity'), 'nature': it.get('nature'), 'ts': it.get('ts'), 'pid': extra.get('pid') if extra.get('pid') is not None else det.get('pid'), 'ppid': det.get('ppid'), 'name': extra.get('name'), 'path': extra.get('path'), 'user': det.get('user'), 'command_line': extra.get('command_line'), 'sha256': det.get('sha256'), 'source': extra.get('source') or '', 'source_etype': extra.get('source_etype') or '', 'event_id': extra.get('event_id'), 'channel': extra.get('channel') or '', 'is_sysmon': bool(extra.get('is_sysmon')), 'topics': topics})
    hist_list = [{'ts': k, **v} for k, v in sorted(hist.items())]
    facets = {'etype': [{'id': k, 'count': v} for k, v in sorted(etype_set.items(), key=lambda x: -x[1])[:40]], 'hostname': [{'id': k, 'count': v} for k, v in sorted(host_set.items(), key=lambda x: -x[1])[:40]]}
    return {'ok': True, 'counts': counts, 'histogram': hist_list, 'facets': facets, 'total': len(items), 'offset': offset, 'limit': limit, 'items': out_items, 'range': rk, 'cut': cut}


def get_log_detail(log_id: int) -> Dict[str, Any]:
    """单条日志详情：字段分组 + 进程链 + 原始 JSON。"""
    _store.ensure()
    lid = int(log_id or 0)
    if lid <= 0:
        return {'ok': False, 'error': '无效日志 ID'}
    with _store._lock:
        conn = _store._connect()
        try:
            row = conn.execute('SELECT * FROM agent_timeline WHERE id=?', (lid,)).fetchone()
            if not row:
                return {'ok': False, 'error': '日志不存在'}
            item = dict(row)
            detail = _store._parse_detail(item.pop('detail_json', None))
            item['detail'] = detail
            item['nature'] = _store._log_nature(item.get('severity') or 'info', item.get('etype') or '', item.get('summary') or '')
            aid = str(item.get('agent_id') or '')
            if aid and (not str(item.get('hostname') or '').strip()):
                try:
                    hr = conn.execute('SELECT hostname, ip FROM agents WHERE agent_id=?', (aid,)).fetchone()
                    if hr:
                        item['hostname'] = hr[0] or item.get('hostname')
                        item['agent_ip'] = hr[1] if len(hr) > 1 else ''
                except Exception:
                    pass
            if aid and (not str(item.get('hostname') or '').strip()):
                try:
                    hr = conn.execute('SELECT hostname, ip FROM agents WHERE agent_id=?', (aid,)).fetchone()
                    if hr:
                        item['hostname'] = hr[0] or item.get('hostname')
                        item['agent_ip'] = hr[1] if len(hr) > 1 else ''
                except Exception:
                    pass
            related = []
            if aid:
                related = conn.execute('SELECT id, etype, summary, detail_json, severity, ts, hostname\n                       FROM agent_timeline WHERE agent_id=? ORDER BY ts DESC, id DESC LIMIT 400', (aid,)).fetchall()
        finally:
            conn.close()
    prefer_groups = [('进程', ['name', 'process_name', 'host_process', 'pid', 'ppid', 'process_guid', 'parent_guid', 'parent_name', 'parent_path', 'user', 'target_pid', 'create_time', 'elevated', 'integrity']), ('模块 / 路径', ['module', 'module_name', 'path', 'image', 'command_line', 'directory', 'script_block', 'payload', 'process_path']), ('签名 / 哈希', ['signed', 'signer', 'sha256', 'company', 'file_version', 'ext', 'size', 'size_kb']), ('网络', ['remote', 'local', 'proto', 'daddr', 'dport', 'saddr', 'sport']), ('其它', [])]
    used = set()
    groups = []
    for title, keys in prefer_groups[:-1]:
        fields = []
        for k in keys:
            if k in detail and detail[k] not in (None, ''):
                fields.append({'k': k, 'v': detail[k]})
                used.add(k)
        if fields:
            groups.append({'title': title, 'fields': fields})
    rest = [{'k': k, 'v': v} for k, v in detail.items() if k not in used and v not in (None, '')]
    if rest:
        groups.append({'title': '其它', 'fields': rest})
    host_label = str(item.get('hostname') or '').strip() or _store.agent_protocol._host_of(aid) or aid
    info = [{'k': '时间', 'v': item.get('ts')}, {'k': '主机名', 'v': host_label}, {'k': 'Agent ID', 'v': aid}, {'k': '终端 IP', 'v': item.get('agent_ip') or ''}, {'k': '事件类型', 'v': item.get('etype')}, {'k': '级别', 'v': item.get('severity')}, {'k': '性质', 'v': item.get('nature')}, {'k': '摘要', 'v': item.get('summary')}]

    def _pid_of(dj: Dict[str, Any]) -> Any:
        return dj.get('pid') if dj.get('pid') not in (None, '') else None

    def _guid_of(dj: Dict[str, Any]) -> str:
        g = str(dj.get('process_guid') or '').strip()
        if g:
            return g
        pid = _pid_of(dj)
        ct = str(dj.get('create_time') or '').strip()
        if pid is not None and ct:
            return f'{pid}_{ct}'
        return ''
    self_pid = _pid_of(detail)
    self_ppid = detail.get('ppid')
    self_guid = _guid_of(detail)
    self_parent_guid = str(detail.get('parent_guid') or '').strip()
    nodes_by_guid: Dict[str, Dict[str, Any]] = {}
    nodes_by_pid: Dict[str, Dict[str, Any]] = {}
    for r in related:
        dj = _store._parse_detail(r['detail_json'])
        pid = _pid_of(dj)
        if pid is None and (not _guid_of(dj)):
            continue
        node = {'pid': pid, 'ppid': dj.get('ppid'), 'process_guid': _guid_of(dj), 'parent_guid': str(dj.get('parent_guid') or '').strip(), 'name': dj.get('name') or dj.get('process_name') or '', 'path': dj.get('path') or dj.get('image') or '', 'command_line': dj.get('command_line') or '', 'user': dj.get('user') or '', 'elevated': dj.get('elevated') or '', 'integrity': dj.get('integrity') or '', 'ts': r['ts'], 'etype': r['etype'], 'summary': r['summary'], 'log_id': r['id'], 'current': False}
        gk = node['process_guid']
        if gk:
            prev = nodes_by_guid.get(gk)
            if not prev or str(r['ts'] or '') >= str(prev.get('ts') or ''):
                nodes_by_guid[gk] = node
        if pid is not None:
            key = str(pid)
            prev = nodes_by_pid.get(key)
            if not prev or str(r['ts'] or '') >= str(prev.get('ts') or ''):
                nodes_by_pid[key] = node
    if self_pid is not None or self_guid:
        cur = {'pid': self_pid, 'ppid': self_ppid, 'process_guid': self_guid, 'parent_guid': self_parent_guid, 'name': detail.get('name') or detail.get('process_name') or '', 'path': detail.get('path') or '', 'command_line': detail.get('command_line') or '', 'user': detail.get('user') or '', 'elevated': detail.get('elevated') or '', 'integrity': detail.get('integrity') or '', 'ts': item.get('ts'), 'etype': item.get('etype'), 'summary': item.get('summary'), 'log_id': item.get('id'), 'current': True}
        if self_guid:
            nodes_by_guid[self_guid] = {**(nodes_by_guid.get(self_guid) or {}), **cur, 'current': True}
        if self_pid is not None:
            nodes_by_pid[str(self_pid)] = {**(nodes_by_pid.get(str(self_pid)) or {}), **cur, 'current': True}

    def _resolve_parent(node: Dict[str, Any]) -> Dict[str, Any] | None:
        pg = str(node.get('parent_guid') or '').strip()
        if pg and pg in nodes_by_guid:
            return nodes_by_guid[pg]
        ppid = node.get('ppid')
        if ppid not in (None, '', 0, '0'):
            return nodes_by_pid.get(str(ppid))
        return None
    chain: List[Dict[str, Any]] = []
    self_node = (nodes_by_guid.get(self_guid) if self_guid else None) or (nodes_by_pid.get(str(self_pid)) if self_pid is not None else None)
    if self_node is not None:
        walk = []
        seen = set()
        cur_n = self_node
        depth = 0
        while depth < 8:
            parent = _resolve_parent(cur_n)
            if not parent:
                ppid = cur_n.get('ppid')
                if ppid not in (None, '', 0, '0'):
                    walk.append({'pid': ppid, 'process_guid': cur_n.get('parent_guid') or '', 'name': detail.get('parent_name') or f'PID {ppid}', 'ppid': None, 'missing': True})
                break
            pk = parent.get('process_guid') or str(parent.get('pid'))
            if pk in seen:
                break
            seen.add(pk)
            walk.append(parent)
            cur_n = parent
            depth += 1
        chain.extend(reversed(walk))
        chain.append(self_node)
        seen_child: set[str] = set()
        candidates = list(nodes_by_guid.values()) + [n for n in nodes_by_pid.values() if not n.get('process_guid')]
        for n in candidates:
            if n.get('current'):
                continue
            hit = False
            if self_guid and str(n.get('parent_guid') or '') == self_guid:
                hit = True
            elif self_pid is not None and str(n.get('ppid')) == str(self_pid) and (not n.get('parent_guid')):
                hit = True
            if not hit:
                continue
            ck = str(n.get('process_guid') or n.get('log_id') or n.get('pid') or id(n))
            if ck in seen_child:
                continue
            seen_child.add(ck)
            chain.append({**n, 'child': True})
    raw = {'id': item.get('id'), 'agent_id': item.get('agent_id'), 'hostname': item.get('hostname'), 'etype': item.get('etype'), 'summary': item.get('summary'), 'severity': item.get('severity'), 'nature': item.get('nature'), 'ts': item.get('ts'), 'created_at': item.get('created_at'), 'detail': detail}
    return {'ok': True, 'item': item, 'info': info, 'groups': groups, 'chain': chain, 'raw': raw}
