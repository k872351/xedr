"""Threat process graph construction extracted from agent_edr."""
from __future__ import annotations

from . import agent_edr as _store


def _build_threat_drop_chain(agent_id: str, ev: Optional[Dict[str, Any]], seed: Optional[Dict[str, Any]], chain: List[Dict[str, Any]], seed_pid: Any) -> Dict[str, Any]:
    """父进程 → 写文件 → 子进程：基于时间线窗口的释放/投递链。"""
    aid = str(agent_id or '').strip()
    if not aid:
        return {'steps': [], 'edges': []}
    hit_pid = _store._timeline_int(seed.get('pid')) if seed else 0
    if not hit_pid and seed_pid not in (None, ''):
        hit_pid = _store._timeline_int(seed_pid)
    center_ts = ''
    if ev:
        center_ts = str(ev.get('created_at') or ev.get('ts') or '')
        raw = ev.get('detail_obj') or ev.get('detail') or {}
        if isinstance(raw, str):
            raw = _store._parse_detail(raw)
        if isinstance(raw, dict):
            evidence = raw.get('evidence') if isinstance(raw.get('evidence'), dict) else raw
            inner = evidence.get('evidence') if isinstance(evidence.get('evidence'), dict) else evidence
            if isinstance(inner, dict):
                center_ts = center_ts or str(inner.get('event_ts') or inner.get('ts') or '')
            center_ts = center_ts or str(raw.get('event_ts') or raw.get('ts') or '')
    dt = _store._parse_ts_any(center_ts) or _store.datetime.utcnow()
    t0 = (dt - _store.timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
    t1 = (dt + _store.timedelta(minutes=45)).strftime('%Y-%m-%d %H:%M:%S')
    tl_rows: List[Dict[str, Any]] = []
    with _store._lock:
        conn = _store._connect()
        try:
            rows = conn.execute('SELECT id, etype, summary, detail_json, ts, severity\n                   FROM agent_timeline WHERE agent_id=? AND ts >= ? AND ts <= ?\n                   ORDER BY ts ASC LIMIT 500', (aid, t0, t1)).fetchall()
            tl_rows = [dict(r) for r in rows]
        finally:
            conn.close()
    steps: List[Dict[str, Any]] = []
    parent_p = chain[-2] if len(chain) >= 2 else None
    if not parent_p and seed:
        pp = _store._timeline_int(seed.get('ppid'))
        if pp:
            for row in reversed(tl_rows):
                et = str(row.get('etype') or '')
                if not et.startswith('process_create'):
                    continue
                d = _store._parse_detail(row.get('detail_json'))
                if _store._timeline_int(d.get('pid')) == pp:
                    steps.append(_store._proc_step_from_timeline(row, d, role='parent'))
                    break
    elif parent_p:
        steps.append(_store._proc_step_from_entity(parent_p, role='parent'))
    if seed:
        steps.append(_store._proc_step_from_entity(seed, role='hit', is_hit=True))
    elif hit_pid:
        title = str((ev or {}).get('title') or '').strip()
        steps.append({'id': f'proc-hit-{hit_pid}', 'kind': 'proc', 'role': 'hit', 'is_hit': True, 'name': title or f'PID {hit_pid}', 'pid': hit_pid, 'path': '', 'ts': center_ts, 'timeline_id': None})
    files: List[tuple] = []
    children: List[tuple] = []
    for row in tl_rows:
        et = str(row.get('etype') or '')
        d = _store._parse_detail(row.get('detail_json'))
        if et in _store._DROP_FILE_ETYPES:
            cpid = _store._timeline_int(d.get('pid') or d.get('process_id') or d.get('creator_pid'))
            if hit_pid and cpid == hit_pid:
                files.append((row, d))
        if et in _store._DROP_PROC_ETYPES or et.startswith('process_create'):
            if hit_pid and _store._timeline_int(d.get('ppid')) == hit_pid:
                children.append((row, d))
    files.sort(key=lambda x: str(x[0].get('ts') or ''))
    children.sort(key=lambda x: str(x[0].get('ts') or ''))
    used_children: set = set()
    child_count = 0
    for row, d in files[:12]:
        fp = str(d.get('path') or '').strip()
        base = _store.os.path.basename(fp).lower() if fp else ''
        steps.append(_store._file_step_from_timeline(row, d))
        for j, (crow, cd) in enumerate(children):
            if j in used_children:
                continue
            cp = str(cd.get('path') or cd.get('image') or '')
            cmd = str(cd.get('command_line') or cd.get('cmdline') or '')
            blob = f'{cp} {cmd}'.lower()
            if fp and (fp.lower() in blob or (base and base in blob)):
                used_children.add(j)
                child_count += 1
                steps.append(_store._proc_step_from_timeline(crow, cd, role='child'))
                break
    for j, (crow, cd) in enumerate(children):
        if j in used_children or child_count >= 8:
            continue
        used_children.add(j)
        child_count += 1
        steps.append(_store._proc_step_from_timeline(crow, cd, role='child'))
    edges = [{'from': i, 'to': i + 1, 'label': _store._drop_edge_label(steps[i], steps[i + 1])} for i in range(len(steps) - 1)]
    return {'steps': steps, 'edges': edges, 'window': {'from': t0, 'to': t1}, 'hit_pid': hit_pid or None}


def threat_process_tree(agent_id: str='', *, event_id: int=0, max_nodes: int=56) -> Dict[str, Any]:
    """威胁视图：从告警证据 + 进程实体表还原进程树（祖先链 + 子进程展开）。"""
    _store.ensure()
    aid = str(agent_id or '').strip()
    seed_eid = ''
    seed_pid: Any = None
    seed_proc_name = ''
    hit_title = ''
    event_item: Optional[Dict[str, Any]] = None
    if event_id:
        try:
            got = _store.agent_protocol.get_event(int(event_id))
            ev = (got or {}).get('item') if (got or {}).get('ok') else None
        except Exception:
            ev = None
        if ev:
            event_item = ev
            aid = aid or str(ev.get('agent_id') or '')
            hit_title = str(ev.get('title') or '')
            raw = ev.get('detail_obj') or ev.get('detail') or {}
            if isinstance(raw, str):
                try:
                    raw = _store.json.loads(raw)
                except Exception:
                    raw = {}
            if not isinstance(raw, dict):
                raw = {}
            evidence = raw.get('evidence') if isinstance(raw.get('evidence'), dict) else raw
            inner = evidence.get('evidence') if isinstance(evidence.get('evidence'), dict) else evidence
            if isinstance(inner, dict):
                seed_eid = str(inner.get('entity_id') or evidence.get('entity_id') or '').strip()
                seed_pid = inner.get('pid') if inner.get('pid') not in (None, '') else evidence.get('pid')
                if seed_pid in (None, '') or not seed_eid:
                    blobs: List[Any] = []
                    if isinstance(inner.get('trigger'), dict):
                        blobs.append(inner.get('trigger'))
                    if isinstance(inner.get('chain'), list):
                        blobs.extend([c for c in inner['chain'] if isinstance(c, dict)])
                    for blob in blobs:
                        if seed_pid in (None, '') and blob.get('pid') not in (None, ''):
                            seed_pid = blob.get('pid')
                        if not seed_eid:
                            seed_eid = str(blob.get('entity_id') or '').strip() or seed_eid
                        if seed_pid not in (None, '') and seed_eid:
                            break
                if seed_pid in (None, '') and (not seed_eid):
                    pname = str(inner.get('process_name') or inner.get('name') or '').strip()
                    if pname and pname.lower() not in ('program', 'windows', 'system32', '?'):
                        seed_proc_name = pname
    if not aid:
        return {'ok': False, 'error': '缺少 agent_id 或无效事件'}
    max_nodes = max(8, min(int(max_nodes or 56), 120))
    with _store._lock:
        conn = _store._connect()
        try:
            rows = conn.execute('SELECT * FROM agent_processes WHERE agent_id=? ORDER BY last_seen DESC LIMIT 800', (aid,)).fetchall()
            procs = [dict(r) for r in rows]
        finally:
            conn.close()
    by_eid: Dict[str, Dict[str, Any]] = {}
    by_parent: Dict[str, List[Dict[str, Any]]] = {}
    for p in procs:
        eid = str(p.get('entity_id') or '').strip()
        if not eid:
            continue
        by_eid[eid] = p
        pe = str(p.get('parent_entity_id') or '').strip()
        if pe:
            by_parent.setdefault(pe, []).append(p)
    seed = by_eid.get(seed_eid) if seed_eid else None
    if not seed and seed_pid not in (None, ''):
        try:
            want = int(seed_pid)
            for p in procs:
                if int(p.get('pid') or 0) == want:
                    seed = p
                    seed_eid = str(p.get('entity_id') or '')
                    break
        except (TypeError, ValueError):
            pass
    if not seed and seed_proc_name:
        want_n = seed_proc_name.lower()
        for p in procs:
            if str(p.get('name') or '').lower() == want_n:
                seed = p
                seed_eid = str(p.get('entity_id') or '')
                break
    if not seed:
        drop_chain = _store._build_threat_drop_chain(aid, event_item, None, [], seed_pid)
        return {'ok': True, 'agent_id': aid, 'nodes': [], 'edges': [], 'ancestor_chain': [], 'root_id': '', 'hit_id': seed_eid, 'title': hit_title, 'drop_chain': drop_chain}
    if not str(seed.get('command_line') or '').strip():
        try:
            from . import event_detail_enrich as _ede
            info = _ede._find_process_command(conn, aid, pid=int(seed.get('pid') or 0), entity_id=str(seed.get('entity_id') or ''))
            if info and str(info.get('command_line') or '').strip():
                seed['command_line'] = info['command_line']
        except Exception:
            pass
    if event_item and (not str(seed.get('command_line') or '').strip()):
        raw = event_item.get('detail_obj') or event_item.get('detail') or {}
        if isinstance(raw, str):
            try:
                raw = _store.json.loads(raw)
            except Exception:
                raw = {}
        if isinstance(raw, dict):
            cmd = str(raw.get('command_line') or raw.get('command') or '').strip()
            if cmd:
                seed['command_line'] = cmd
    chain: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = seed
    seen_chain: set = set()
    while cur and len(chain) < 14:
        eid = str(cur.get('entity_id') or '')
        if not eid or eid in seen_chain:
            break
        seen_chain.add(eid)
        chain.append(cur)
        pe = str(cur.get('parent_entity_id') or '').strip()
        cur = by_eid.get(pe) if pe else None
    chain.reverse()
    hit_id = str(seed.get('entity_id') or '')
    include: set = set()
    for p in chain:
        eid = str(p.get('entity_id') or '')
        if eid:
            include.add(eid)
    if hit_id:
        include.add(hit_id)
    for child in by_parent.get(hit_id, [])[:20]:
        ce = str(child.get('entity_id') or '')
        if ce:
            include.add(ce)
    parent_eid = str(seed.get('parent_entity_id') or '').strip()
    if parent_eid:
        include.add(parent_eid)
        for sib in by_parent.get(parent_eid, [])[:14]:
            ce = str(sib.get('entity_id') or '')
            if ce:
                include.add(ce)
    for p in chain:
        pe = str(p.get('entity_id') or '')
        for child in by_parent.get(pe, [])[:5]:
            ce = str(child.get('entity_id') or '')
            if ce and len(include) < max_nodes:
                include.add(ce)

    def _node_of(p: Dict[str, Any], *, is_hit: bool) -> Dict[str, Any]:
        eid = str(p.get('entity_id') or '')
        return {'id': eid, 'name': p.get('name') or '?', 'pid': p.get('pid'), 'ppid': p.get('ppid'), 'parent_id': str(p.get('parent_entity_id') or ''), 'path': p.get('path') or '', 'command_line': str(p.get('command_line') or '')[:2000], 'user': p.get('user') or '', 'integrity': p.get('integrity') or '', 'elevated': p.get('elevated') or '', 'create_time': p.get('create_time') or '', 'source': p.get('source') or '', 'is_hit': is_hit, 'exit_time': p.get('exit_time') or ''}
    nodes = [_node_of(by_eid[eid], is_hit=eid == hit_id) for eid in include if eid in by_eid]
    edges = []
    node_ids = {n['id'] for n in nodes}
    by_pid: Dict[int, str] = {}
    for n in nodes:
        try:
            by_pid[int(n.get('pid') or 0)] = n['id']
        except (TypeError, ValueError):
            pass
    for n in nodes:
        pid = n.get('parent_id')
        if pid and pid in node_ids:
            edges.append({'from': pid, 'to': n['id'], 'label': '子进程'})
    for n in list(nodes):
        if n.get('parent_id') and n['parent_id'] in node_ids:
            continue
        ppid = n.get('ppid')
        try:
            pp = int(ppid) if ppid not in (None, '') else 0
        except (TypeError, ValueError):
            pp = 0
        if pp and pp in by_pid and (by_pid[pp] != n['id']):
            n['parent_id'] = by_pid[pp]
            n['link_repaired'] = True
            if n['parent_id'] not in node_ids:
                continue
            edges.append({'from': n['parent_id'], 'to': n['id'], 'label': 'PPID 关联', 'repaired': True})
        elif pp and n['id'] == hit_id:
            syn = f'syn-parent-{pp}'
            if syn not in node_ids:
                nodes.append({'id': syn, 'name': f'父进程 PID {pp}', 'pid': pp, 'ppid': None, 'parent_id': '', 'path': '', 'command_line': '', 'is_hit': False, 'exit_time': '', 'synthetic': True, 'missing': True})
                node_ids.add(syn)
            n['parent_id'] = syn
            n['link_repaired'] = True
            edges.append({'from': syn, 'to': n['id'], 'label': '断链推断', 'repaired': True})
    for n in nodes:
        pid = n.get('parent_id')
        if pid and pid in node_ids and (not any((e['from'] == pid and e['to'] == n['id'] for e in edges))):
            edges.append({'from': pid, 'to': n['id'], 'label': '子进程'})
    root_id = str(chain[0].get('entity_id') or hit_id) if chain else hit_id
    if root_id.startswith('syn-parent-'):
        root_id = hit_id or root_id
    drop_chain = _store._build_threat_drop_chain(aid, event_item, seed, chain, seed_pid)
    ancestor_chain = [_node_of(p, is_hit=str(p.get('entity_id') or '') == hit_id) for p in chain if str(p.get('entity_id') or '')]
    return {'ok': True, 'agent_id': aid, 'root_id': root_id, 'hit_id': hit_id, 'nodes': nodes, 'edges': edges, 'ancestor_chain': ancestor_chain, 'title': hit_title, 'drop_chain': drop_chain}
