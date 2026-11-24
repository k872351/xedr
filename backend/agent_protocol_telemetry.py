"""Agent telemetry and snapshot ingestion extracted from agent_protocol."""
from __future__ import annotations

from . import agent_protocol as _store


def report_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """终端或平台写入威胁/采集异常事件。"""
    _store.ensure_db()
    agent_id = str(payload.get('agent_id') or '').strip()
    title = str(payload.get('title') or '').strip()[:200]
    if not agent_id or not title:
        return {'ok': False, 'error': '缺少 agent_id 或 title'}
    if _store._is_remote_ops_noise(title):
        return {'ok': True, 'suppressed': True, 'reason': 'remote_ops_noise'}
    module = str(payload.get('module') or '').strip().lower()[:32]
    if _store._suppress_response_ops_event(module, title):
        return {'ok': True, 'suppressed': True, 'ops_audit': True}
    severity = str(payload.get('severity') or 'medium').strip().lower()[:16]
    if severity not in ('info', 'low', 'medium', 'high', 'critical'):
        severity = 'medium'
    detail = _store.fit_detail(payload.get('detail'))
    building_block = bool(payload.get('building_block')) or (isinstance(detail, dict) and detail.get('building_block') is True)
    if building_block:
        module = module or 'building_block'
        if module not in ('building_block', 'correlation'):
            module = 'building_block'
        if severity in ('high', 'critical'):
            severity = 'medium'
    hostname = str(payload.get('hostname') or '').strip()[:128] or _store._host_of(agent_id)
    now = _store._now()
    from . import alert_allow
    with _store._lock:
        conn = _store._connect()
        try:
            if not conn.execute('SELECT 1 FROM agents WHERE agent_id=?', (agent_id,)).fetchone():
                return {'ok': False, 'error': '终端未注册或已删除', 'orphan': True}
            allow = alert_allow.find_match(conn, agent_id, title, detail)
            if allow is not None:
                alert_allow.record_hit(conn, allow['id'])
                return {'ok': True, 'suppressed': True, 'allow_id': allow['id']}
            payload_key = _store._event_payload_key(detail)
            row = None
            if payload_key:
                since2h = _store.time.strftime('%Y-%m-%dT%H:%M:%S', _store.time.localtime(_store.time.time() - 7200))
                cand = conn.execute("SELECT id, title, detail, severity FROM agent_events\n                       WHERE agent_id=? AND status='open' AND created_at>=?\n                       ORDER BY id DESC LIMIT 40", (agent_id, since2h)).fetchall()
                for c in cand or []:
                    if _store._event_payload_key(c['detail']) == payload_key:
                        row = c
                        break
            if row is None:
                row = conn.execute("SELECT id FROM agent_events\n                       WHERE agent_id=? AND title=? AND status='open'\n                         AND created_at>=?\n                       ORDER BY id DESC LIMIT 1", (agent_id, title, _store.time.strftime('%Y-%m-%dT%H:%M:%S', _store.time.localtime(_store.time.time() - 600)))).fetchone()
            if row:
                old = conn.execute('SELECT detail, severity, hit_count FROM agent_events WHERE id=?', (row['id'],)).fetchone()
                old_detail = str((old['detail'] if old else '') or '')
                old_sev = str((old['severity'] if old else '') or severity)
                richer = _store._detail_richer(detail, old_detail)
                sev_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                bump_sev = sev_rank.get(severity, 0) > sev_rank.get(old_sev, 0)
                prev_hits = int((old['hit_count'] if old else 1) or 1)
                new_hits = max(1, prev_hits) + 1
                conn.execute('UPDATE agent_events SET detail=?, severity=?, module=?, hit_count=?, updated_at=?\n                       WHERE id=?', (detail if richer else old_detail, severity if bump_sev else old_sev, module or '', new_hits, now, row['id']))
                eid = row['id']
                deduped = True
            else:
                cur = conn.execute("INSERT INTO agent_events(agent_id, hostname, severity, title, detail, module, status,\n                                                hit_count, created_at, updated_at)\n                       VALUES(?,?,?,?,?,?, 'open', 1, ?, ?)", (agent_id, hostname, severity, title, detail, module, now, now))
                eid = cur.lastrowid
                deduped = False
                from . import elastic_detection_es as _edes
                if _edes.detection_enabled():
                    from .es_event_queue import enqueue_timeline_event
                    try:
                        det = _store.json.loads(detail) if isinstance(detail, str) else detail
                    except (ValueError, TypeError):
                        det = {}
                    det = det if isinstance(det, dict) else {}
                    enqueue_timeline_event(conn=conn, source_id=f"alert:{eid}", agent_id=agent_id,
                                           hostname=hostname, etype=str(det.get('etype') or module or 'event'),
                                           summary=title, detail=det, ts=now)
            _store.mark_telemetry_received(conn, agent_id, now)
            conn.commit()
        finally:
            conn.close()
    _store.bump_live('event', agent_id=agent_id, event_id=eid)
    if not deduped:
        row = {'id': eid, 'agent_id': agent_id, 'hostname': hostname, 'severity': severity, 'title': title, 'detail': detail, 'module': module, 'status': 'open', 'created_at': now, 'updated_at': now, 'deduped': False}
        if not building_block:
            try:
                from . import agent_notify
                agent_notify.notify_event(row)
            except Exception:
                pass
        try:
            from . import agent_store
            _store.threading.Thread(target=agent_store.write_event, args=(row,), daemon=True).start()
        except Exception:
            pass
    return {'ok': True, 'id': eid, 'deduped': deduped}


def _post_snapshot(agent_id: str, module: str, items: List[Any], blob: str, *, total: int, extra: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
    """快照入库后的质量检查与规则匹配；增量时 items 只含新增/变化条目。"""
    if _store._blob_has_mojibake(blob):
        _store.report_event({'agent_id': agent_id, 'module': module, 'severity': 'medium', 'title': f'采集编码异常（{module}）', 'detail': '快照中出现乱码字符，请升级终端 Agent 后重新上报'})
    if module in ('service', 'process', 'network') and total == 0:
        _store.report_event({'agent_id': agent_id, 'module': module, 'severity': 'low', 'title': f'模块采集为空（{module}）', 'detail': '本次快照 0 条，可能权限不足或采集失败'})
    rule_stats = {'hits': 0}
    host = _store._host_of(agent_id)
    if items:
        try:
            from . import agent_rules
            rule_stats = agent_rules.apply_snapshot_rules(agent_id, module, items, hostname=host) or {}
        except Exception as e:
            print('[agent_rules]', e)
    _store.bump_live('snapshot', agent_id=agent_id, module=module)
    out = {'ok': True, 'module': module, 'item_count': total, 'rule_hits': int(rule_stats.get('hits') or 0), 'live_rev': _store.live_revision()}
    if extra:
        out.update(extra)
    return out


def upsert_snapshot(payload: Dict[str, Any], *, staged=False) -> Dict[str, Any]:
    """写入某模块最新快照（覆盖式）。payload.items 建议 ≤500 条精简对象。"""
    _store.ensure_db()
    agent_id = str(payload.get('agent_id') or '').strip()
    module = str(payload.get('module') or '').strip().lower()
    if not agent_id or module not in _store.AGENT_MODULES:
        return {'ok': False, 'error': 'agent_id 或 module 无效'}
    items = payload.get('items')
    if not isinstance(items, list):
        return {'ok': False, 'error': 'snapshot_items_invalid'}
    paged = staged and ((module == 'software' and payload.get('paged_software') is True)
                        or (module in ('service', 'hotfix', 'user') and payload.get('paged_inventory') is True))
    limit = 4000 if paged else (1000 if module == 'software' else 500)
    if len(items) > limit:
        return {'ok': False, 'error': 'snapshot_item_limit_exceeded'}
    if any(not isinstance(item, dict) for item in items):
        return {'ok': False, 'error': 'snapshot_items_invalid'}
    keys = payload.get('keys')
    versioned = payload.get('generation') not in (None, 0, '0', '') or bool(keys)
    if paged and (not versioned or type(payload.get('generation')) is not int):
        return {'ok': False, 'error': 'snapshot_generation_invalid'}
    if versioned and (not isinstance(keys, list) or len(keys) != len(items)
                      or any(not isinstance(k, str) or not k or len(k) > 300 for k in keys)
                      or len(set(keys)) != len(keys)):
        return {'ok': False, 'error': 'snapshot_keys_invalid'}
    if not versioned:
        keys = []
    try:
        generation = int(payload.get('generation') or 0) if versioned else 0
    except (TypeError, ValueError):
        return {'ok': False, 'error': 'snapshot_generation_invalid'}
    if versioned and generation <= 0:
        return {'ok': False, 'error': 'snapshot_generation_invalid'}
    digest = str(payload.get('digest') or '').strip()[:128]
    collected_at = str(payload.get('collected_at') or _store._now())[:32]
    blob = _store.json.dumps(items, ensure_ascii=False)
    if len(blob) > 1500000:
        return {'ok': False, 'error': 'snapshot 过大，请精简字段'}
    now = _store._now()
    with _store._lock:
        conn = _store._connect()
        try:
            _store.mark_telemetry_received(conn, agent_id, now)
            conn.execute('INSERT INTO agent_snapshots(agent_id, module, collected_at, item_count, digest, payload_json,\n                                               generation, keys_json)\n                   VALUES(?,?,?,?,?,?,?,?)\n                   ON CONFLICT(agent_id, module) DO UPDATE SET\n                     collected_at=excluded.collected_at,\n                     item_count=excluded.item_count,\n                     digest=excluded.digest,\n                     payload_json=excluded.payload_json,\n                     generation=excluded.generation,\n                     keys_json=excluded.keys_json', (agent_id, module, collected_at, len(items), digest, blob, generation, _store.json.dumps(keys, ensure_ascii=False) if versioned else ''))
            conn.commit()
        finally:
            conn.close()
    return _store._post_snapshot(agent_id, module, items, blob, total=len(items))


def apply_snapshot_delta(payload: Dict[str, Any]) -> Dict[str, Any]:
    """按 generation 链应用增量清单。服务端代号与 base_generation 不一致、或应用后条数与 Agent
    声明不符时拒绝（generation_mismatch），Agent 收到拒绝后改发全量，不做"猜测式合并"。"""
    _store.ensure_db()
    agent_id = str(payload.get('agent_id') or '').strip()
    module = str(payload.get('module') or '').strip().lower()
    if not agent_id or module not in _store.AGENT_MODULES:
        return {'ok': False, 'error': 'agent_id 或 module 无效'}
    try:
        base = int(payload.get('base_generation') or 0)
        gen = int(payload.get('generation') or 0)
        want_n = int(payload.get('item_count')) if payload.get('item_count') is not None else -1
    except (TypeError, ValueError):
        return {'ok': False, 'error': 'generation 无效'}
    ups = payload.get('upserts')
    rms = payload.get('removes')
    if not isinstance(ups, list) or not isinstance(rms, list):
        return {'ok': False, 'error': 'snapshot_delta_invalid'}
    def valid_key(key):
        return isinstance(key, str) and 0 < len(key) <= 300
    if (any(not isinstance(u, dict) or not valid_key(u.get('k')) or not isinstance(u.get('item'), dict) for u in ups)
            or any(not valid_key(k) for k in rms)):
        return {'ok': False, 'error': 'snapshot_delta_invalid'}
    up_keys = {u['k'] for u in ups}
    if len(up_keys) != len(ups) or len(set(rms)) != len(rms) or up_keys.intersection(rms):
        return {'ok': False, 'error': 'snapshot_delta_invalid'}
    if base <= 0 or gen <= base:
        return {'ok': False, 'error': 'generation_mismatch'}
    collected_at = str(payload.get('collected_at') or _store._now())[:32]
    digest = str(payload.get('digest') or '').strip()[:128]
    now = _store._now()
    changed: List[Dict[str, Any]] = []
    with _store._lock:
        conn = _store._connect()
        try:
            row = conn.execute('SELECT generation, keys_json, payload_json FROM agent_snapshots WHERE agent_id=? AND module=?', (agent_id, module)).fetchone()
            if not row or int(row['generation'] or 0) != base or (not row['keys_json']):
                return {'ok': False, 'error': 'generation_mismatch'}
            try:
                keys = _store.json.loads(row['keys_json'] or '[]')
                items = _store.json.loads(row['payload_json'] or '[]')
            except Exception:
                return {'ok': False, 'error': 'generation_mismatch'}
            if not isinstance(keys, list) or not isinstance(items, list) or len(keys) != len(items):
                return {'ok': False, 'error': 'generation_mismatch'}
            if any(not valid_key(k) for k in keys) or len(set(keys)) != len(keys) or not set(rms).issubset(keys):
                return {'ok': False, 'error': 'generation_mismatch'}
            rmset = {str(k) for k in rms}
            new_keys: List[str] = []
            new_items: List[Any] = []
            for k, it in zip(keys, items):
                if k not in rmset:
                    new_keys.append(k)
                    new_items.append(it)
            pos = {k: i for i, k in enumerate(new_keys)}
            for u in ups:
                if not isinstance(u, dict) or not isinstance(u.get('item'), dict):
                    continue
                k = str(u.get('k') or '')[:300]
                if not k:
                    continue
                if k in pos:
                    new_items[pos[k]] = u['item']
                else:
                    pos[k] = len(new_keys)
                    new_keys.append(k)
                    new_items.append(u['item'])
                changed.append(u['item'])
            if len(new_items) > _store.DELTA_MAX_ITEMS or (want_n >= 0 and len(new_items) != want_n):
                return {'ok': False, 'error': 'generation_mismatch'}
            blob = _store.json.dumps(new_items, ensure_ascii=False)
            if len(blob) > 1500000:
                return {'ok': False, 'error': 'snapshot 过大，请精简字段'}
            _store.mark_telemetry_received(conn, agent_id, now)
            conn.execute('UPDATE agent_snapshots SET collected_at=?, item_count=?, digest=?, payload_json=?,\n                       generation=?, keys_json=? WHERE agent_id=? AND module=?', (collected_at, len(new_items), digest, blob, gen, _store.json.dumps(new_keys, ensure_ascii=False), agent_id, module))
            conn.commit()
            total = len(new_items)
        finally:
            conn.close()
    changed_blob = _store.json.dumps(changed, ensure_ascii=False) if changed else ''
    return _store._post_snapshot(agent_id, module, changed, changed_blob, total=total, extra={'delta': True, 'upserts': len(changed), 'removes': len(rmset), 'generation': gen})


def related_events_by_payload(event_id: int, *, limit: int=20) -> Dict[str, Any]:
    """按 task_execute/payload_path 等载荷键关联同主机告警（FIM↔EVM↔进程产品化边）。"""
    _store.ensure_db()
    limit = max(1, min(int(limit or 20), 50))
    with _store._lock:
        conn = _store._connect()
        try:
            row = conn.execute('SELECT * FROM agent_events WHERE id=?', (int(event_id),)).fetchone()
            if not row:
                return {'ok': False, 'error': '事件不存在'}
            detail = row['detail']
            key = _store._event_payload_key(detail)
            edges = []
            dobj = None
            try:
                import json as _json
                dobj = _json.loads(detail) if isinstance(detail, str) else detail
            except Exception:
                dobj = detail if isinstance(detail, dict) else {}
            if isinstance(dobj, dict):
                for label, field in (('task_def', 'task_def_path'), ('payload', 'task_execute'), ('payload', 'payload_path'), ('shortcut', 'shortcut_target'), ('service', 'service_exe'), ('process', 'image'), ('process', 'path'), ('network', 'remote_ip')):
                    v = str(dobj.get(field) or '').strip()
                    if v:
                        edges.append({'kind': label, 'field': field, 'value': v})
            items = []
            if key:
                aid = row['agent_id']
                cand = conn.execute('SELECT id, title, module, severity, status, created_at, detail\n                       FROM agent_events WHERE agent_id=? AND id<>?\n                       ORDER BY id DESC LIMIT 80', (aid, int(event_id))).fetchall()
                for c in cand or []:
                    if _store._event_payload_key(c['detail']) != key:
                        continue
                    items.append({'id': c['id'], 'title': c['title'], 'module': c['module'], 'severity': c['severity'], 'status': c['status'], 'created_at': c['created_at'], 'payload_key': key})
                    if len(items) >= limit:
                        break
            return {'ok': True, 'event_id': int(event_id), 'payload_key': key, 'edges': edges, 'items': items}
        finally:
            conn.close()
