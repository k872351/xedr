"""Finding evidence hydration extracted from db_store."""
from __future__ import annotations

from . import db_store as _store


def enrich_ioc_evidence_paths(rid: str, items: List[Any]) -> List[Any]:
    """旧报告 IOC 证据常只有文件名；按哈希从 files 表补全完整路径。"""
    if not rid or not items:
        return items
    dbp = _store._resolve_db_path(rid) or _store.P.resolve_analysis_db(rid) or _store.P.db_path_for_write(rid)
    if not dbp or not _store.Path(dbp).is_file():
        return items
    want: Set[str] = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        mid = str(it.get('matcher') or '').lower()
        cat = str(it.get('category') or it.get('type') or '')
        if mid not in ('ioc', 'ioc_db') and cat.upper() != 'IOC':
            continue
        for line in _store._norm_evidence_list(it.get('evidence')):
            if '文件' not in line and 'hash' not in line.lower():
                pass
            for m in _store._HASH_IN_EV.finditer(line):
                want.add(m.group(1).lower())
        rid_s = str(it.get('rule_id') or '')
        for m in _store._HASH_IN_EV.finditer(rid_s):
            want.add(m.group(1).lower())
    if not want:
        return items
    path_by_hash: Dict[str, str] = {}
    conn = _store._connect(_store.Path(dbp))
    try:
        _store._ensure_files_hash_indexes(conn)
        cols = {r[1] for r in conn.execute('PRAGMA table_info(files)').fetchall()}
        hash_cols = [c for c in ('md5', 'sha1', 'sha256') if c in cols]
        if not hash_cols:
            return items
        vals = list(want)
        for i in range(0, len(vals), 400):
            chunk = vals[i:i + 400]
            ph = ','.join('?' * len(chunk))
            where = ' OR '.join((f'{c} IN ({ph})' for c in hash_cols))
            args: List[Any] = []
            for _ in hash_cols:
                args.extend(chunk)
            sql = f"SELECT full_path, name, {', '.join(hash_cols)} FROM files WHERE {where} LIMIT 2000"
            for r in conn.execute(sql, args).fetchall():
                fp = (r['full_path'] or '').replace('/', '\\')
                if not fp:
                    continue
                for c in hash_cols:
                    hv = str(r[c] or '').strip().lower()
                    if hv and hv in want and (hv not in path_by_hash):
                        path_by_hash[hv] = fp
    except Exception:
        return items
    finally:
        conn.close()
    if not path_by_hash:
        return items
    out: List[Any] = []
    for it in items:
        if not isinstance(it, dict):
            out.append(it)
            continue
        mid = str(it.get('matcher') or '').lower()
        cat = str(it.get('category') or it.get('type') or '')
        if mid not in ('ioc', 'ioc_db') and cat.upper() != 'IOC':
            out.append(it)
            continue
        ev = _store._norm_evidence_list(it.get('evidence'))
        if not ev:
            out.append(it)
            continue
        changed = False
        new_ev = []
        paths_found: List[str] = []
        for line in ev:
            nl = line
            if _store.re.search('[A-Za-z]:\\\\[^\\\\]', line) or line.startswith('\\\\'):
                new_ev.append(nl)
                mpath = _store.re.search('文件[：:]\\s*([^→\\n]+)', line)
                if mpath:
                    paths_found.append(mpath.group(1).strip())
                continue
            hm = _store._HASH_IN_EV.search(line)
            fp = path_by_hash.get(hm.group(1).lower() if hm else '', '')
            if fp:
                if _store._FILE_EV_PREFIX.search(line):
                    rest = _store._FILE_EV_PREFIX.sub('', line, count=1)
                    if '→' in rest or '->' in rest:
                        arrow = '→' if '→' in rest else '->'
                        _name, tail = rest.split(arrow, 1)
                        nl = f'文件:{fp} {arrow}{tail}'
                    else:
                        nl = f'文件:{fp}'
                else:
                    nl = f'文件:{fp} · {line}'
                changed = True
                paths_found.append(fp)
            new_ev.append(nl)
        if not changed:
            out.append(it)
            continue
        copy = dict(it)
        copy['evidence'] = new_ev
        if new_ev and (not copy.get('reason') or '文件:' in str(copy.get('reason') or '')):
            copy['reason'] = new_ev[0]
        if paths_found:
            ex = dict(copy.get('extra') or {}) if isinstance(copy.get('extra'), dict) else {}
            if not ex.get('path'):
                ex['path'] = paths_found[0]
            copy['extra'] = ex
            if not copy.get('path'):
                copy['path'] = paths_found[0]
        out.append(copy)
    return out

def load_finding_evidence_page(report_file: str, finding_id: str, offset: int=0, limit: int=50) -> Optional[Dict[str, Any]]:
    """按告警 id 分页返回完整去重证据。"""
    rid = _store.P.report_id(report_file)
    fid = str(finding_id or '').strip()
    if not fid:
        return None
    base_id = fid.split('#', 1)[0].strip() or fid
    offset = max(0, int(offset or 0))
    limit = max(1, min(500, int(limit or 50)))
    item: Optional[Dict[str, Any]] = None
    try:
        from .mysql_store import load_finding_row_mysql
        item = load_finding_row_mysql(rid, base_id)
    except Exception:
        item = None
    if not item:
        dbp = _store._resolve_db_path(rid)
        if not dbp:
            return None
        conn = _store._connect(dbp)
        try:
            _store._init_schema(conn)
            row = conn.execute('SELECT * FROM findings_agg WHERE id=?', (base_id,)).fetchone()
            if not row:
                for r in conn.execute('SELECT * FROM findings_agg'):
                    if str(r['id'] or '') == base_id:
                        row = r
                        break
            if row:
                item = {'id': row['id'], 'title': row['title'], 'count': row['count'], 'evidence': _store._jload(row['evidence'], []), 'extra': _store._jload(row['extra'], {}) or {}}
        finally:
            conn.close()
    if not item:
        return None
    try:
        enriched = _store.enrich_ioc_evidence_paths(rid, [item])
        if enriched and isinstance(enriched[0], dict):
            item = enriched[0]
    except Exception:
        pass
    try:
        enriched2 = _store.enrich_linux_persistence_evidence(rid, [item])
        if enriched2 and isinstance(enriched2[0], dict):
            item = enriched2[0]
    except Exception:
        pass
    try:
        enriched3 = _store.enrich_network_finding_process(rid, [item])
        if enriched3 and isinstance(enriched3[0], dict):
            item = enriched3[0]
    except Exception:
        pass
    ev = _store._norm_evidence_list(item.get('evidence'))
    if len(ev) == 1 and '\n' in ev[0]:
        ev = [ln.strip() for ln in ev[0].splitlines() if ln.strip()] or ev
        ev = _store._coalesce_black_mod_evidence(ev)
    kind_suffix = fid.split('#', 1)[1].strip() if '#' in fid else ''
    if kind_suffix and kind_suffix in ('task', 'startup', 'service', 'registry', 'wmi', 'other'):
        filtered = []
        for line in ev:
            low = line.lower()
            if kind_suffix == 'wmi' and ('wmi' in low or 'filters=' in low):
                filtered.append(line)
            elif kind_suffix == 'registry' and ('hk' in low or 'ifeo' in low or 'winlogon' in low or ('registry' in low)):
                filtered.append(line)
            elif kind_suffix == 'startup' and ('startup' in low or '启动项' in line or '\\\\run' in low):
                filtered.append(line)
            elif kind_suffix == 'task' and ('计划任务' in line or 'schtasks' in low or line.strip().startswith('\\')):
                filtered.append(line)
            elif kind_suffix == 'service' and ('服务' in line or 'service' in low or '[服务]' in line):
                filtered.append(line)
            elif kind_suffix == 'other':
                filtered.append(line)
        if filtered:
            ev = filtered
    total = len(ev)
    slice_ev = ev[offset:offset + limit]
    return {'ok': True, 'file': rid, 'id': fid, 'base_id': base_id, 'title': item.get('title') or '', 'count': int(item.get('count') or total), 'total': total, 'offset': offset, 'limit': limit, 'items': slice_ev, 'evidence_total': total, 'truncated': False}
