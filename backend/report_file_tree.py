"""Database-backed file tree queries, kept behind the db_store API."""
from __future__ import annotations

from . import db_store as _store


def load_files_for_tree(report_file: str, q: str='', hidden_only: bool=False, limit: int=8000, offset: int=0, root: str='', include_tree: bool=False, recent_days: int=0, mtime_from: str='', mtime_to: str='') -> Dict[str, Any]:
    """从 analysis.db files 表按需取文件列表（供文件树），避免整包 view。

    默认按分目录分层抽样（Users 优先），避免 Program Files 占满 LIMIT 后看不到 Users。
    传 root=Users 等可只看某一目录。
    recent_days=1/3/5：按 mtime 相对采集时间筛近 N 天（扁平列表）。
    mtime_from / mtime_to：绝对时间窗（修改时间），与 recent_days 互斥时优先绝对窗。
    """
    from datetime import datetime, timedelta
    rid = _store.P.report_id(report_file)
    dbp = _store._resolve_db_path(rid)
    if not dbp or not dbp.exists():
        return {'files': [], 'total': 0, 'returned': 0, 'truncated': False, 'root': root or ''}
    lim = max(1, min(20000, int(limit or 8000)))
    off = max(0, int(offset or 0))
    root_tag = (root or '').strip()
    try:
        recent_days = int(recent_days or 0)
    except (TypeError, ValueError):
        recent_days = 0
    if recent_days not in (0, 1, 3, 5):
        recent_days = 0
    mf = _store._parse_mtime_bound(mtime_from)
    mt = _store._parse_mtime_bound(mtime_to)
    if mf and mt and (mf > mt):
        mf, mt = (mt, mf)
    conn = _store._connect(dbp)
    try:
        _store._init_schema(conn)
        try:
            total = int(conn.execute('SELECT COUNT(*) FROM files').fetchone()[0] or 0)
        except Exception:
            total = 0
        recent_counts: Dict[str, int] = {}
        collect_anchor = ''
        cols = {r[1] for r in conn.execute('PRAGMA table_info(files)').fetchall()}
        if 'mtime' in cols:
            try:
                row = conn.execute("SELECT value FROM meta WHERE key='collect_time' LIMIT 1").fetchone()
                raw_ct = row[0] if row else ''
            except Exception:
                raw_ct = ''
            if not raw_ct:
                try:
                    rp = _store.P.report_dir(rid, create=False) / 'report.json'
                    if rp.is_file():
                        import json as _json
                        data = _json.loads(rp.read_text(encoding='utf-8', errors='replace'))
                        if isinstance(data, dict):
                            raw_ct = data.get('collect_time') or data.get('time') or ''
                except Exception:
                    raw_ct = ''
            s = str(raw_ct or '').replace('T', ' ').replace('Z', '')
            if len(s) > 19 and s[19] in '+-.':
                s = s[:19]
            anchor = None
            for n, fmt in ((19, '%Y-%m-%d %H:%M:%S'), (16, '%Y-%m-%d %H:%M'), (10, '%Y-%m-%d')):
                if len(s) < n:
                    continue
                try:
                    anchor = datetime.strptime(s[:n], fmt)
                    break
                except ValueError:
                    continue
            if anchor:
                collect_anchor = anchor.strftime('%Y-%m-%d %H:%M:%S')
                for d in (1, 3, 5):
                    cut = (anchor - timedelta(days=d)).strftime('%Y-%m-%d %H:%M:%S')
                    recent_counts[str(d)] = int(conn.execute("SELECT COUNT(1) FROM files WHERE IFNULL(mtime,'')!='' AND mtime>=?", (cut,)).fetchone()[0] or 0)
        use_abs_range = bool(mf or mt)
        use_recent = not use_abs_range and recent_days > 0 and bool(collect_anchor)
        if (use_abs_range or use_recent) and 'mtime' in cols:
            where = ["IFNULL(mtime,'')!=''"]
            params: List[Any] = []
            if use_abs_range:
                if mf:
                    where.append('mtime>=?')
                    params.append(mf)
                if mt:
                    where.append('mtime<=?')
                    params.append(mt)
            else:
                cut = (datetime.strptime(collect_anchor, '%Y-%m-%d %H:%M:%S') - timedelta(days=recent_days)).strftime('%Y-%m-%d %H:%M:%S')
                where.append('mtime>=?')
                params.append(cut)
            if hidden_only:
                where.append('(hidden=1 OR system=1)')
            if q:
                ql = (q or '').strip().lower()
                from .search_sql import classify, files_where
                plan = classify(ql, 'smart')
                if plan.mode in ('segment', 'glob'):
                    pred, par = files_where(plan)
                    where.append(pred)
                    params.extend(par)
                else:
                    where.append('(lower(full_path) LIKE ? OR lower(name) LIKE ?)')
                    params.extend([f'%{ql}%', f'%{ql}%'])
            wh = ' AND '.join(where)
            filtered_total = int(conn.execute(f'SELECT COUNT(1) FROM files WHERE {wh}', params).fetchone()[0] or 0)
            sel = 'full_path,name,path,ext,size,company,signer,sig_status,md5,sha1,sha256,hidden,system,mtime'
            have = [c for c in sel.split(',') if c in cols]
            rows = conn.execute(f"SELECT {','.join(have)} FROM files WHERE {wh} ORDER BY mtime DESC, full_path LIMIT ? OFFSET ?", params + [lim, off]).fetchall()
            files = []
            for r in rows:
                item = {k: r[k] for k in r.keys()}
                item['dir'] = False
                item['file'] = True
                files.append(item)
            return {'files': files, 'total': total, 'filtered_total': filtered_total, 'returned': len(files), 'truncated': filtered_total > off + len(files), 'root': root_tag, 'recent_days': 0 if use_abs_range else recent_days, 'mtime_from': mf, 'mtime_to': mt, 'recent_counts': recent_counts, 'collect_time': collect_anchor, 'mtime_mode': True}
        base_where: List[str] = []
        base_params: List[Any] = []
        if hidden_only:
            base_where.append('(hidden=1 OR system=1)')
        if q:
            ql = (q or '').strip().lower()
            tokens = [t for t in ql.split() if t and t not in ('-', '—', '–')]
            unsigned_set = {'未签名', 'unsigned', '无签名'}
            empty_set = {'空签名', 'empty', 'nosig', '无状态'}
            signed_set = {'已签名', 'signed', 'valid'}
            missing_only = bool(tokens) and all((t == 'missing' for t in tokens))
            empty_only = bool(tokens) and all((t in empty_set for t in tokens))
            unsigned_only = bool(tokens) and all((t in unsigned_set for t in tokens))
            signed_only = bool(tokens) and all((t in signed_set for t in tokens))
            if missing_only:
                base_where.append("LOWER(IFNULL(sig_status,'')) = 'missing'")
            elif empty_only:
                base_where.append("(IFNULL(sig_status,'')='' OR LOWER(IFNULL(sig_status,'')) IN ('-','n/a','unknown')) AND IFNULL(signed,0)=0")
            elif unsigned_only:
                base_where.append("(LOWER(IFNULL(sig_status,'')) IN ('missing','notsigned','unsigned','error','hashmismatch','nottrusted') OR (IFNULL(signed,0)=0 AND IFNULL(sig_status,'')!='' AND LOWER(IFNULL(sig_status,'')) NOT LIKE '%valid%' AND LOWER(IFNULL(sig_status,'')) NOT IN ('-','n/a','unknown')))")
            elif signed_only:
                base_where.append("(IFNULL(signed,0)=1 OR LOWER(IFNULL(sig_status,'')) LIKE '%valid%')")
            else:
                from .search_sql import classify, files_where
                plan = classify(ql, 'smart')
                if plan.mode in ('segment', 'glob'):
                    pred, par = files_where(plan)
                    base_where.append(pred)
                    base_params.extend(par)
                else:
                    like = f'%{ql}%'
                    ext_like = f"%{ql.lstrip('.')}%"
                    base_where.append("(LOWER(full_path) LIKE ? OR LOWER(name) LIKE ? OR LOWER(IFNULL(company,'')) LIKE ? OR LOWER(IFNULL(signer,'')) LIKE ? OR LOWER(IFNULL(sig_status,'')) LIKE ? OR LOWER(IFNULL(product,'')) LIKE ? OR LOWER(IFNULL(description,'')) LIKE ? OR LOWER(IFNULL(magic_hex,'')) LIKE ? OR LOWER(IFNULL(ext,'')) LIKE ? OR LOWER(REPLACE(IFNULL(ext,''), '.', '')) LIKE ?)")
                    base_params.extend([like] * 9 + [ext_like])
        root_clause = _store._root_where_clause(root_tag)
        if root_clause:
            base_where.append(root_clause)
        try:
            count_sql = 'SELECT COUNT(*) FROM files'
            if base_where:
                count_sql += ' WHERE ' + ' AND '.join(base_where)
            filtered_total = int(conn.execute(count_sql, base_params).fetchone()[0] or 0)
        except Exception:
            filtered_total = total

        def _fetch(extra_where: Optional[str], lim_n: int, offset_n: int=0) -> List[Any]:
            wh = list(base_where)
            if extra_where:
                wh.append(extra_where)
            sql = f'SELECT {_FILE_TREE_COLS} FROM files'
            if wh:
                sql += ' WHERE ' + ' AND '.join(wh)
            sql += ' ORDER BY lower(full_path) LIMIT ? OFFSET ?'
            params = list(base_params) + [max(1, lim_n), max(0, offset_n)]
            try:
                return list(conn.execute(sql, params).fetchall())
            except sqlite3.OperationalError:
                wh2: List[str] = []
                params2: List[Any] = []
                if hidden_only:
                    pass
                if q:
                    wh2.append('(LOWER(full_path) LIKE ? OR LOWER(name) LIKE ?)')
                    like = f'%{str(q).lower()}%'
                    params2.extend([like, like])
                if extra_where:
                    wh2.append(extra_where)
                if root_clause:
                    wh2.append(root_clause)
                sql2 = 'SELECT full_path,name,path,ext,size FROM files'
                if wh2:
                    sql2 += ' WHERE ' + ' AND '.join(wh2)
                sql2 += ' ORDER BY lower(full_path) LIMIT ? OFFSET ?'
                params2.extend([max(1, lim_n), max(0, offset_n)])
                return list(conn.execute(sql2, params2).fetchall())
        rows: List[Any] = []
        dir_rows: List[Any] = []
        dir_total = 0
        if q:
            ql = (q or '').strip().lower()
            like = f'%{ql}%'
            dir_where = ['(lower(d.name) LIKE ? OR lower(d.full_path) LIKE ?)']
            dir_args: List[Any] = [like, like]
            if hidden_only:
                dir_where.append("EXISTS (SELECT 1 FROM files hf WHERE (hf.hidden=1 OR hf.system=1) AND (hf.parent_path_norm=d.path_norm OR substr(hf.parent_path_norm,1,length(d.path_norm)+1)=d.path_norm||'\\'))")
            dir_sql = ' AND '.join(dir_where)
            try:
                dir_total = int(conn.execute(f'SELECT COUNT(1) FROM file_directories d WHERE {dir_sql}', dir_args).fetchone()[0] or 0)
            except Exception:
                dir_total = 0
            filtered_total = dir_total + filtered_total
            if off < dir_total:
                dir_rows = conn.execute(f'SELECT d.path_norm,d.parent_path_norm,d.name,d.full_path,EXISTS(SELECT 1 FROM file_directories c WHERE c.parent_path_norm=d.path_norm) OR EXISTS(SELECT 1 FROM files f WHERE f.parent_path_norm=d.path_norm) AS has_children FROM file_directories d WHERE {dir_sql} ORDER BY d.name COLLATE NOCASE LIMIT ? OFFSET ?', dir_args + [lim, off]).fetchall()
            file_off = max(0, off - dir_total)
            file_lim = max(0, lim - len(dir_rows))
            if file_lim > 0:
                rows = _fetch(None, file_lim, file_off)
        elif root_clause or total <= lim or hidden_only or off:
            rows = _fetch(None, lim, off)
        else:
            roots_meta: Dict[str, int] = {}
            try:
                raw = conn.execute('SELECT value FROM meta WHERE key=?', ('file_scan_roots',)).fetchone()
                if raw and raw['value']:
                    roots_meta = _store._jload(raw['value']) or {}
            except Exception:
                roots_meta = {}
            if not isinstance(roots_meta, dict):
                roots_meta = {}
            present = [k for k in _store._ROOT_ORDER if int(roots_meta.get(k) or 0) > 0]
            if not present:
                present = list(_store._ROOT_ORDER)
            users_quota = max(lim // 2, lim // max(1, len(present))) if 'Users' in present else 0
            remain = lim - users_quota
            other = [k for k in present if k != 'Users']
            per = max(200, remain // max(1, len(other))) if other else 0
            quotas: Dict[str, int] = {}
            if 'Users' in present:
                quotas['Users'] = users_quota
            for k in other:
                quotas[k] = per
            seen_paths: Set[str] = set()
            for tag in _store._ROOT_ORDER:
                need = int(quotas.get(tag) or 0)
                if need <= 0:
                    continue
                left = lim - len(rows)
                if left <= 0:
                    break
                chunk = _fetch(_store._root_where_clause(tag), min(need, left))
                for r in chunk:
                    fp = r['full_path'] if 'full_path' in r.keys() else ''
                    if fp in seen_paths:
                        continue
                    seen_paths.add(fp)
                    rows.append(r)
                    if len(rows) >= lim:
                        break
            if len(rows) < lim:
                left = lim - len(rows)
                for r in _fetch(None, lim * 2):
                    fp = r['full_path'] if 'full_path' in r.keys() else ''
                    if fp in seen_paths:
                        continue
                    seen_paths.add(fp)
                    rows.append(r)
                    left -= 1
                    if left <= 0:
                        break
        files = [_store._file_row_to_tree_item(r) for r in rows]
        if dir_rows:
            dir_items = [{'name': r['name'] or '', 'full_path': r['full_path'] or '', 'path': str(r['full_path'] or '').replace('\\', '/'), 'dir': True, 'has_children': bool(r['has_children'])} for r in dir_rows]
            files = dir_items + files
        roots_out = {}
        try:
            raw = conn.execute('SELECT value FROM meta WHERE key=?', ('file_scan_roots',)).fetchone()
            if raw and raw['value']:
                roots_out = _store._jload(raw['value']) or {}
        except Exception:
            roots_out = {}
        out = {'files': files, 'total': total, 'filtered_total': filtered_total, 'returned': len(files), 'offset': off, 'limit': lim, 'truncated': filtered_total > off + len(files), 'root': root_tag, 'file_scan_roots': roots_out if isinstance(roots_out, dict) else {}, 'recent_days': 0, 'recent_counts': recent_counts, 'collect_time': collect_anchor}
        if include_tree:
            out['tree'] = _store._build_files_tree(files)
            out.pop('files', None)
        return out
    finally:
        conn.close()
