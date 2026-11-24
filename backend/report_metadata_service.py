"""Report metadata and index synchronization extracted from db_store."""
from __future__ import annotations

from . import db_store as _store


def rename_hostname(old_name: str, new_name: str) -> Dict[str, Any]:
    """将某主机下全部报告的显示主机名改为新名称（索引 + analysis.db meta + report.json）。"""
    old_name = (old_name or '').strip()
    new_name = (new_name or '').strip()
    if not old_name or not new_name:
        raise ValueError('主机名不能为空')
    if old_name == new_name:
        return {'updated': 0, 'old': old_name, 'new': new_name}
    if any((c in new_name for c in '<>:"/\\|?*')):
        raise ValueError('主机名含非法字符')
    if len(new_name) > 128:
        raise ValueError('主机名过长')
    updated_files: List[str] = []
    conn = _store._connect(_store.INDEX_DB)
    try:
        _store._init_index(conn)
        rows = conn.execute('SELECT file FROM reports WHERE hostname=?', (old_name,)).fetchall()
        files = [r['file'] for r in rows]
        if not files:
            raise ValueError(f'未找到主机: {old_name}')
        conn.execute('UPDATE reports SET hostname=? WHERE hostname=?', (new_name, old_name))
        conn.commit()
    finally:
        conn.close()
    for rid in files:
        dbp = _store.P.resolve_analysis_db(rid)
        if dbp and dbp.exists():
            try:
                c = _store._connect(dbp)
                try:
                    _store._init_schema(c)
                    c.execute("INSERT INTO meta(key,value) VALUES('hostname',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (new_name,))
                    c.commit()
                finally:
                    c.close()
            except Exception as e:
                print(f'[rename_hostname] db {rid}:', e)
        jp = _store.P.resolve_report_json(rid)
        if jp and jp.exists():
            try:
                with open(jp, encoding='utf-8') as fh:
                    data = _store.json.load(fh)
                if isinstance(data, dict):
                    data['hostname'] = new_name
                    _store.write_report_json(jp, data)
            except Exception as e:
                print(f'[rename_hostname] json {rid}:', e)
        rp = _store.P.resolve_result_json(rid)
        if rp and rp.exists():
            try:
                with open(rp, encoding='utf-8') as fh:
                    data = _store.json.load(fh)
                if isinstance(data, dict):
                    if 'hostname' in data:
                        data['hostname'] = new_name
                    if isinstance(data.get('report'), dict):
                        data['report']['hostname'] = new_name
                    _store.write_report_json(rp, data)
            except Exception as e:
                print(f'[rename_hostname] result {rid}:', e)
        updated_files.append(rid)
    try:
        from .hosts import get_host_by_name, _hconnect
        h = get_host_by_name(old_name)
        if h:
            conn_h = _hconnect()
            try:
                conn_h.execute('UPDATE hosts SET name=?, updated_at=? WHERE id=?', (new_name, _store.time.time(), h['id']))
                conn_h.commit()
            finally:
                conn_h.close()
        else:
            from .hosts import ensure_host
            ensure_host(new_name)
    except Exception as e:
        print('[rename_hostname] hosts:', e)
    try:
        from .mysql_store import rename_reports_hostname
        rename_reports_hostname(old_name, new_name)
    except Exception as e:
        print('[rename_hostname] mysql reports:', e)
    return {'updated': len(updated_files), 'old': old_name, 'new': new_name, 'files': updated_files}

def backfill_os_family_index() -> int:
    """Fill empty/wrong os_family in SQLite index + MySQL from os / collector heuristics."""
    from .os_detect import detect_os_family
    updates: List[tuple] = []

    def _detect_for_row(file_id: str, hostname: str, os_label: str, cur_fam: str) -> tuple:
        cur = str(cur_fam or '').strip().lower()
        fake = {'os_family': cur, 'os': os_label or '', 'hostname': hostname or '', 'file': file_id or ''}
        try:
            folder = P.report_dir(file_id)
            rp = folder / 'report.json'
            if rp.is_file():
                data = json.loads(rp.read_text(encoding='utf-8', errors='replace'))
                if isinstance(data, dict):
                    fake.update({'os_family': data.get('os_family') or cur, 'os': data.get('os') or fake['os'], 'collector': data.get('collector'), 'source': data.get('source'), 'processes': data.get('processes') or [], 'security_extras': data.get('security_extras')})
        except Exception:
            pass
        fam = detect_os_family(fake)
        return (fam, str(fake.get('os') or os_label or '').strip())
    n = 0
    if _store.INDEX_DB.exists():
        conn = _store._connect(_store.INDEX_DB)
        try:
            _store._init_index(conn)
            rows = conn.execute('SELECT file, hostname, os, os_family FROM reports').fetchall()
            for r in rows:
                cur = str(r['os_family'] or '').strip().lower()
                fam, os_label = _detect_for_row(r['file'], r['hostname'] or '', r['os'] or '', cur)
                if fam and fam != cur:
                    conn.execute("UPDATE reports SET os_family=?, os=CASE WHEN ?<>'' THEN ? ELSE os END WHERE file=?", (fam, os_label, os_label, r['file']))
                    n += 1
                    updates.append((r['file'], fam, os_label))
                elif fam:
                    updates.append((r['file'], fam, os_label or (r['os'] or '')))
            conn.commit()
        finally:
            conn.close()
    try:
        from .mysql_db import mysql_ready, connect_mysql
        if mysql_ready():
            conn = connect_mysql()
            try:
                with conn.cursor() as cur:
                    cur.execute('SELECT file, hostname, os, os_family FROM reports')
                    rows = cur.fetchall() or []
                    for r in rows:
                        rid = r.get('file') or ''
                        cur_fam = str(r.get('os_family') or '').strip().lower()
                        fam, os_label = _detect_for_row(rid, r.get('hostname') or '', r.get('os') or '', cur_fam)
                        if not fam:
                            continue
                        if fam != cur_fam or (os_label and (not str(r.get('os') or '').strip())):
                            cur.execute("UPDATE reports SET os_family=%s, os=IF(%s<>'', %s, os) WHERE file=%s", (fam, os_label, os_label, rid))
                            if fam != cur_fam:
                                n += 1
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        print(f'[os_family] mysql backfill: {e}')
    try:
        _store.invalidate_list_cache()
    except Exception:
        pass
    return n

def sync_findings_to_analysis_db(report_file: str, analysis: Dict[str, Any]) -> bool:
    """light 阶段：只刷新 findings_agg + 分析摘要 blob，不碰 files/采集大表。

    让 analysis.db 与 result.json 告警对齐，避免界面读库仍见旧误报。
    """
    rid = _store.P.report_id(report_file)
    dbp = _store._resolve_db_path(rid) or _store.P.resolve_analysis_db(rid) or _store.P.db_path_for_write(rid)
    if not dbp:
        return False
    if not _store.Path(dbp).is_file():
        return False
    conn = _store._connect(dbp)
    try:
        _store._init_schema(conn)
        conn.execute('DELETE FROM findings_agg')
        agg_rows = []
        for item in analysis.get('findings_aggregated') or []:
            if not isinstance(item, dict):
                continue
            ex = item.get('extra') if isinstance(item.get('extra'), dict) else {}
            if not ex:
                ex = {k: item.get(k) for k in ('type', 'name', 'reason', 'kind', 'path', 'file_count', 'file', 'members_truncated') if k in item and item.get(k) is not None}
            else:
                ex = {k: v for k, v in ex.items() if k != 'members'}
            agg_rows.append((item.get('id') or f"{item.get('category')}|{item.get('title')}", item.get('category') or '', item.get('severity') or 'medium', item.get('title') or '', int(item.get('count') or 1), _store._jdump(item.get('evidence') or []), _store._jdump(item.get('sources') or []), item.get('rule_id') or '', item.get('matcher') or '', _store._jdump(ex)))
        if agg_rows:
            conn.executemany('INSERT OR REPLACE INTO findings_agg\n                   (id,category,severity,title,count,evidence,sources,rule_id,matcher,extra)\n                   VALUES(?,?,?,?,?,?,?,?,?,?)', agg_rows)

        def _upsert_blob(name: str, data: Any) -> None:
            conn.execute('DELETE FROM blobs WHERE name=?', (name,))
            conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', (name, _store._jdump(data)))
        summary = analysis.get('summary') or {}
        summary_agg = analysis.get('summary_aggregated') or {}
        pipe = analysis.get('pipeline') or {}
        pipe_slim = {'matchers': pipe.get('matchers') or [], 'rules_used': pipe.get('rules_used') or []}
        _upsert_blob('summary', summary)
        _upsert_blob('summary_aggregated', summary_agg)
        _upsert_blob('pipeline', pipe_slim)
        raw = analysis.get('findings') or []
        _upsert_blob('findings_raw_sample', raw[:200])
        conn.execute('INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)', ('raw_findings_total', str(len(raw))))
        fbm = analysis.get('findings_by_module') or {}
        fbm_slim = {}
        for k, block in fbm.items():
            if not isinstance(block, dict):
                continue
            items = block.get('findings') or []
            fbm_slim[k] = {'matcher': block.get('matcher') or k, 'count': block.get('count') or len(items), 'high': block.get('high') or 0, 'findings': items[:300], 'truncated': len(items) > 300}
        _upsert_blob('findings_by_module', fbm_slim)
        conn.commit()
        return True
    except Exception as e:
        print(f'[db_store] sync_findings_to_analysis_db: {e}')
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        conn.close()
