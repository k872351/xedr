"""Report persistence extracted from db_store."""
from __future__ import annotations

from . import db_store as _store


def save_report_db(report: Dict[str, Any], analysis: Dict[str, Any], fname: str) -> Path:
    """分析完成后写入独立 db（reports/<stem>/analysis.db），并更新索引。"""
    rid = _store.P.report_id(fname)
    dbp = _store.P.db_path_for_write(rid)
    legacy = _store.P.legacy_db_path(rid)
    if legacy.exists() and legacy.resolve() != dbp.resolve() and (not dbp.exists()):
        try:
            _store.P.migrate_report_to_folder(rid)
            dbp = _store.P.db_path_for_write(rid)
        except Exception:
            pass
    conn = _store._connect(dbp)
    try:
        _store._init_schema(conn)
        conn.execute('DELETE FROM meta')
        conn.execute('DELETE FROM findings_agg')
        conn.execute('DELETE FROM blobs')
        try:
            conn.execute('DELETE FROM entity_lists')
        except _store.sqlite3.OperationalError:
            pass
        skip_files = bool(report.get('_files_ingested'))
        if not skip_files:
            conn.execute('DELETE FROM files')
        meta = {'hostname': report.get('hostname') or '', 'ip': report.get('ip') or '', 'os': report.get('os') or '', 'os_family': (report.get('os_family') or '').strip().lower(), 'collect_time': report.get('collect_time') or '', 'report_file': rid, 'report_folder': _store.P.report_stem(rid), 'db_version': '2'}
        if meta['os_family'] not in ('linux', 'windows'):
            try:
                from .os_detect import detect_os_family
                meta['os_family'] = detect_os_family(report)
                report['os_family'] = meta['os_family']
            except Exception:
                meta['os_family'] = 'windows'
        for k, v in meta.items():
            conn.execute('INSERT INTO meta(key,value) VALUES(?,?)', (k, str(v)))
        summary = analysis.get('summary') or {}
        summary_agg = analysis.get('summary_aggregated') or {}
        pipe = analysis.get('pipeline') or {}
        pipe_slim = {'matchers': pipe.get('matchers') or [], 'rules_used': pipe.get('rules_used') or []}
        conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', ('summary', _store._jdump(summary)))
        conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', ('summary_aggregated', _store._jdump(summary_agg)))
        conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', ('pipeline', _store._jdump(pipe_slim)))
        conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', ('timeline', _store._jdump((analysis.get('timeline') or [])[:500])))
        if analysis.get('ai'):
            conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', ('ai', _store._jdump(analysis['ai'])))
        if analysis.get('meta'):
            conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', ('analysis_meta', _store._jdump(analysis['meta'])))
        raw = analysis.get('findings') or []
        conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', ('findings_raw_sample', _store._jdump(raw[:200])))
        conn.execute('INSERT INTO meta(key,value) VALUES(?,?)', ('raw_findings_total', str(len(raw))))
        fbm = analysis.get('findings_by_module') or {}
        fbm_slim = {}
        _mod_sample = 300
        for k, block in fbm.items():
            if not isinstance(block, dict):
                continue
            items = block.get('findings') or []
            fbm_slim[k] = {'matcher': block.get('matcher') or k, 'count': block.get('count') or len(items), 'high': block.get('high') or 0, 'findings': items[:_mod_sample], 'truncated': len(items) > _mod_sample}
        conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', ('findings_by_module', _store._jdump(fbm_slim)))
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
        for key in _store.BLOB_KEYS:
            if key not in report:
                continue
            val = report.get(key)
            if key == 'file_scans':
                continue
            if key == 'event_logs' and isinstance(val, list):
                if bool(report.get('_event_logs_ingested')):
                    n_ev = int(report.get('_event_logs_count') or 0)
                    if n_ev <= 0:
                        try:
                            n_ev = int(conn.execute('SELECT COUNT(1) AS c FROM event_logs').fetchone()['c'] or 0)
                        except Exception:
                            n_ev = 0
                    conn.execute('INSERT INTO meta(key,value) VALUES(?,?)', ('count_event_logs', str(n_ev)))
                    row = conn.execute('SELECT 1 AS o FROM blobs WHERE name=? LIMIT 1', (key,)).fetchone()
                    if not row:
                        conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', (key, '[]'))
                    continue
                conn.execute('DELETE FROM event_logs')
                n_ev = _store._insert_event_log_rows(conn, val)
                conn.execute('INSERT INTO meta(key,value) VALUES(?,?)', ('count_event_logs', str(n_ev)))
                sample = [x for x in val if isinstance(x, dict)][:300]
                conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', (key, _store._jdump(sample)))
                continue
            if key == 'browser_artifacts' and isinstance(val, list):
                slim = [a for a in val if isinstance(a, dict)]
                val = slim
            conn.execute('INSERT INTO blobs(name,data) VALUES(?,?)', (key, _store._jdump(val)))
            if isinstance(val, list):
                conn.execute('INSERT INTO meta(key,value) VALUES(?,?)', (f'count_{key}', str(len(val))))
            elif isinstance(val, dict):
                n = len(val)
                conn.execute('INSERT INTO meta(key,value) VALUES(?,?)', (f'count_{key}', str(n)))
            elif val is not None and val != '':
                conn.execute('INSERT INTO meta(key,value) VALUES(?,?)', (f'count_{key}', '1'))
        files = report.get('file_scans') or []
        if skip_files:
            n_files = int(report.get('_files_count') or 0)
            if n_files <= 0:
                try:
                    n_files = int(conn.execute('SELECT COUNT(1) AS c FROM files').fetchone()['c'] or 0)
                except Exception:
                    n_files = 0
            conn.execute('INSERT INTO meta(key,value) VALUES(?,?)', ('count_file_scans', str(n_files)))
            files = [{}] * n_files
        else:
            conn.execute('INSERT INTO meta(key,value) VALUES(?,?)', ('count_file_scans', str(len(files))))
            _store._insert_file_rows(conn, files)
        roots = report.get('file_scan_roots')
        if not isinstance(roots, dict) or not roots:
            if skip_files:
                try:
                    row = conn.execute('SELECT value FROM meta WHERE key=?', ('file_scan_roots',)).fetchone()
                    if row and row['value']:
                        roots = _store._jload(row['value'])
                except Exception:
                    roots = {}
            else:
                roots = _store._derive_file_scan_roots(report.get('file_scans') or [])
        if isinstance(roots, dict) and roots:
            conn.execute('INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)', ('file_scan_roots', _store._jdump(roots)))
        try:
            from .entity_lists import build_entity_lists_from_report
            el_counts = build_entity_lists_from_report(conn, report, rid=rid)
            if el_counts:
                print(f'[db] entity_lists rid={rid} {el_counts}')
        except Exception as e:
            print(f'[db] entity_lists build failed: {e}')
        conn.commit()
    finally:
        conn.close()
    _store.upsert_index({'file': rid, 'db_path': str(dbp.relative_to(_store.config.REPORTS_DIR)).replace('\\', '/'), 'hostname': report.get('hostname'), 'collect_time': report.get('collect_time'), 'ip': _store.pick_primary_ip(report.get('ip') or ''), 'issues': (summary_agg.get('total') if summary_agg else None) or summary.get('total') or 0, 'raw_issues': summary.get('total') or len(raw), 'analyzed': True, 'processes': len(report.get('processes') or []), 'services': len(report.get('services') or []), 'files': len(files), 'os_family': report.get('os_family') or meta.get('os_family') or '', 'os': report.get('os') or ''})
    try:
        from .mysql_store import save_analysis_mysql
        save_analysis_mysql(report, analysis, rid)
    except Exception as e:
        print(f'[store] save_analysis_mysql: {e}')
    return dbp
