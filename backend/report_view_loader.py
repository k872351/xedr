"""Load persisted report views extracted from db_store."""
from __future__ import annotations

from . import db_store as _store


def load_view_from_db(report_file: str) -> Optional[Dict[str, Any]]:
    """从 db 组装前端所需结构，不读大 JSON。"""
    dbp = _store.db_path_for_report(report_file)
    if not dbp.exists():
        rel = None
        if _store.INDEX_DB.exists():
            conn = _store._connect(_store.INDEX_DB)
            try:
                _store._init_index(conn)
                row = conn.execute('SELECT db_path FROM reports WHERE file=?', (report_file,)).fetchone()
                if row and row['db_path']:
                    rel = _store.config.REPORTS_DIR / row['db_path']
            finally:
                conn.close()
        if rel and rel.exists():
            dbp = rel
        else:
            return None
    conn = _store._connect(dbp)
    try:
        _store._init_schema(conn)
        meta = {r['key']: r['value'] for r in conn.execute('SELECT key,value FROM meta')}
        blobs = {r['name']: _store._jload(r['data']) for r in conn.execute('SELECT name,data FROM blobs')}
        findings = _store._load_fresh_findings(report_file)
        try:
            file_rows = conn.execute('SELECT full_path,name,path,ext,size,company,product,description,file_version,signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system FROM files').fetchall()
            file_scans = [{'full_path': r['full_path'], 'name': r['name'], 'path': r['path'], 'ext': r['ext'], 'size': r['size'], 'company': r['company'] or '', 'product': r['product'] or '', 'description': r['description'] or '', 'file_version': r['file_version'] or '', 'signed': bool(r['signed']), 'signer': r['signer'] or '', 'sig_status': r['sig_status'] or '', 'sig_type': (r['sig_type'] if 'sig_type' in r.keys() else '') or '', 'magic_hex': r['magic_hex'] or '', 'md5': (r['md5'] if 'md5' in r.keys() else '') or '', 'sha1': (r['sha1'] if 'sha1' in r.keys() else '') or '', 'sha256': (r['sha256'] if 'sha256' in r.keys() else '') or '', 'hidden': bool(r['hidden']) if 'hidden' in r.keys() else False, 'system': bool(r['system']) if 'system' in r.keys() else False} for r in file_rows]
        except _store.sqlite3.OperationalError:
            try:
                file_rows = conn.execute('SELECT full_path,name,path,ext,size,company,product,description,file_version,signed,signer,sig_status,magic_hex,hidden,system FROM files').fetchall()
                file_scans = [{'full_path': r['full_path'], 'name': r['name'], 'path': r['path'], 'ext': r['ext'], 'size': r['size'], 'company': r['company'] or '', 'product': r['product'] or '', 'description': r['description'] or '', 'file_version': r['file_version'] or '', 'signed': bool(r['signed']), 'signer': r['signer'] or '', 'sig_status': r['sig_status'] or '', 'magic_hex': r['magic_hex'] or '', 'hidden': bool(r['hidden']) if 'hidden' in r.keys() else False, 'system': bool(r['system']) if 'system' in r.keys() else False} for r in file_rows]
            except _store.sqlite3.OperationalError:
                try:
                    file_rows = conn.execute('SELECT full_path,name,path,ext,size,company,product,description,file_version,signed,signer,sig_status,magic_hex FROM files').fetchall()
                    file_scans = [{'full_path': r['full_path'], 'name': r['name'], 'path': r['path'], 'ext': r['ext'], 'size': r['size'], 'company': r['company'] or '', 'product': r['product'] or '', 'description': r['description'] or '', 'file_version': r['file_version'] or '', 'signed': bool(r['signed']), 'signer': r['signer'] or '', 'sig_status': r['sig_status'] or '', 'magic_hex': r['magic_hex'] or '', 'hidden': False, 'system': False} for r in file_rows]
                except _store.sqlite3.OperationalError:
                    file_rows = conn.execute('SELECT full_path,name,path,ext,size FROM files').fetchall()
                    file_scans = [{'full_path': r['full_path'], 'name': r['name'], 'path': r['path'], 'ext': r['ext'], 'size': r['size'], 'hidden': False, 'system': False} for r in file_rows]
        out: Dict[str, Any] = {'hostname': meta.get('hostname'), 'ip': meta.get('ip'), 'os': meta.get('os'), 'os_family': meta.get('os_family') or '', 'collect_time': meta.get('collect_time'), 'file_scans': file_scans, '_source': 'db', '_db': str(dbp.name), '_report_file': meta.get('report_file') or report_file}
        for k, v in blobs.items():
            if k in ('summary', 'summary_aggregated', 'pipeline', 'timeline', 'ai', 'analysis_meta', 'findings_raw_sample', 'findings_by_module'):
                continue
            if k in _store.RETIRED_BLOB_KEYS:
                continue
            out[k] = v
        analysis = {'findings_aggregated': findings, 'findings': blobs.get('findings_raw_sample') or [], 'findings_by_module': blobs.get('findings_by_module') or {}, 'summary': blobs.get('summary') or {}, 'summary_aggregated': blobs.get('summary_aggregated') or {'total': len(findings)}, 'pipeline': blobs.get('pipeline') or {}, 'timeline': blobs.get('timeline') or [], 'ai': blobs.get('ai'), 'meta': blobs.get('analysis_meta') or {}, 'ioc_hits': {}}
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
                    analysis['findings'] = analysis.get('findings') or local_findings
                    findings = local_findings
                elif ma.get('findings_aggregated'):
                    analysis['findings_aggregated'] = ma['findings_aggregated']
                    analysis['findings'] = ma.get('findings') or ma['findings_aggregated']
                    findings = analysis['findings_aggregated']
                if ma.get('_findings_total') is not None and (not local_findings):
                    analysis['_findings_total'] = ma['_findings_total']
                analysis['_source'] = 'sqlite+mysql' if local_findings else 'mysql+sqlite'
                out['_source'] = analysis['_source']
        except Exception as e:
            print('[view] mysql overlay:', e)
        try:
            from .pipeline import prune_inactive_modules
            analysis = prune_inactive_modules(analysis)
        except Exception:
            pass
        try:
            from .text_fix import fix_analysis_text
            analysis = fix_analysis_text(analysis)
        except Exception:
            pass
        out['analysis'] = analysis
        if not out.get('suspicious_items'):
            out['suspicious_items'] = [{'type': x.get('category'), 'name': x.get('title'), 'reason': x.get('reason') or x.get('title'), 'severity': x.get('severity', 'medium'), 'count': x.get('count', 1)} for x in findings]
        return out
    finally:
        conn.close()
