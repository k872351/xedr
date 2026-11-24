import sqlite3
import unittest
from unittest.mock import patch
from backend import agent_protocol as ap


class _Connection(sqlite3.Connection):
    def close(self):
        pass


class AlertCursorPaginationTests(unittest.TestCase):
    def test_filtered_total_and_cursor_cover_more_than_500(self):
        conn = sqlite3.connect(':memory:', factory=_Connection)
        self.addCleanup(sqlite3.Connection.close, conn)
        conn.row_factory = sqlite3.Row
        conn.executescript(ap._SCHEMA)
        conn.executemany('INSERT INTO agent_events(agent_id,severity,module,status,created_at) VALUES(?,?,?,?,?)',
            [('fixture', 'high', 'fixture-module', 'open', '2026-11-22T12:00:00')] * 1201 +
            [('fixture', 'low', 'fixture-module', 'open', '2026-11-22T12:00:00')] * 400 +
            [('other', 'high', 'fixture-module', 'open', '2026-11-22T12:00:00')] * 20)
        conn.commit()
        filters = dict(agent_id='fixture', severity='high', module='fixture-module', status='open',
                       start_at='2026-11-22T00:00:00', end_at='2026-11-23T00:00:00', limit=200)
        with patch.object(ap, 'ensure_db'), patch.object(ap, '_connect', return_value=conn), patch.object(ap, '_quiet_open_alerts'):
            page = ap.list_events(**filters)
            anchor = page['anchor_id']
            conn.execute('INSERT INTO agent_events(agent_id,severity,module,status,created_at) VALUES(?,?,?,?,?)',
                         ('fixture', 'high', 'fixture-module', 'open', '2026-11-22T12:01:00'))
            ids = []
            while True:
                self.assertEqual(page['total'], 1201)
                ids.extend(item['id'] for item in page['items'])
                before = page['next_before_id']
                if before is None:
                    break
                page = ap.list_events(**filters, anchor_id=anchor, before_id=before)
            self.assertEqual(ids, list(range(1201, 0, -1)))
            self.assertEqual(ap.list_events(start_at='invalid')['error'], 'invalid_event_time_range')
            self.assertEqual(ap.list_events(status='invalid')['error'], 'invalid_event_status')
