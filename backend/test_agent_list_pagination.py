import sqlite3
import time
import unittest
from unittest.mock import patch

from backend import agent_protocol as ap


class _Connection(sqlite3.Connection):
    def close(self):
        pass


class AgentListPaginationTests(unittest.TestCase):
    def test_page_and_online_filter_match_legacy(self):
        conn = sqlite3.connect(':memory:', factory=_Connection)
        self.addCleanup(sqlite3.Connection.close, conn)
        conn.row_factory = sqlite3.Row
        conn.executescript(ap._SCHEMA)
        ap._mig_001_agent_build_protocol(conn)
        ap._mig_002_credentials_health(conn)
        ap._mig_012_heartbeat_period_and_index_outbox(conn)
        now = 1800000000
        for i in range(1201):
            age = 10 if i % 3 == 0 else 100 if i % 3 == 1 else 400
            stamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now-age))
            conn.execute('INSERT INTO agents(agent_id,last_seen,last_heartbeat_at,heartbeat_period_sec,revoked,health_json) VALUES(?,?,?,?,?,?)',
                         (f'fixture-{i:04}', stamp, stamp, 120 if i % 2 else 3, int(i % 17 == 0), '{"fixture":true}'))
        conn.commit()
        with patch.object(ap, 'ensure_db'), patch.object(ap, '_connect', return_value=conn), \
             patch('backend.agent_release.release_status', return_value={}), patch.object(ap.time, 'time', return_value=now):
            legacy = ap.list_agents()['items']
            for state in (None, True, False):
                expected = [row['agent_id'] for row in legacy if state is None or row['online'] == state]
                obtained = []
                offset = 0
                while offset is not None:
                    result = ap.list_agents(offset=offset, limit=100, online=state, include_health=False)
                    self.assertEqual(result['page']['total'], len(expected))
                    self.assertTrue(all('health' not in row and 'secret_hash' not in row for row in result['items']))
                    obtained.extend(row['agent_id'] for row in result['items'])
                    offset = result['page']['next_offset']
                self.assertEqual(obtained, expected)
            self.assertEqual(ap.list_agents(limit=501)['error'], 'agent_page_invalid')
