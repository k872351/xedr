import sqlite3
import unittest
from unittest.mock import patch

from backend import agent_protocol as ap


class _Connection(sqlite3.Connection):
    def close(self):
        pass


class AgentIdentityTests(unittest.TestCase):
    def test_approval_resolution_requires_exact_identity(self):
        from backend.response_approval import _resolve_agent_id
        conn = sqlite3.connect(':memory:')
        self.addCleanup(conn.close)
        conn.execute('CREATE TABLE agents(agent_id TEXT, hostname TEXT)')
        conn.executemany('INSERT INTO agents VALUES(?,?)', [('id-one','fixture'), ('id-two','fixture')])
        self.assertIsNone(_resolve_agent_id(conn, 'fixture'))
        self.assertEqual(_resolve_agent_id(conn, 'id-one'), 'id-one')

    def test_same_hostname_has_distinct_identity(self):
        conn = sqlite3.connect(':memory:', factory=_Connection)
        self.addCleanup(sqlite3.Connection.close, conn)
        conn.row_factory = sqlite3.Row
        conn.executescript(ap._SCHEMA)
        ap._mig_001_agent_build_protocol(conn)
        ap._mig_002_credentials_health(conn)
        ap._mig_012_heartbeat_period_and_index_outbox(conn)
        conn.commit()
        with patch.object(ap, '_connect', return_value=conn), patch.object(ap, 'ensure_db'), \
             patch.object(ap, 'bump_live'), patch('backend.agent_store.write_agent'):
            payload = {'hostname': 'fixture-host', 'capabilities': ['auth.agent_secret'], 'protocol_min': 1, 'protocol_max': 2}
            first = ap.register_agent(payload, cred='enroll')
            second = ap.register_agent(payload, cred='enroll')
            self.assertTrue(first['ok'] and second['ok'])
            self.assertNotEqual(first['agent_id'], second['agent_id'])
            self.assertNotEqual(first['agent_secret'], second['agent_secret'])
            row = conn.execute('SELECT secret_hash,secret_rev FROM agents WHERE agent_id=?', (first['agent_id'],)).fetchone()
            self.assertFalse(ap.register_agent(dict(payload, agent_id=first['agent_id']), cred='enroll')['ok'])
            self.assertTrue(ap.register_agent(dict(payload, agent_id=first['agent_id']), cred='secret')['ok'])
            self.assertEqual(tuple(row), tuple(conn.execute('SELECT secret_hash,secret_rev FROM agents WHERE agent_id=?', (first['agent_id'],)).fetchone()))
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM agents').fetchone()[0], 2)
