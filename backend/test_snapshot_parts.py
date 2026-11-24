"""Staging tests use only synthetic inventory rows and an isolated SQLite DB."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backend.agent_snapshot_parts import accept_part, ensure_schema


class SnapshotPartsTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(':memory:')
        self.addCleanup(self.conn.close)
        ensure_schema(self.conn)
        self.publish = Mock(return_value={'ok': True})
        raw = json.dumps({'agent_id': 'ignored', 'module': 'service', 'items': [{'name': 'sample'}]}, ensure_ascii=False)
        self.parts = [raw[:20], raw[20:40], raw[40:]]
        self.meta = {'module': 'service', 'transfer_id': 'a' * 64, 'part_count': 3,
                     'checksum': hashlib.sha256(raw.encode()).hexdigest()}

    def send(self, index, **overrides):
        part = dict(self.meta, part_index=index, fragment=self.parts[index])
        part.update(overrides)
        self.conn.execute('SAVEPOINT part')
        result = accept_part(self.conn, 'authenticated-agent', part, modules=('service',), publish=self.publish)
        if not result.get('ok'):
            self.conn.execute('ROLLBACK TO part')
        self.conn.execute('RELEASE part')
        return result

    def test_only_complete_snapshot_is_published(self):
        self.assertFalse(self.send(0)['complete'])
        self.assertFalse(self.send(0)['complete'])
        self.assertFalse(self.send(2)['ok'])
        self.publish.assert_not_called()
        self.assertFalse(self.send(1)['complete'])
        self.assertTrue(self.send(2)['complete'])
        self.publish.assert_called_once_with({'agent_id': 'authenticated-agent', 'module': 'service', 'items': [{'name': 'sample'}]})
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM agent_snapshot_parts').fetchone()[0], 0)

    def test_mismatched_checksum_and_replayed_conflict(self):
        self.assertTrue(self.send(0)['ok'])
        self.assertFalse(self.send(0, fragment='conflicting')['ok'])
        self.assertFalse(self.send(1, checksum='b' * 64)['ok'])
        self.assertTrue(self.send(1)['ok'])
        self.assertFalse(self.send(2, fragment='corrupted')['ok'])
        self.publish.assert_not_called()

    def test_superseded_transfer_never_publishes_partial(self):
        self.assertTrue(self.send(0)['ok'])
        self.assertTrue(self.send(0, transfer_id='b' * 64)['ok'])
        self.assertFalse(self.send(1)['ok'])
        self.publish.assert_not_called()

    def test_large_software_snapshot_stays_atomic(self):
        items = [{'name': f'pkg-{i}'} for i in range(1501)]
        snapshot = {'module': 'software', 'items': items, 'paged_software': True}
        raw = json.dumps(snapshot)
        midpoint = len(raw) // 2
        fragments = [raw[:midpoint], raw[midpoint:]]
        meta = {'module': 'software', 'transfer_id': 'c' * 64, 'part_count': 2,
                'checksum': hashlib.sha256(raw.encode()).hexdigest()}
        for i, fragment in enumerate(fragments):
            result = accept_part(self.conn, 'synthetic', dict(meta, fragment=fragment, part_index=i),
                                 modules=('software',), publish=self.publish)
            self.assertTrue(result['ok'])
            self.assertEqual(result['complete'], i == 1)
            if i == 0:
                self.publish.assert_not_called()
        self.publish.assert_called_once_with(dict(snapshot, agent_id='synthetic'))

    def test_large_asset_snapshots_stay_atomic(self):
        for module in ('service', 'hotfix', 'user'):
            with self.subTest(module=module):
                self.publish.reset_mock()
                snapshot = {'module': module, 'paged_inventory': True,
                            'items': [{'name': f'fixture-{i}'} for i in range(1501)]}
                raw = json.dumps(snapshot)
                midpoint = len(raw) // 2
                meta = {'module': module, 'transfer_id': 'd' * 64, 'part_count': 2,
                        'checksum': hashlib.sha256(raw.encode()).hexdigest()}
                for index, fragment in enumerate((raw[:midpoint], raw[midpoint:])):
                    result = accept_part(self.conn, 'synthetic', dict(meta, fragment=fragment, part_index=index),
                                         modules=(module,), publish=self.publish)
                    self.assertTrue(result['ok'])
                    self.assertEqual(result['complete'], index == 1)
                    if index == 0:
                        self.publish.assert_not_called()
                self.publish.assert_called_once_with(dict(snapshot, agent_id='synthetic'))

    def test_batch_receipts_and_publication_survive_reconnect(self):
        from backend import agent_protocol as ap, agent_edr, agent_ingest_v2
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.sqlite'

            def connect():
                conn = sqlite3.connect(path)
                conn.row_factory = sqlite3.Row
                return conn

            conn = connect()
            try:
                conn.executescript(ap._SCHEMA)
                ap._add_col(conn, 'agent_snapshots', 'generation', 'INTEGER DEFAULT 0')
                ap._add_col(conn, 'agent_snapshots', 'keys_json', "TEXT DEFAULT ''")
                conn.executescript('''CREATE TABLE agent_receipts(agent_id TEXT,event_uuid TEXT,kind TEXT,
                    stream TEXT,seq INTEGER,status TEXT,error TEXT,received_at TEXT,PRIMARY KEY(agent_id,event_uuid));
                    CREATE TABLE agent_streams(agent_id TEXT,stream TEXT,high_seq INTEGER,received INTEGER,
                    rejected INTEGER,updated_at TEXT,PRIMARY KEY(agent_id,stream));''')
                ensure_schema(conn)
                conn.commit()
            finally:
                conn.close()

            def send(index):
                return agent_ingest_v2.ingest_batch('synthetic', [
                    {'uuid': f'synthetic-part-{index}', 'kind': 'snapshot_part', 'seq': 1,
                     'payload': dict(self.meta, part_index=index, fragment=self.parts[index])}])

            def counts():
                conn = connect()
                try:
                    return tuple(conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                                 for table in ('agent_snapshot_parts', 'agent_snapshots', 'agent_receipts'))
                finally:
                    conn.close()

            with patch.object(ap, '_real_connect', side_effect=connect), patch.object(ap, 'ensure_db'), \
                 patch.object(agent_edr, 'ensure'), patch.object(ap, 'mark_telemetry_received'), \
                 patch.object(ap, '_post_snapshot', return_value={'ok': True}) as published, \
                 patch.object(agent_ingest_v2, '_purge_receipts'):
                self.assertEqual(send(0)['acked'], ['synthetic-part-0'])
                self.assertEqual(counts(), (1, 0, 1))
                self.assertEqual(send(0)['duplicates'], 1)
                self.assertEqual(send(1)['acked'], ['synthetic-part-1'])
                self.assertEqual(counts(), (2, 0, 2))
                self.assertEqual(send(2)['acked'], ['synthetic-part-2'])
                self.assertEqual(counts(), (0, 1, 3))
                self.assertEqual(send(2)['duplicates'], 1)
                self.assertEqual(published.call_count, 1)
