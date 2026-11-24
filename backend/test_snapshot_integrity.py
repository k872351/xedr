"""Snapshot protocol checks against synthetic data and an isolated database."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import agent_protocol as ap


class SnapshotIntegrityTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        path = Path(directory) / 'synthetic.sqlite'

        def connect():
            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            return conn

        self.connect = connect
        conn = connect()
        try:
            conn.executescript(ap._SCHEMA)
            ap._add_col(conn, 'agent_snapshots', 'generation', 'INTEGER DEFAULT 0')
            ap._add_col(conn, 'agent_snapshots', 'keys_json', "TEXT DEFAULT ''")
            conn.commit()
        finally:
            conn.close()
        self.enterContext(patch.object(ap, 'ensure_db'))
        self.enterContext(patch.object(ap, '_connect', side_effect=connect))
        self.enterContext(patch.object(ap, 'mark_telemetry_received'))
        self.enterContext(patch.object(ap, '_post_snapshot', return_value={'ok': True}))
        self.base = {'agent_id': 'synthetic', 'module': 'service'}

    def stored(self):
        conn = self.connect()
        try:
            return tuple(conn.execute('SELECT generation, item_count, payload_json FROM agent_snapshots').fetchone())
        finally:
            conn.close()

    def test_invalid_full_preserves_last_snapshot(self):
        self.assertTrue(ap.upsert_snapshot(dict(self.base, items=[{'name': 'sample'}], keys=['sample'], generation=1))['ok'])
        before = self.stored()
        for invalid in ({'items': None}, {'items': [{}] * 501},
                        {'items': [{}, {}], 'keys': ['same', 'same'], 'generation': 2},
                        {'items': [{}], 'keys': [], 'generation': 2}):
            self.assertFalse(ap.upsert_snapshot(dict(self.base, **invalid))['ok'])
            self.assertEqual(self.stored(), before)

    def test_empty_versioned_snapshot_accepts_first_delta(self):
        self.assertTrue(ap.upsert_snapshot(dict(self.base, items=[], keys=[], generation=1))['ok'])
        delta = dict(self.base, base_generation=1, generation=2, item_count=1,
                     upserts=[{'k': 'sample', 'item': {'name': 'sample'}}], removes=[])
        self.assertFalse(ap.apply_snapshot_delta(dict(delta, upserts=[{'k': 'sample'}]))['ok'])
        self.assertFalse(ap.apply_snapshot_delta(dict(delta, removes=['missing']))['ok'])
        self.assertEqual(self.stored()[:2], (1, 0))
        self.assertTrue(ap.apply_snapshot_delta(delta)['ok'])
        self.assertEqual(self.stored()[:2], (2, 1))

    def test_legacy_full_without_version_is_accepted(self):
        self.assertTrue(ap.upsert_snapshot(dict(self.base, items=[{'name': 'sample'}]))['ok'])
        self.assertEqual(self.stored()[:2], (0, 1))

    def test_extended_software_limit_and_delta(self):
        base = dict(self.base, module='software')
        keys = [f'pkg-{i}' for i in range(1000)]
        items = [{'name': key} for key in keys]
        self.assertTrue(ap.upsert_snapshot(dict(base, items=items, keys=keys, generation=1))['ok'])
        self.assertEqual(self.stored()[:2], (1, 1000))
        self.assertFalse(ap.upsert_snapshot(dict(base, items=items + [{}]))['ok'])
        self.assertEqual(self.stored()[:2], (1, 1000))
        delta = dict(base, base_generation=1, generation=2, item_count=999, upserts=[], removes=[keys[0]])
        self.assertTrue(ap.apply_snapshot_delta(delta)['ok'])
        self.assertEqual(self.stored()[:2], (2, 999))

    def test_paged_software_requires_staging(self):
        keys = [f'pkg-{i}' for i in range(1501)]
        payload = dict(self.base, module='software', items=[{'name': k} for k in keys],
                       keys=keys, generation=1, paged_software=True)
        self.assertFalse(ap.upsert_snapshot(payload)['ok'])
        self.assertTrue(ap.upsert_snapshot(payload, staged=True)['ok'])
        self.assertEqual(self.stored()[:2], (1, 1501))
        invalid = dict(payload, generation=2, items=[{}] * 4001)
        self.assertFalse(ap.upsert_snapshot(invalid, staged=True)['ok'])
        self.assertEqual(self.stored()[:2], (1, 1501))

    def test_paged_assets_require_staging(self):
        for module in ('service', 'hotfix', 'user'):
            keys = [f'fixture-{i}' for i in range(1501)]
            payload = dict(self.base, module=module, items=[{'name': k} for k in keys],
                           keys=keys, generation=1, paged_inventory=True)
            self.assertFalse(ap.upsert_snapshot(payload)['ok'])
            self.assertTrue(ap.upsert_snapshot(payload, staged=True)['ok'])
        self.assertFalse(ap.upsert_snapshot(dict(payload, module='browser'), staged=True)['ok'])
