"""Regression tests using an isolated, in-memory receipt store."""
import sqlite3
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from backend import agent_edr, agent_ingest_v2 as ingest


class ReceiptTests(unittest.TestCase):
    def test_replayed_rejection_remains_rejected(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.executescript("""
            CREATE TABLE agent_receipts (
                agent_id TEXT, event_uuid TEXT, kind TEXT, stream TEXT,
                seq INTEGER, status TEXT, error TEXT, received_at TEXT,
                PRIMARY KEY(agent_id,event_uuid));
            CREATE TABLE agent_streams (
                agent_id TEXT, stream TEXT, high_seq INTEGER, received INTEGER,
                rejected INTEGER, updated_at TEXT, PRIMARY KEY(agent_id,stream));
        """)

        @contextmanager
        def transaction():
            with conn:
                yield conn

        events = [
            {"uuid": "event-good", "kind": "event", "seq": 1, "payload": {}},
            {"uuid": "event-reject", "kind": "event", "seq": 2, "payload": {}},
        ]
        with patch.object(ingest.ap, "ensure_db"), patch.object(agent_edr, "ensure"), \
             patch.object(ingest.ap, "batch_tx", transaction), \
             patch.object(ingest, "_apply", side_effect=[{"ok": True}, {"ok": False, "error": "invalid"}]) as apply, \
             patch.object(ingest, "_purge_receipts"):
            first = ingest.ingest_batch("test-agent", events)
            replay = ingest.ingest_batch("test-agent", events)
        self.assertEqual(first["acked"], ["event-good"])
        self.assertEqual(first["rejected"], [{"uuid": "event-reject", "error": "invalid"}])
        self.assertEqual(replay["acked"], first["acked"])
        self.assertEqual(replay["rejected"], first["rejected"])
        self.assertEqual(replay["duplicates"], 2)
        self.assertEqual(apply.call_count, 2)
        self.assertEqual(conn.execute("SELECT received,rejected FROM agent_streams").fetchone(), (1, 1))


if __name__ == "__main__":
    unittest.main()
