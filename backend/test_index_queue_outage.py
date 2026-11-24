"""Synthetic index outage and recovery; no deployed database or network."""
import sqlite3
import unittest
from unittest.mock import patch

from backend import es_event_queue as queue


class _Connection(sqlite3.Connection):
    def close(self):
        pass


class IndexQueueOutageTests(unittest.TestCase):
    def test_batch_recovery_preserves_identity(self):
        conn = sqlite3.connect(':memory:', factory=_Connection)
        self.addCleanup(sqlite3.Connection.close, conn)
        conn.row_factory = sqlite3.Row
        queue.ensure_transactional_schema(conn)
        conn.commit()
        with conn:
            for i in range(100):
                queue.enqueue_timeline_event(conn=conn, source_id=f'fixture:{i}', agent_id='fixture',
                    etype='fixture', summary='synthetic record', detail={}, ts='fixture')
        self.assertEqual(conn.execute('SELECT COUNT(*) FROM es_queue').fetchone()[0], 100)
        attempted = []
        def unavailable(items):
            attempted.extend(key for key, _ in items)
            raise ConnectionError('synthetic index outage')
        with patch.object(queue, '_connect', return_value=conn), \
             patch('backend.elastic_detection_es.index_timeline_batch', side_effect=unavailable):
            self.assertTrue(queue._drain_once(limit=100))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM es_queue WHERE status='pending' AND attempts=1").fetchone()[0], 100)
            self.assertFalse(queue._drain_once(limit=100))
        # Advance only the fixture's retry eligibility; never alter live data.
        with conn:
            conn.execute('UPDATE es_queue SET updated_at=0')
        recovered = []
        def available(items):
            recovered.extend(key for key, _ in items)
            return {key: True for key, _ in items}
        with patch.object(queue, '_connect', return_value=conn), \
             patch('backend.elastic_detection_es.index_timeline_batch', side_effect=available):
            self.assertTrue(queue._drain_once(limit=100))
            self.assertFalse(queue._drain_once(limit=100))
        self.assertEqual(set(attempted), set(recovered))
        self.assertEqual(len(recovered), 100)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM es_queue WHERE status='done' AND attempts=2").fetchone()[0], 100)
