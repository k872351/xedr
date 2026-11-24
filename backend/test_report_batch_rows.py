import sqlite3
import unittest

from backend.report_batch_rows import _insert_file_rows, _insert_event_log_rows
from backend.report_schema import _init_schema


class ReportBatchRowsTests(unittest.TestCase):
    def test_generator_and_legacy_fields(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        _init_schema(conn)
        self.assertEqual(_insert_file_rows(conn, iter([{"full_path": "example.txt", "size": "invalid"}, None])), 1)
        self.assertIsNone(conn.execute("SELECT size FROM files").fetchone()[0])
        self.assertEqual(_insert_event_log_rows(conn, iter([{"event_id": 2**64, "message": "example"}])), 1)
        self.assertEqual(conn.execute("SELECT event_id FROM event_logs").fetchone()[0], 0)

    def test_cancelled_batch_preserves_caller_rollback(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        _init_schema(conn)
        attempts = iter([False, True])
        with self.assertRaises(InterruptedError):
            with conn:
                _insert_event_log_rows(conn, ({"event_id": i} for i in range(2001)), lambda: next(attempts))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM event_logs").fetchone()[0], 0)
