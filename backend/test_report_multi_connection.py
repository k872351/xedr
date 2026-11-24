import sqlite3
import unittest
from uuid import uuid4

from backend.report_index_rows import upsert_index_row
from backend.report_index_schema import _init_index


class ReportMultiConnectionTests(unittest.TestCase):
    def test_committed_rows_visible_and_failed_update_rolled_back(self):
        uri = "file:" + uuid4().hex + "?mode=memory&cache=shared"
        first = sqlite3.connect(uri, uri=True)
        second = sqlite3.connect(uri, uri=True)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        _init_index(first)
        _init_index(second)
        with first:
            upsert_index_row(first, {"file": "example", "files": 2}, {}, 1)
        self.assertEqual(second.execute("SELECT files FROM reports").fetchone()[0], 2)
        with self.assertRaises(RuntimeError):
            with second:
                upsert_index_row(second, {"file": "example", "files": 9}, {}, 2)
                raise RuntimeError("simulated interruption")
        self.assertEqual(first.execute("SELECT files FROM reports").fetchone()[0], 2)
