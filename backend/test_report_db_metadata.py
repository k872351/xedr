import sqlite3
import unittest
from contextlib import closing

from .report_db_metadata import _has_object, _table_rows


class MetadataTests(unittest.TestCase):
    def test_row_count_and_object(self):
        with closing(sqlite3.connect(":memory:")) as conn:
            conn.execute('CREATE TABLE "report rows" (id INTEGER)')
            conn.execute('INSERT INTO "report rows" VALUES (1), (2)')
            self.assertTrue(_has_object(conn, "report rows"))
            self.assertEqual(_table_rows(conn, "report rows"), 2)
            self.assertFalse(_has_object(conn, "missing"))
            self.assertEqual(_table_rows(conn, "missing"), 0)
