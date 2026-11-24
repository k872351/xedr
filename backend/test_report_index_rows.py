import sqlite3
import unittest

from backend.report_index_schema import _init_index
from backend.report_index_rows import upsert_index_row, list_index_rows, report_index_view


class ReportIndexRowsTests(unittest.TestCase):
    def test_sqlite_and_mysql_views_have_same_defaults(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT 'report_example.json' AS file, NULL AS hostname").fetchone()
        self.assertEqual(report_index_view(row), report_index_view({"file": "report_example.json", "hostname": ""}))
    def test_read_rows_respect_owner_and_limit(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.row_factory = sqlite3.Row
        _init_index(conn)
        upsert_index_row(conn, {"file": "a", "collect_time": "2026-01-01"}, {"owner_id": "first"}, 1)
        upsert_index_row(conn, {"file": "b", "collect_time": "2026-01-02"}, {"owner_id": "second"}, 2)
        self.assertEqual([row["file"] for row in list_index_rows(conn, 10, admin=False, uid="first")], ["a"])
        self.assertEqual([row["file"] for row in list_index_rows(conn, 1, admin=True)], ["b"])

    def test_owner_id_is_authoritative(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.row_factory = sqlite3.Row
        _init_index(conn)
        upsert_index_row(conn, {"file": "current"}, {"owner_id": "current-id", "owner_username": "shared"}, 1)
        upsert_index_row(conn, {"file": "legacy"}, {"owner_username": "shared"}, 2)
        rows = list_index_rows(conn, 10, admin=False, uid="another-id", uname="shared")
        self.assertEqual([row["file"] for row in rows], ["legacy"])
    def test_upsert_preserves_existing_metadata(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        _init_index(conn)
        upsert_index_row(conn, {"file": "example", "os_family": "Windows", "os": "Windows 11"}, {"owner_id": "user", "owner_username": "example"}, 1)
        upsert_index_row(conn, {"file": "example", "files": 3}, {}, 2)
        row = conn.execute("SELECT file,files,owner_id,os_family,os,updated_at FROM reports").fetchone()
        self.assertEqual(row, ("example", 3, "user", "windows", "Windows 11", 2))
