import sqlite3
import unittest
from datetime import datetime

from backend.timeline_value_format import _parse_detail, _timeline_int, _parse_ts_any
from backend.rule_metadata import _enrich_rule_item
from backend.sqlite_schema_tools import _add_col, _col_exists


class SharedFormatsTests(unittest.TestCase):
    def test_timeline_legacy_types(self):
        self.assertEqual(_parse_detail('{"value": 1}'), {"value": 1})
        self.assertEqual(_parse_detail("[]"), {})
        self.assertEqual(_timeline_int("wrong"), 0)
        self.assertEqual(_parse_ts_any("2026-01-01T12:00:00Z"), datetime(2026, 1, 1, 12))

    def test_rule_metadata_copy(self):
        source = {"id": "elastic-example"}
        self.assertEqual(_enrich_rule_item(source)["source"], "elastic")
        self.assertNotIn("source", source)

    def test_schema_column_repeat(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute('CREATE TABLE "example table" (id TEXT)')
        _add_col(conn, "example table", "example column", "TEXT")
        _add_col(conn, "example table", "example column", "TEXT")
        self.assertTrue(_col_exists(conn, "example table", "example column"))
