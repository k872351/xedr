import unittest
import sqlite3

from backend.report_index_consistency import compare_report_indexes


class ReportIndexConsistencyTests(unittest.TestCase):
    def test_sqlite_row_and_invalid_count(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT 'example' AS file, 1 AS files").fetchone()
        self.assertTrue(compare_report_indexes([row], [{"file": "example", "files": "1"}])["consistent"])
        with self.assertRaises(ValueError):
            compare_report_indexes([{"file": "example", "files": 1.5}], [])

    def test_legacy_types(self):
        left = [{"file": "a", "files": "3", "analyzed": 1}]
        right = [{"file": "a", "files": 3, "analyzed": True, "os": ""}]
        self.assertTrue(compare_report_indexes(left, right)["consistent"])

    def test_missing_and_changed(self):
        left = [{"file": "a", "files": 3}, {"file": "b"}]
        right = [{"file": "a", "files": 4}, {"file": "c"}]
        result = compare_report_indexes(left, right)
        self.assertEqual((result["sqlite_only"], result["mysql_only"], result["different"]), (1, 1, 1))
        self.assertFalse(result["consistent"])
        self.assertEqual(result["field_mismatches"], {"files": 1})

    def test_console_export_time_alias(self):
        left = [{"file": "example", "collect_time": "2026-01-01"}]
        right = [{"file": "example", "time": "2026-01-01"}]
        self.assertTrue(compare_report_indexes(left, right)["consistent"])
        right[0]["time"] = "2026-01-02"
        self.assertEqual(compare_report_indexes(left, right)["field_mismatches"], {"collect_time": 1})

    def test_duplicate_identifier_rejected(self):
        with self.assertRaises(ValueError):
            compare_report_indexes([{"file": "a"}, {"file": "a"}], [])
