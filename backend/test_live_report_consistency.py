import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.check_live_report_consistency import check_live


class LiveReportConsistencyTests(unittest.TestCase):
    def test_disabled_store_is_not_queried(self):
        with patch("scripts.check_live_report_consistency.Path.is_file", return_value=False), \
             patch("scripts.check_live_report_consistency.read_mysql") as mysql:
            result = check_live(Path("example.db"), {"enabled": False})
            self.assertEqual(result["status"], "unavailable")
            mysql.assert_not_called()

    def test_incomplete_snapshot_cannot_claim_consistency(self):
        with patch("scripts.check_live_report_consistency.Path.is_file", return_value=True), \
             patch("scripts.check_live_report_consistency.read_sqlite", return_value=[{"file": "a"}, {"file": "b"}]), \
             patch("scripts.check_live_report_consistency.read_mysql", return_value=[]):
            self.assertEqual(check_live(Path("example.db"), {"enabled": True}, 1)["status"], "incomplete")
