import unittest
from unittest.mock import patch

from backend.db_store import list_index


class ReportIndexAuthorityTests(unittest.TestCase):
    def test_empty_mysql_result_does_not_fall_back(self):
        with patch("backend.mysql_db.mysql_ready", return_value=True), \
             patch("backend.mysql_store.list_reports_mysql", return_value=[]), \
             patch("backend.db_store._connect") as connect:
            self.assertEqual(list_index(), [])
            connect.assert_not_called()

    def test_mysql_read_does_not_prune(self):
        rows = [{"file": "example"}]
        with patch("backend.mysql_db.mysql_ready", return_value=True), \
             patch("backend.mysql_store.list_reports_mysql", return_value=rows), \
             patch("backend.db_store.prune_stale_index") as prune, \
             patch("backend.mysql_store.delete_report_files") as delete:
            self.assertEqual(list_index(), rows)
            prune.assert_not_called()
            delete.assert_not_called()
