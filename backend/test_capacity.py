import stat
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from backend.capacity import _dir_size, _report_counts, _cache_dir_size


class CapacityTests(unittest.TestCase):
    def test_cache_is_bounded_and_expires(self):
        with patch("backend.capacity._DIR_SIZE_CACHE", {}) as cache, \
             patch("backend.capacity._DIR_SIZE_CACHE_MAX", 2), \
             patch("backend.capacity.time.monotonic", side_effect=[1, 2, 3, 100]):
            for key in ("a", "b", "c", "d"):
                _cache_dir_size((key, 1), {"bytes": 0})
                self.assertLessEqual(len(cache), 2)
            self.assertEqual(list(cache), [("d", 1)])
    def test_report_count_status(self):
        with patch("backend.capacity.P.iter_report_ids", return_value=[]):
            self.assertEqual(_report_counts()["status"], "complete")
        with patch("backend.capacity.P.iter_report_ids", side_effect=OSError("unavailable")):
            self.assertEqual(_report_counts()["status"], "error")
        with patch("backend.capacity.P.iter_report_ids", return_value=list(range(5000))):
            self.assertEqual(_report_counts()["status"], "partial")

    def test_exact_limit_and_partial_scan(self):
        folder = MagicMock()
        folder.exists.return_value = True
        item = MagicMock()
        item.stat.return_value = SimpleNamespace(st_mode=stat.S_IFREG, st_size=10)
        broken = MagicMock()
        broken.stat.side_effect = OSError("unreadable")
        with patch("backend.capacity._DIR_SIZE_CACHE", {}):
            folder.rglob.return_value = [item]
            exact = _dir_size(folder, limit_files=1)
            self.assertFalse(exact["truncated"])
            folder.rglob.return_value = [item, broken, item]
            complete = _dir_size(folder, limit_files=2)
            self.assertEqual(complete["bytes"], 20)
            self.assertEqual(complete["unreadable"], 1)
            self.assertFalse(complete["truncated"])
            folder.rglob.return_value = [item] * 4
            partial = _dir_size(folder, limit_files=3)
            self.assertEqual(partial["bytes"], 30)
            self.assertTrue(partial["truncated"])
