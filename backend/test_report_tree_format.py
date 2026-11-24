import unittest

from .report_tree_format import _build_files_tree, _parse_mtime_bound


class ReportTreeFormatTests(unittest.TestCase):
    def test_tree_preserves_existing_rows(self):
        tree = _build_files_tree([{"full_path": "folder/b.txt", "size": 5},
                                  {"full_path": "folder/a.txt", "size": 3}])
        self.assertEqual(tree[0]["name"], "folder")
        self.assertEqual([x["name"] for x in tree[0]["children"]], ["a.txt", "b.txt"])
        self.assertNotIn("_map", tree[0])

    def test_date_bounds(self):
        self.assertEqual(_parse_mtime_bound("2026-11-20T12:34"), "2026-11-20 12:34:00")
        self.assertEqual(_parse_mtime_bound("invalid"), "")
