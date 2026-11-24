import sqlite3
import unittest
from contextlib import closing

from .report_directory_index import _ensure_files_path_norm_index, _ensure_files_hash_indexes


class ReportDirectoryIndexTests(unittest.TestCase):
    def test_probe_does_not_create_index(self):
        with closing(sqlite3.connect(":memory:")) as conn:
            conn.execute("CREATE TABLE files (full_path TEXT, md5 TEXT, sha1 TEXT, sha256 TEXT)")
            self.assertFalse(_ensure_files_path_norm_index(conn, create=False))
            self.assertTrue(_ensure_files_path_norm_index(conn))
            self.assertTrue(_ensure_files_path_norm_index(conn, create=False))
            _ensure_files_hash_indexes(conn)
            indexes = {row[1] for row in conn.execute("PRAGMA index_list(files)")}
            self.assertTrue({"idx_files_md5", "idx_files_sha1", "idx_files_sha256"} <= indexes)
