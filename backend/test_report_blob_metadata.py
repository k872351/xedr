import sqlite3
import unittest
from contextlib import closing

from .report_blob_metadata import _count_blob_fast, _nested_artifact_count, _load_one_blob, _conn_os_family


class ReportBlobMetadataTests(unittest.TestCase):
    def test_nested_count(self):
        self.assertEqual(_nested_artifact_count({"rows": [1, 2], "title": "sample", "empty": ""}), 3)

    def test_metadata_reads(self):
        with closing(sqlite3.connect(":memory:")) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("CREATE TABLE blobs (name TEXT, data TEXT)")
            conn.execute("CREATE TABLE meta (key TEXT, value TEXT)")
            conn.execute("INSERT INTO blobs VALUES (?, ?)", ("sample", '[1,2]'))
            conn.execute("INSERT INTO meta VALUES (?, ?)", ("os_family", "Windows"))
            self.assertEqual(_load_one_blob(conn, "sample"), [1, 2])
            self.assertEqual(_conn_os_family(conn), "windows")
            self.assertEqual(_count_blob_fast(conn, "sample", {"count_sample": "2"}), 2)
