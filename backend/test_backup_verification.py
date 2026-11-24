import sqlite3
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from scripts.verify_sqlite_backup import verify_backup, verify_connection


class BackupVerificationTests(unittest.TestCase):
    def test_isolated_backup_and_restore(self):
        source = sqlite3.connect(":memory:")
        restored = sqlite3.connect(":memory:")
        self.addCleanup(source.close)
        self.addCleanup(restored.close)
        source.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
        source.execute("CREATE TABLE child (parent_id INTEGER REFERENCES parent(id))")
        source.execute("INSERT INTO parent VALUES (1)")
        source.execute("INSERT INTO child VALUES (1)")
        source.commit()
        source.backup(restored)
        self.assertTrue(verify_connection(restored, full=True))
        self.assertEqual(restored.execute("SELECT parent_id FROM child").fetchall(), [(1,)])
        restored.execute("INSERT INTO child VALUES (2)")
        self.assertFalse(verify_connection(restored, full=True))

    def test_valid_backup(self):
        path = Path(__file__).resolve()
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY)")
        with patch('scripts.verify_sqlite_backup.sqlite3.connect', return_value=conn) as connect:
            self.assertTrue(verify_backup(path))
            connect.assert_called_once_with(path.as_uri() + "?mode=ro", uri=True)

    def test_missing_backup_does_not_create_a_file(self):
        path = Path(__file__).parent / (uuid4().hex + '.sqlite')
        with self.assertRaises(FileNotFoundError):
            verify_backup(path)
        self.assertFalse(path.exists())
