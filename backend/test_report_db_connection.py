import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.report_db_connection import _connect


class ReportDbConnectionTests(unittest.TestCase):
    def test_unavailable_wal_is_not_silently_accepted(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = ("delete",)
        with patch("backend.report_db_connection.sqlite3.connect", return_value=conn):
            with self.assertRaisesRegex(sqlite3.OperationalError, "required WAL"):
                _connect(Path("example.db"))
        conn.close.assert_called_once()

    def test_file_database_reopens_and_two_connections_share_committed_state(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as tmp:
            path = Path(tmp) / "report-fixture.db"
            first = _connect(path)
            second = None
            try:
                second = _connect(path)
                self.assertEqual(first.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                self.assertEqual(second.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                with first:
                    first.execute("CREATE TABLE fixture(value INTEGER)")
                    first.execute("INSERT INTO fixture VALUES(1)")
                self.assertEqual(second.execute("SELECT value FROM fixture").fetchone()[0], 1)
                with self.assertRaises(RuntimeError):
                    with second:
                        second.execute("UPDATE fixture SET value=2")
                        raise RuntimeError("synthetic interruption")
            finally:
                if second is not None:
                    second.close()
                first.close()
            reopened = _connect(path)
            try:
                self.assertEqual(reopened.execute("SELECT value FROM fixture").fetchone()[0], 1)
                self.assertEqual(reopened.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            finally:
                reopened.close()

    def test_existing_wal_avoids_reconfiguration(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = ("wal",)
        with patch("backend.report_db_connection.sqlite3.connect", return_value=conn):
            self.assertIs(_connect(Path("example.db")), conn)
        self.assertNotIn("PRAGMA journal_mode=WAL", [call.args[0] for call in conn.execute.call_args_list])

    def test_failed_setup_closes_connection(self):
        conn = MagicMock()
        conn.execute.side_effect = sqlite3.OperationalError("unavailable")
        with patch("backend.report_db_connection.sqlite3.connect", return_value=conn):
            with self.assertRaises(sqlite3.OperationalError):
                _connect(Path("example.db"))
        conn.close.assert_called_once()
