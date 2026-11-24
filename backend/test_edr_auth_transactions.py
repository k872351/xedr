import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend import edr_auth


class AccountTransactionTests(unittest.TestCase):
    def test_unavailable_wal_closes_connection(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = ("delete",)
        with patch.object(edr_auth, "db_path", return_value=Path("fixture.db")), \
             patch.object(edr_auth.sqlite3, "connect", return_value=conn):
            with self.assertRaisesRegex(sqlite3.OperationalError, "required WAL"):
                edr_auth._connect()
        conn.close.assert_called_once()

    def test_account_mutations_preserve_admin_and_revoke_sessions(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as tmp:
            with patch.object(edr_auth, "db_path", return_value=Path(tmp) / "accounts.db"), \
                 patch.object(edr_auth, "_touch_at", {}):
                a = edr_auth.create_user("fixture-admin", "FixturePass123", role="admin")
                b = edr_auth.create_user("fixture-other", "FixturePass456", role="admin")
                token = edr_auth.login("fixture-other", "FixturePass456")["token"]
                edr_auth.update_user(b["id"], enabled=False)
                self.assertIsNone(edr_auth.me(token))
                with self.assertRaises(ValueError):
                    edr_auth.delete_user(a["id"])
                with self.assertRaises(ValueError):
                    edr_auth.update_user(a["id"], role="readonly")
                rows = {row["id"]: row for row in edr_auth.list_users()}
                self.assertEqual(rows[a["id"]]["role"], "admin")
                self.assertTrue(rows[a["id"]]["enabled"])
                self.assertFalse(rows[b["id"]]["enabled"])
                token = edr_auth.login("fixture-admin", "FixturePass123")["token"]
                edr_auth.reset_password(a["id"], "FixtureNew123")
                self.assertIsNone(edr_auth.me(token))
                self.assertTrue(edr_auth.login("fixture-admin", "FixtureNew123")["user"]["must_change"])
                conn = edr_auth._connect()
                try:
                    self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                finally:
                    conn.close()
