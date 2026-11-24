"""审批 dispatching 中断恢复。"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import response_approval as ra


class ApprovalRecoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "t.db"

        def _connect():
            conn = sqlite3.connect(str(self.db))
            conn.row_factory = sqlite3.Row
            conn.executescript(ra._SCHEMA)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS agents(
                    agent_id TEXT PRIMARY KEY, hostname TEXT, last_seen TEXT,
                    last_heartbeat_at TEXT, heartbeat_period_sec INTEGER, revoked INTEGER DEFAULT 0)"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS agent_audit(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT, action TEXT, detail TEXT, actor TEXT, created_at TEXT)"""
            )
            return conn

        self._connect_patch = patch.object(ra, "_connect", side_effect=_connect)
        self._audit_patch = patch("backend.agent_edr._audit")
        self._connect_patch.start()
        self._audit_patch.start()

    def tearDown(self):
        self._connect_patch.stop()
        self._audit_patch.stop()
        self.tmp.cleanup()

    def test_recover_old_dispatching(self):
        conn = ra._connect()
        conn.execute(
            """INSERT INTO response_approvals(id, agent_id, action, status, updated_at, created_at)
               VALUES('a1','ag1','kill_process','dispatching','2000-01-01T00:00:00','2000-01-01T00:00:00')"""
        )
        conn.execute(
            """INSERT INTO response_approvals(id, agent_id, action, status, updated_at, created_at)
               VALUES('a2','ag1','kill_process','pending','2000-01-01T00:00:00','2000-01-01T00:00:00')"""
        )
        conn.commit()
        conn.close()

        out = ra.recover_stuck_approvals(older_than_sec=30)
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["recovered"], ["a1"])

        conn = ra._connect()
        row = conn.execute("SELECT status FROM response_approvals WHERE id='a1'").fetchone()
        self.assertEqual(row["status"], "pending")
        row2 = conn.execute("SELECT status FROM response_approvals WHERE id='a2'").fetchone()
        self.assertEqual(row2["status"], "pending")
        conn.close()

    def test_skip_fresh_dispatching(self):
        now = ra._now()
        conn = ra._connect()
        conn.execute(
            """INSERT INTO response_approvals(id, agent_id, action, status, updated_at, created_at)
               VALUES('fresh','ag1','kill_process','dispatching',?,?)""",
            (now, now),
        )
        conn.commit()
        conn.close()
        out = ra.recover_stuck_approvals(older_than_sec=120)
        self.assertEqual(out["count"], 0)


if __name__ == "__main__":
    unittest.main()
