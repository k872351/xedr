import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.agent_protocol import _mig_014_approval_command_guard


class ApprovalCommandGuardTests(unittest.TestCase):
    def test_uncommitted_fixture_is_rolled_back_and_duplicate_guard_survives_reopen(self):
        # Only synthetic database rows are used; no terminal actions are dispatched.
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as tmp:
            path = Path(tmp) / 'approval-fixture.db'
            conn = sqlite3.connect(path)
            try:
                conn.execute('CREATE TABLE agent_commands(id TEXT PRIMARY KEY, idempotency_key TEXT, status TEXT)')
                _mig_014_approval_command_guard(conn)
                conn.execute('INSERT INTO agent_commands VALUES(?,?,?)', ('fixture-committed', 'approval:fixture', 'pending'))
                conn.commit()
                conn.execute('UPDATE agent_commands SET status=? WHERE id=?', ('failed', 'fixture-committed'))
            finally:
                conn.close()  # deliberately leave the status update uncommitted
            reopened = sqlite3.connect(path)
            try:
                self.assertEqual(reopened.execute('SELECT status FROM agent_commands WHERE id=?', ('fixture-committed',)).fetchone(), ('pending',))
                with self.assertRaises(sqlite3.IntegrityError):
                    reopened.execute('INSERT INTO agent_commands VALUES(?,?,?)', ('fixture-repeat', 'approval:fixture', 'pending'))
                self.assertEqual(reopened.execute('PRAGMA integrity_check').fetchone(), ('ok',))
            finally:
                reopened.close()

    def test_existing_duplicates_preserved_but_new_duplicates_blocked(self):
        conn = sqlite3.connect(':memory:')
        self.addCleanup(conn.close)
        conn.execute('CREATE TABLE agent_commands(id TEXT PRIMARY KEY, idempotency_key TEXT, status TEXT)')
        conn.executemany('INSERT INTO agent_commands VALUES(?,?,?)', [
            ('fixture-old-one', 'approval:fixture', 'failed'), ('fixture-old-two', 'approval:fixture', 'expired')])
        _mig_014_approval_command_guard(conn)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute('INSERT INTO agent_commands VALUES(?,?,?)', ('fixture-new', 'approval:fixture', 'pending'))
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute('UPDATE agent_commands SET idempotency_key=? WHERE id=?', ('other', 'fixture-old-one'))
        self.assertEqual(conn.execute('SELECT COUNT(*) FROM agent_commands').fetchone()[0], 2)
        conn.execute('INSERT INTO agent_commands VALUES(?,?,?)', ('fixture-distinct', 'approval:distinct', 'pending'))
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute('INSERT INTO agent_commands VALUES(?,?,?)', ('fixture-distinct-repeat', 'approval:distinct', 'pending'))
