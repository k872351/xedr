import sqlite3
import unittest

from backend.db_store import INDEX_SCHEMA_VERSION, REPORT_SCHEMA_VERSION, _init_index, _init_schema, _schema_conn_key, _schema_cache_valid


class ReportSchemaTests(unittest.TestCase):
    def test_current_report_schema_avoids_ddl(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        _init_schema(conn)
        statements = []
        conn.set_trace_callback(statements.append)
        _init_schema(conn)
        self.assertFalse(any(statement.startswith(("CREATE", "ALTER", "BEGIN IMMEDIATE")) for statement in statements))
    def test_schema_version_does_not_mask_missing_table(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        _init_schema(conn)
        self.assertTrue(_schema_cache_valid(conn))
        conn.execute("DROP TABLE entity_lists")
        self.assertFalse(_schema_cache_valid(conn))
        _init_schema(conn)
        self.assertTrue(_schema_cache_valid(conn))
    def test_index_schema_rollback_and_repeat(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE reports (file TEXT PRIMARY KEY, hostname TEXT)")
        conn.execute("INSERT INTO reports VALUES ('example', 'host')")
        _init_index(conn)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], INDEX_SCHEMA_VERSION)
        conn.rollback()
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 0)
        _init_index(conn)
        _init_index(conn)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(reports)")}
        self.assertTrue({"owner_id", "owner_username", "os_family", "os"}.issubset(cols))

    def test_index_current_version_avoids_ddl(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        _init_index(conn)
        statements = []
        conn.set_trace_callback(statements.append)
        _init_index(conn)
        self.assertFalse(any(statement.startswith("CREATE") or statement.startswith("ALTER") for statement in statements))

    def test_index_migration_adds_sort_indexes(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE reports (file TEXT PRIMARY KEY, hostname TEXT)")
        conn.execute("INSERT INTO reports VALUES ('example', 'host')")
        conn.commit()
        conn.execute("PRAGMA user_version=1")
        _init_index(conn)
        self.assertEqual(conn.execute("SELECT hostname FROM reports").fetchone()[0], "host")
        plan = conn.execute("EXPLAIN QUERY PLAN SELECT * FROM reports ORDER BY collect_time DESC, file DESC LIMIT 10").fetchall()
        self.assertTrue(any("idx_reports_time_file" in str(row) for row in plan))
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], INDEX_SCHEMA_VERSION)

    def test_legacy_upgrade_is_idempotent(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE files (full_path TEXT PRIMARY KEY, name TEXT, path TEXT, ext TEXT, size INTEGER)")
        conn.execute("INSERT INTO files VALUES ('example', 'example', '', '', 3)")
        _init_schema(conn)
        _init_schema(conn)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(files)")}
        self.assertTrue({"sha256", "content", "mtime"}.issubset(cols))
        self.assertEqual(conn.execute("SELECT size FROM files").fetchone()[0], 3)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], REPORT_SCHEMA_VERSION)

    def test_migration_respects_outer_transaction(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE files (full_path TEXT PRIMARY KEY, name TEXT, path TEXT, ext TEXT, size INTEGER)")
        conn.execute("INSERT INTO files VALUES ('example', 'example', '', '', 3)")
        _init_schema(conn)
        conn.rollback()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM files").fetchone()[0], 0)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 0)
        self.assertNotIn("content", {row[1] for row in conn.execute("PRAGMA table_info(files)")})

    def test_separate_memory_databases(self):
        first = sqlite3.connect(":memory:")
        second = sqlite3.connect(":memory:")
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        self.assertNotEqual(_schema_conn_key(first), _schema_conn_key(second))

    def test_failed_migration_does_not_leave_partial_schema(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE files (full_path TEXT PRIMARY KEY)")
        with self.assertRaises(sqlite3.OperationalError):
            _init_schema(conn)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 0)
        self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='meta'").fetchone())
