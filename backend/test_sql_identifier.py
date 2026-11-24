import unittest

from backend.sqlite_schema_tools import _add_col, _identifier, _validate_column_ddl
import sqlite3


class SqlIdentifierTests(unittest.TestCase):
    def test_rejects_injection_identifier(self):
        with self.assertRaises(ValueError):
            _identifier('users"; DROP TABLE x;--')

    def test_rejects_bad_ddl(self):
        with self.assertRaises(ValueError):
            _validate_column_ddl("TEXT; DROP TABLE reports")

    def test_add_col_ok(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t(id INTEGER)")
        _add_col(conn, "t", "note", "TEXT DEFAULT ''")
        cols = [r[1] for r in conn.execute("PRAGMA table_info(t)")]
        self.assertIn("note", cols)


if __name__ == "__main__":
    unittest.main()
