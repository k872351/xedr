"""Read-only SQLite report metadata queries."""
from __future__ import annotations

import sqlite3


def _table_rows(conn: sqlite3.Connection, table: str) -> int:
    try:
        identifier = '"' + table.replace('"', '""') + '"'
        return int(conn.execute(f"SELECT COUNT(1) AS c FROM {identifier}").fetchone()[0] or 0)
    except (sqlite3.Error, TypeError, ValueError, AttributeError):
        return 0


def _has_object(conn: sqlite3.Connection, name: str) -> bool:
    try:
        return bool(conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name=? LIMIT 1", (name,)
        ).fetchone())
    except sqlite3.Error:
        return False
