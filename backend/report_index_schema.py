"""SQLite report index schema and transactional migrations."""
import re
import sqlite3
from .sqlite_schema_tools import _identifier, _validate_column_ddl, schema_migration

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_INDEX_EXPR = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\s+(?:ASC|DESC))?(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*(?:\s+(?:ASC|DESC))?)*$"
)

INDEX_SCHEMA_VERSION = 2
_INDEX_COLUMNS = {
    "db_path": "TEXT", "hostname": "TEXT", "collect_time": "TEXT", "ip": "TEXT",
    "issues": "INTEGER DEFAULT 0", "raw_issues": "INTEGER DEFAULT 0",
    "analyzed": "INTEGER DEFAULT 0", "processes": "INTEGER DEFAULT 0",
    "services": "INTEGER DEFAULT 0", "files": "INTEGER DEFAULT 0", "updated_at": "REAL",
    "owner_id": "TEXT DEFAULT ''", "owner_username": "TEXT DEFAULT ''",
    "os_family": "TEXT DEFAULT ''", "os": "TEXT DEFAULT ''",
}
_INDEX_DEFINITIONS = {
    "idx_reports_host": "hostname",
    "idx_reports_owner": "owner_id",
    "idx_reports_time_file": "collect_time DESC, file DESC",
    "idx_reports_owner_time": "owner_id, collect_time DESC, file DESC",
    "idx_reports_username_time": "owner_username, collect_time DESC, file DESC",
}


def _init_index(conn: sqlite3.Connection) -> None:
    if int(conn.execute("PRAGMA user_version").fetchone()[0]) >= INDEX_SCHEMA_VERSION:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(reports)")}
        indexes = {row[1] for row in conn.execute("PRAGMA index_list(reports)")}
        if ({"file", *_INDEX_COLUMNS}.issubset(existing)
                and _INDEX_DEFINITIONS.keys() <= indexes):
            return
    with schema_migration(conn):
        _apply_index_schema(conn)
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version < INDEX_SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version={INDEX_SCHEMA_VERSION}")


def _apply_index_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            file TEXT PRIMARY KEY,
            db_path TEXT,
            hostname TEXT,
            collect_time TEXT,
            ip TEXT,
            issues INTEGER DEFAULT 0,
            raw_issues INTEGER DEFAULT 0,
            analyzed INTEGER DEFAULT 0,
            processes INTEGER DEFAULT 0,
            services INTEGER DEFAULT 0,
            files INTEGER DEFAULT 0,
            updated_at REAL,
            owner_id TEXT DEFAULT '',
            owner_username TEXT DEFAULT ''
        )
        """
    )
    # 旧库补列（必须先于依赖新列的 INDEX）
    cols = {r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()}
    if "file" not in cols:
        raise sqlite3.OperationalError("reports table is missing its report identifier")
    for name, definition in _INDEX_COLUMNS.items():
        if name not in cols:
            if not _IDENT.fullmatch(name):
                raise ValueError(f"invalid column name: {name}")
            safe_ddl = _validate_column_ddl(definition)
            conn.execute(f"ALTER TABLE reports ADD COLUMN {_identifier(name)} {safe_ddl}")
    for name, columns in _INDEX_DEFINITIONS.items():
        if not _IDENT.fullmatch(name) or not _INDEX_EXPR.fullmatch(columns):
            raise ValueError(f"invalid index definition: {name} ({columns})")
        conn.execute(f"CREATE INDEX IF NOT EXISTS {_identifier(name)} ON reports({columns})")


