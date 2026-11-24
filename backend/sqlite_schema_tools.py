"""Small SQLite schema helpers for trusted application migrations."""
import re
import sqlite3
from contextlib import contextmanager

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DDL_TYPE = re.compile(
    r"^(TEXT|INTEGER|REAL|BLOB|NUMERIC)"
    r"(?:\s+DEFAULT\s+(?:NULL|0|1|''|\"\"|'[^']{0,64}'|\"[^\"]{0,64}\"|-?\d+(?:\.\d+)?))?$"
    r"(?:\s+NOT\s+NULL)?$",
    re.IGNORECASE,
)


def _identifier(name: str) -> str:
    raw = str(name or "")
    if not _IDENT.fullmatch(raw):
        raise ValueError(f"invalid SQL identifier: {raw!r}")
    return '"' + raw + '"'


def _validate_column_ddl(ddl: str) -> str:
    text = " ".join(str(ddl or "").split())
    if not text or len(text) > 120 or not _DDL_TYPE.fullmatch(text):
        raise ValueError(f"invalid column DDL: {ddl!r}")
    return text


def _col_exists(conn: sqlite3.Connection, table: str, col: str) -> bool:
    return any(row[1] == col for row in conn.execute(f"PRAGMA table_info({_identifier(table)})"))


def _add_col(conn: sqlite3.Connection, table: str, col: str, ddl: str) -> None:
    if not _col_exists(conn, table, col):
        safe_ddl = _validate_column_ddl(ddl)
        conn.execute(f"ALTER TABLE {_identifier(table)} ADD COLUMN {_identifier(col)} {safe_ddl}")


@contextmanager
def schema_migration(conn: sqlite3.Connection):
    """Serialize schema changes across SQLite connections while preserving caller transactions."""
    nested = conn.in_transaction
    if nested:
        conn.execute("SAVEPOINT application_schema_migration")
    else:
        conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        if nested:
            conn.execute("RELEASE SAVEPOINT application_schema_migration")
        else:
            conn.commit()
    except BaseException:
        if nested:
            conn.execute("ROLLBACK TO SAVEPOINT application_schema_migration")
            conn.execute("RELEASE SAVEPOINT application_schema_migration")
        else:
            conn.rollback()
        raise
