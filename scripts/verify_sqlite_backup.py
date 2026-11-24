"""Read-only verification of an explicitly supplied SQLite backup file."""
from __future__ import annotations

import argparse
import sqlite3
from contextlib import closing
from pathlib import Path


def verify_connection(conn: sqlite3.Connection, *, full: bool = False) -> bool:
    pragma = "PRAGMA integrity_check" if full else "PRAGMA quick_check"
    if conn.execute(pragma).fetchall() != [("ok",)]:
        return False
    return not full or conn.execute("PRAGMA foreign_key_check").fetchone() is None


def verify_backup(path: Path, *, full: bool = False) -> bool:
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError("Expected an existing backup file")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as conn:
        return verify_connection(conn, full=full)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="A detached SQLite backup file")
    parser.add_argument("--full", action="store_true", help="Also check full integrity and foreign keys")
    args = parser.parse_args()
    try:
        ok = verify_backup(args.backup, full=args.full)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"Verification failed: {exc}")
        return 1
    print(("SQLite full check: " if args.full else "SQLite quick_check: ") + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
