"""Read-only report index comparison using the configured stores."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.report_index_consistency import COMPARE_FIELDS, compare_report_indexes


def read_sqlite(path: Path, cap: int):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(reports)")}
        if "file" not in columns:
            raise ValueError("SQLite reports table is missing")
        # Legacy databases can lack optional metadata columns.
        select = ", ".join(["file", *(name if name in columns else f"NULL AS {name}" for name in COMPARE_FIELDS)])
        return conn.execute(f"SELECT {select} FROM reports ORDER BY file LIMIT ?", (cap + 1,)).fetchall()


def read_mysql(cfg: dict, cap: int):
    import pymysql
    with closing(pymysql.connect(
        host=cfg["host"], port=int(cfg["port"]), user=cfg["user"], password=cfg["password"],
        database=cfg["database"], charset=cfg.get("charset") or "utf8mb4",
        cursorclass=pymysql.cursors.DictCursor, autocommit=False,
        connect_timeout=5, read_timeout=10, write_timeout=5,
    )) as conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                cursor.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
                cursor.execute("SHOW COLUMNS FROM reports")
                columns = {row["Field"] for row in cursor.fetchall()}
                if "file" not in columns:
                    raise ValueError("MySQL reports table is missing")
                select = ", ".join(["file", *(name if name in columns else f"NULL AS {name}" for name in COMPARE_FIELDS)])
                cursor.execute(f"SELECT {select} FROM reports ORDER BY file LIMIT %s", (cap + 1,))
                return cursor.fetchall()
        finally:
            conn.rollback()


def check_live(sqlite_path: Path, cfg: dict, cap: int = 100000) -> dict:
    unavailable = []
    if not sqlite_path.is_file():
        unavailable.append("sqlite_index_missing")
    if not cfg.get("enabled"):
        unavailable.append("mysql_disabled")
    if unavailable:
        return {"status": "unavailable", "reasons": unavailable}
    left = read_sqlite(sqlite_path, cap)
    right = read_mysql(cfg, cap)
    if len(left) > cap or len(right) > cap:
        return {"status": "incomplete", "reason": "row_limit_exceeded", "row_limit": cap}
    return {"status": "compared", **compare_report_indexes(left, right),
            "snapshot_note": "Independent snapshots; concurrent writes can produce temporary differences."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-rows", type=int, default=100000, choices=(10000, 50000, 100000))
    args = parser.parse_args()
    from backend import config
    from backend.mysql_db import load_db_config
    try:
        result = check_live(Path(config.REPORTS_DIR) / "index.db", load_db_config(), args.max_rows)
    except Exception as exc:
        # Report the exception type only; connection errors can contain private configuration.
        result = {"status": "error", "type": type(exc).__name__}
    print(json.dumps(result, indent=2))
    return 0 if result.get("consistent") is True else 1 if result["status"] == "compared" else 2


if __name__ == "__main__":
    raise SystemExit(main())
