"""Measure the local report list against synthetic, disposable metadata."""
from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.report_index_schema import _init_index
from backend.report_index_rows import list_index_rows


def benchmark(count: int = 10000, repeats: int = 30) -> dict:
    conn = sqlite3.connect(":memory:")
    try:
        conn.row_factory = sqlite3.Row
        _init_index(conn)
        conn.executemany(
            "INSERT INTO reports(file, owner_id, collect_time) VALUES(?,?,?)",
            ((f"sample-{i:08d}", f"group-{i % 10}", f"2026-01-{i % 28 + 1:02d}") for i in range(count)),
        )
        conn.commit()
        result = {}
        for name, owner in (("admin", True), ("owner", False)):
            samples = []
            for _ in range(repeats):
                start = time.perf_counter()
                rows = list_index_rows(conn, 50, admin=owner, uid="group-1")
                samples.append((time.perf_counter() - start) * 1000)
                if len(rows) > 50:
                    raise RuntimeError("Page exceeded requested size")
            result[name] = {"median_ms": round(statistics.median(samples), 3),
                            "max_ms": round(max(samples), 3)}
        return {"synthetic_rows": count, "repeats": repeats, "queries": result}
    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=10000, choices=(1000, 10000, 50000))
    parser.add_argument("--repeats", type=int, default=30, choices=(10, 30, 100))
    args = parser.parse_args()
    print(json.dumps(benchmark(args.rows, args.repeats), indent=2))
