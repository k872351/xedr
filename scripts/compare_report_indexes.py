"""Compare already exported JSON report-index lists, without connecting to databases."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.report_index_consistency import compare_report_indexes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sqlite_snapshot", type=Path)
    parser.add_argument("mysql_snapshot", type=Path)
    args = parser.parse_args()
    try:
        snapshots = [json.loads(path.read_text(encoding="utf-8-sig")) for path in (args.sqlite_snapshot, args.mysql_snapshot)]
        if any(not isinstance(rows, list) for rows in snapshots):
            raise ValueError("Each snapshot must be a JSON list")
        result = compare_report_indexes(*snapshots)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"Comparison failed: {exc}")
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["consistent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
