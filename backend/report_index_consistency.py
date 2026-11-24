"""Compare report index metadata from two read-only snapshots."""
from collections.abc import Iterable, Mapping


COUNT_FIELDS = ("issues", "raw_issues", "analyzed", "processes", "services", "files")
TEXT_FIELDS = ("hostname", "collect_time", "ip", "owner_id", "owner_username", "os_family", "os")
COMPARE_FIELDS = COUNT_FIELDS + TEXT_FIELDS


def _count_value(value) -> int:
    if value is None or value == "":
        return 0
    count = int(value)
    if count < 0 or (not isinstance(value, str) and count != value):
        raise ValueError("Invalid report count")
    return count


def _canonical(rows: Iterable[Mapping]) -> dict:
    result = {}
    for row in rows:
        if not isinstance(row, Mapping):
            row = dict(row)
        identifier = row.get("file")
        if not isinstance(identifier, str) or not identifier or identifier in result:
            raise ValueError("Missing or duplicate report identifier")
        # A console export uses "time"; raw index snapshots use "collect_time".
        if "collect_time" not in row and "time" in row:
            row = {**row, "collect_time": row["time"]}
        result[identifier] = (
            *(_count_value(row.get(key)) for key in COUNT_FIELDS),
            *(str(row.get(key) or "") for key in TEXT_FIELDS),
        )
    return result


def compare_report_indexes(sqlite_rows, mysql_rows) -> dict:
    left = _canonical(sqlite_rows)
    right = _canonical(mysql_rows)
    common = left.keys() & right.keys()
    mismatch_counts = {field: 0 for field in COMPARE_FIELDS}
    differences = 0
    for key in common:
        if left[key] != right[key]:
            differences += 1
            for field, a, b in zip(COMPARE_FIELDS, left[key], right[key]):
                if a != b:
                    mismatch_counts[field] += 1
    return {
        "sqlite_count": len(left),
        "mysql_count": len(right),
        "sqlite_only": len(left.keys() - right.keys()),
        "mysql_only": len(right.keys() - left.keys()),
        "different": differences,
        "field_mismatches": {field: count for field, count in mismatch_counts.items() if count},
        "consistent": left == right,
    }
