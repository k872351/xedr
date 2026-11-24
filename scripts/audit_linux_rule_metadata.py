#!/usr/bin/env python3
"""Read-only, aggregate quality report for the Linux rule corpus.

This does not evaluate matching expressions, change rule behavior, or publish rules.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import json
import tomllib

if __package__:
    from .validate_rules import RISK_BANDS, SEV_RANK
else:
    from validate_rules import RISK_BANDS, SEV_RANK

ROOT = Path(__file__).resolve().parents[1] / "rules" / "linux"
FIELDS = ("name", "description", "severity", "risk_score", "false_positives", "references", "rule_id")
REQUIRED = ("name", "description", "severity", "risk_score", "rule_id")


def _present(value) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple)):
        return any(_present(item) for item in value)
    return value is not None


def _valid(field: str, value) -> bool:
    if field == "risk_score":
        return type(value) is int and 0 <= value <= 100
    if field == "severity":
        return isinstance(value, str) and value in SEV_RANK
    if field in ("false_positives", "references"):
        return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)
    return isinstance(value, str) and bool(value.strip())


def _risk_mismatch(rule: dict) -> bool:
    severity, score = rule.get("severity"), rule.get("risk_score")
    if not (_valid("severity", severity) and _valid("risk_score", score)):
        return False
    low, high = RISK_BANDS.get(severity, (0, 100))
    return not low <= score <= high


def audit(root: Path) -> dict:
    files = sorted(root.rglob("*.toml"))
    rows = []
    parse_errors = 0
    for path in files:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            rule = data.get("rule")
            if not isinstance(rule, dict):
                parse_errors += 1
                continue
            rows.append(rule)
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            parse_errors += 1
    ids = Counter(r["rule_id"].strip() for r in rows if isinstance(r.get("rule_id"), str) and _present(r["rule_id"]))
    coverage = {key: sum(_present(r.get(key)) for r in rows) for key in FIELDS}
    invalid = {key: sum(key in r and not _valid(key, r[key]) for r in rows) for key in FIELDS}
    required_missing = sum(any(not _present(r.get(key)) for key in REQUIRED) for r in rows)
    mismatch = sum(_risk_mismatch(r) for r in rows)
    duplicates = sum(n > 1 for n in ids.values())
    return {
        "files": len(files),
        "parsed": len(rows),
        "parse_errors": parse_errors,
        "missing_ids": len(rows) - sum(ids.values()),
        "duplicate_id_groups": duplicates,
        "severity_counts": dict(sorted(Counter(r["severity"] if _valid("severity", r.get("severity")) else "missing" if "severity" not in r else "invalid" for r in rows).items())),
        "metadata_coverage": coverage,
        "metadata_missing": {key: len(rows) - count for key, count in coverage.items()},
        "metadata_invalid": invalid,
        "required_metadata_missing_rules": required_missing,
        "risk_severity_mismatch": mismatch,
        "metadata_validation_ok": bool(files) and not (parse_errors or duplicates or required_missing or mismatch or any(invalid.values())),
        "review_status": "metadata_only",
        "false_positive_rate": None,
    }


if __name__ == "__main__":
    print(json.dumps(audit(ROOT), ensure_ascii=False, indent=2))
