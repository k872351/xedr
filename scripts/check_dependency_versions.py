"""Compare installed direct dependencies with the project's exact pins."""
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def check_versions(lines):
    failures = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name, separator, expected = line.partition("==")
        if not separator or not name or not expected:
            failures.append(f"Invalid exact pin: {line}")
            continue
        try:
            actual = version(name)
        except PackageNotFoundError:
            failures.append(f"{name}: missing")
            continue
        if actual != expected:
            failures.append(f"{name}: installed {actual}, expected {expected}")
    return failures


if __name__ == "__main__":
    manifest = Path(__file__).resolve().parent.parent / "requirements.txt"
    failures = check_versions(manifest.read_text(encoding="utf-8-sig").splitlines())
    for failure in failures:
        print(failure)
    print("Dependency pins: " + ("FAIL" if failures else "PASS"))
    raise SystemExit(bool(failures))
