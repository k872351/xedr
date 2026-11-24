"""JSON encoding shared by report storage and its legacy readers."""
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


def _jdump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _jload(s: Optional[str], default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def write_report_json(path: Path, data: Any) -> None:
    """Replace one report document only after the new document is fully written."""
    path = Path(path)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".report-", suffix=".tmp", delete=False) as stream:
            temp_path = Path(stream.name)
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
