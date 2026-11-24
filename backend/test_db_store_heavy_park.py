"""WEB-01：heavy park 使用 gzip JSON，拒绝危险 pickle。"""
from __future__ import annotations

import gzip
import json
import pickle
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import db_store_heavy as heavy


class HeavyParkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

        def report_dir(rid, create=False):
            d = self.root / rid
            if create:
                d.mkdir(parents=True, exist_ok=True)
            return d

        self.patcher = patch.object(heavy.P, "report_dir", side_effect=report_dir)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_park_and_load_json_gz(self):
        report = {"file_scans": [{"path": "C:\\a.exe"}], "event_logs": [{"id": 1}]}
        out = heavy.park_heavy_arrays("r1", report)
        self.assertEqual(out["files"], 1)
        self.assertEqual(report["file_scans"], [])
        path = self.root / "r1" / heavy._PARK_FILES
        self.assertTrue(path.is_file())
        with gzip.open(path, "rb") as fh:
            self.assertEqual(json.loads(fh.read().decode("utf-8"))[0]["path"], "C:\\a.exe")
        restored = {}
        heavy.load_parked_heavy("r1", restored)
        self.assertEqual(len(restored["file_scans"]), 1)

    def test_refuse_malicious_pickle(self):
        d = self.root / "r2"
        d.mkdir()
        bad = d / heavy._LEGACY_FILES

        class Boom:
            def __reduce__(self):
                import os
                return (os.system, ("echo pwned",))

        with open(bad, "wb") as fh:
            pickle.dump(Boom(), fh)
        restored = {}
        heavy.load_parked_heavy("r2", restored)
        self.assertFalse(restored.get("file_scans"))
        self.assertFalse(bad.exists())


if __name__ == "__main__":
    unittest.main()
