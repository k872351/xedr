import unittest
from pathlib import Path
from unittest.mock import patch

from backend.report_json import _jdump, _jload, write_report_json


class ReportJsonTests(unittest.TestCase):
    def test_failed_write_does_not_replace_existing_document(self):
        with patch("backend.report_json.tempfile.NamedTemporaryFile") as temp, \
             patch("backend.report_json.os.replace") as replace, \
             patch("backend.report_json.Path.unlink") as unlink:
            stream = temp.return_value.__enter__.return_value
            stream.name = "example.tmp"
            stream.write.side_effect = OSError("write failed")
            with self.assertRaises(OSError):
                write_report_json(Path("example.json"), {"name": "example"})
            replace.assert_not_called()
            unlink.assert_called_once_with(missing_ok=True)
    def test_roundtrip(self):
        value = {"name": "测试", "items": [1, None, False]}
        self.assertEqual(_jload(_jdump(value)), value)

    def test_legacy_empty_or_invalid(self):
        for value in ("", None, "{"):
            self.assertEqual(_jload(value, []), [])
