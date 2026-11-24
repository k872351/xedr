import unittest

from backend.report_event_format import _elog_row_tuple, _event_log_row_to_dict


class ReportEventFormatTests(unittest.TestCase):
    def test_legacy_roundtrip(self):
        keys = ("channel", "event_id", "provider", "time", "level", "computer", "message", "fields")
        source = {"channel": "System", "event_id": "12", "message": "Example", "fields": {"status": "ok"}}
        row = dict(zip(keys, _elog_row_tuple(source)))
        decoded = _event_log_row_to_dict(row)
        self.assertEqual(decoded["event_id"], 12)
        self.assertEqual(decoded["fields"], {"status": "ok"})
        self.assertEqual(decoded["message"], "Example")

    def test_invalid_legacy_values(self):
        row = _elog_row_tuple({"event_id": "invalid", "message": "x" * 2001, "fields": []})
        self.assertEqual(row[1], 0)
        self.assertEqual(len(row[6]), 2003)
        self.assertEqual(row[7], "")
