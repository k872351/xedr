import unittest

from .report_finding_format import _finding_search_blob


class ReportFindingFormatTests(unittest.TestCase):
    def test_existing_report_fields(self):
        result = _finding_search_blob({"title": "Example", "evidence": ["Note", "Review"],
                                       "extra": {"status": "Ready"}}, "Host-A", "Report-1")
        for term in ("example", "note review", '"status": "ready"', "host-a", "report-1"):
            self.assertIn(term, result)
