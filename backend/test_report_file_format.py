import unittest

from backend.report_file_format import FILE_CONTENT_MAX_CHARS, _file_content_field, _file_row_tuple


class ReportFileFormatTests(unittest.TestCase):
    def test_bad_size_does_not_break_serialization(self):
        for value in ("invalid", -1, 1.5, 2**63, float("inf"), True):
            self.assertIsNone(_file_row_tuple({"size": value})[5])
        self.assertEqual(_file_row_tuple({"size": "1024"})[5], 1024)
    def test_legacy_record(self):
        row = _file_row_tuple({"full_path": "C:/Example/app.txt", "size": "3", "ext": "TXT", "SHA256": "AB" * 32})
        self.assertEqual(len(row), 25)
        self.assertEqual(row[3], r"c:\example")
        self.assertEqual(row[4:6], (".txt", 3))
        self.assertEqual(row[17], "ab" * 32)

    def test_content_bounds(self):
        self.assertEqual(_file_content_field({"text": b"example"}), "example")
        self.assertEqual(_file_content_field({"content": " "}), "")
        self.assertEqual(len(_file_content_field({"content": "x" * (FILE_CONTENT_MAX_CHARS + 1)})), FILE_CONTENT_MAX_CHARS)
