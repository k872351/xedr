import unittest

from backend.file_normalization import _norm_ext, _norm_hash_field, _norm_file_path, _file_parent, _directory_rows


class FileNormalizationTests(unittest.TestCase):
    def test_directory_rows(self):
        rows = _directory_rows([{"full_path": "/usr/bin/example"}, {"full_path": "/usr/bin/other"}])
        self.assertEqual([row[3] for row in rows], ["/usr", "/usr/bin"])
        self.assertEqual(rows[1][1], rows[0][0])

    def test_extension(self):
        self.assertEqual(_norm_ext(" EXE "), ".exe")
        self.assertEqual(_norm_ext(None), "")

    def test_hash(self):
        self.assertEqual(_norm_hash_field("0x" + "AB-" * 16), "ab" * 16)
        self.assertEqual(_norm_hash_field("g" * 32), "")

    def test_path(self):
        self.assertEqual(_norm_file_path("C:/Temp//Example.TXT"), r"c:\temp\example.txt")
        self.assertEqual(_file_parent({"full_path": "C:/Temp/Example.TXT"}), r"C:\Temp")
