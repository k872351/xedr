import unittest
from unittest.mock import patch

from scripts.check_dependency_versions import check_versions


class DependencyVersionsTests(unittest.TestCase):
    def test_pins(self):
        with patch("scripts.check_dependency_versions.version", return_value="1.2"):
            self.assertEqual(check_versions(["# comment", "", "example==1.2"]), [])
            self.assertEqual(len(check_versions(["example==1.3", "example>=1.2"])), 2)
