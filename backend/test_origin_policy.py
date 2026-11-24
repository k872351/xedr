import unittest

from backend.origin_policy import same_write_origin


class OriginPolicyTests(unittest.TestCase):
    def test_same_origin(self):
        self.assertTrue(same_write_origin("https://console.example", "console.example:443", "https"))
        self.assertTrue(same_write_origin("http://[::1]:8100", "[::1]:8100", "http"))
        self.assertTrue(same_write_origin("", "localhost:8100", "http"))

    def test_other_or_invalid_origins(self):
        for origin in ("null", "https://other.example", "http://console.example", "https://console.example:8100", "https://console.example/path", "https://console.example:bad"):
            self.assertFalse(same_write_origin(origin, "console.example", "https"))
