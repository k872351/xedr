import unittest

from backend.ssrf_guard import validate_outbound_url


class SsrfGuardTests(unittest.TestCase):
    def test_blocks_loopback(self):
        with self.assertRaises(ValueError):
            validate_outbound_url("https://127.0.0.1/x")

    def test_blocks_metadata(self):
        with self.assertRaises(ValueError):
            validate_outbound_url("http://169.254.169.254/latest/meta-data/")

    def test_blocks_private(self):
        with self.assertRaises(ValueError):
            validate_outbound_url("https://10.0.0.5/hook")

    def test_requires_https_by_default_for_scheme_check(self):
        # allow_http=False 默认拒绝 http
        with self.assertRaises(ValueError):
            validate_outbound_url("http://example.com/hook", allow_http=False)


if __name__ == "__main__":
    unittest.main()
