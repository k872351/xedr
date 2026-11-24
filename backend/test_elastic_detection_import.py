import unittest

from backend import elastic_detection_import as importer


class ElasticDetectionImportTests(unittest.TestCase):
    def test_linux_rule_ids_are_namespaced_from_other_platforms(self):
        rule = {"rule_id": "884e87cc-c67b-4c90-a4ed-e1e24a940c82"}
        self.assertEqual(importer._elastic_id(rule, "windows/example.toml"), "elastic-884e87cc")
        self.assertEqual(importer._elastic_id(rule, "linux/example.toml"), "elastic-884e87cc-linux")

    def test_linux_catalog_is_discovered_from_rules_directory(self):
        catalog = importer.scan_catalog(platform="linux")
        self.assertGreaterEqual(catalog["stats"]["total"], 300)
        self.assertEqual(catalog["stats"]["total"], sum(
            catalog["stats"][key] for key in ("convertible", "reference", "unsupported")
        ))
        self.assertTrue(all(item["platform"] == "linux" for item in catalog["items"]))
        self.assertTrue(all(item["id"].endswith("-linux") for item in catalog["items"]))


if __name__ == "__main__":
    unittest.main()
