# -*- coding: utf-8 -*-
"""ATT&CK 版本演进字段单测：revoked_by / deprecated / data_sources / 子技术继承 / 闭集校验。"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from . import mitre


def _catalog(**kw):
    base = {
        "mitre_version": "17.1", "verified": True,
        "deprecated": set(), "revoked_by": {}, "data_sources": {},
        "allowed_data_sources": {"Process", "Process Access", "Command", "File"},
    }
    base.update(kw)
    return base


class BackwardCompatTest(unittest.TestCase):
    def test_default_catalog_is_empty_and_backward_compatible(self):
        # 真实数据文件默认全空 => 不改变任何现有技术的展示
        cat = mitre._version_catalog()
        self.assertFalse(cat["deprecated"])
        self.assertFalse(cat["revoked_by"])
        self.assertFalse(cat["data_sources"])

    def test_meta_keeps_legacy_fields(self):
        m = mitre.technique_meta("T1003")
        for k in ("id", "name_cn", "name_en", "label", "label_plain"):
            self.assertIn(k, m)
        self.assertEqual(m["id"], "T1003")
        self.assertEqual(m["label"], "T1003 · 操作系统凭据转储")
        self.assertEqual(m["status"], "active")
        self.assertFalse(m["deprecated"])

    def test_subtechnique_falls_back_to_parent_name(self):
        m = mitre.technique_meta("T1003.001")
        self.assertEqual(m["id"], "T1003.001")
        self.assertIn("name_cn", m)

    def test_label_unchanged_when_no_version_data(self):
        labels = mitre.mitre_labels(["T1003", "T1059"])
        for item in labels:
            self.assertEqual(item["label"], item["label_plain"])


class VersionStatusTest(unittest.TestCase):
    def test_deprecated(self):
        c = _catalog(deprecated={"T1086"})
        s = mitre.version_status("T1086", versioning=c)
        self.assertEqual(s["status"], "deprecated")
        self.assertTrue(s["deprecated"])
        self.assertEqual(s["mitre_version"], "17.1")

    def test_revoked_with_replacement(self):
        c = _catalog(revoked_by={"T1086": "T1059.001"})
        s = mitre.version_status("T1086", versioning=c)
        self.assertEqual(s["status"], "revoked")
        self.assertEqual(s["revoked_by"], "T1059.001")

    def test_revoked_takes_precedence_over_deprecated(self):
        c = _catalog(deprecated={"T1086"}, revoked_by={"T1086": "T1059.001"})
        self.assertEqual(mitre.version_status("T1086", versioning=c)["status"], "revoked")

    def test_data_sources(self):
        c = _catalog(data_sources={"T1003": ["Process", "Process Access"]})
        s = mitre.version_status("T1003", versioning=c)
        self.assertEqual(s["data_sources"], ["Process", "Process Access"])

    def test_subtechnique_inherits_parent_revocation(self):
        c = _catalog(revoked_by={"T1003": "T1003.008"})
        s = mitre.version_status("T1003.001", versioning=c)
        self.assertEqual(s["status"], "revoked")
        self.assertEqual(s["revoked_by"], "T1003.008")

    def test_subtechnique_own_status_wins(self):
        c = _catalog(revoked_by={"T1003": "T1003.008", "T1003.001": "T1003.002"})
        s = mitre.version_status("T1003.001", versioning=c)
        self.assertEqual(s["revoked_by"], "T1003.002")

    def test_invalid_id_is_active(self):
        self.assertEqual(mitre.version_status("garbage", versioning=_catalog())["status"], "active")


class MetaLabelTest(unittest.TestCase):
    def test_deprecated_label_marked(self):
        m = mitre.technique_meta("T1086", versioning=_catalog(deprecated={"T1086"}))
        self.assertIn("已废弃", m["label"])
        self.assertIn("已废弃", m["label_with_status"])
        self.assertEqual(m["label_plain"], m["label_plain"])

    def test_revoked_label_has_replacement(self):
        m = mitre.technique_meta("T1086", versioning=_catalog(revoked_by={"T1086": "T1059.001"}))
        self.assertIn("T1059.001", m["label"])


class ValidateVersioningTest(unittest.TestCase):
    def test_real_file_is_valid(self):
        p = Path(mitre.__file__).resolve().parent / "data" / "mitre_versioning.json"
        raw = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(mitre.validate_versioning(raw), [])

    def test_unknown_top_key_rejected(self):
        raw = {"mitre_version": "x", "verified": False, "allowed_data_sources": ["Process"],
               "deprecated": [], "revoked_by": {}, "data_sources": {}, "bogus": 1}
        self.assertTrue(any("未知顶层键" in e for e in mitre.validate_versioning(raw)))

    def test_bad_technique_id_rejected(self):
        raw = {"mitre_version": "x", "verified": True, "allowed_data_sources": ["Process"],
               "deprecated": ["NOT-A-TID"], "revoked_by": {}, "data_sources": {}}
        self.assertTrue(any("非法技术 ID" in e for e in mitre.validate_versioning(raw)))

    def test_bad_revoked_by_value_rejected(self):
        raw = {"mitre_version": "x", "verified": True, "allowed_data_sources": ["Process"],
               "deprecated": [], "revoked_by": {"T1086": "???", "data_sources": {}}}
        self.assertTrue(any("revoked_by" in e for e in mitre.validate_versioning(raw)))

    def test_non_whitelisted_data_source_rejected(self):
        raw = {"mitre_version": "x", "verified": True, "allowed_data_sources": ["Process"],
               "deprecated": [], "revoked_by": {}, "data_sources": {"T1003": ["Alien Source"]}}
        self.assertTrue(any("非白名单数据源" in e for e in mitre.validate_versioning(raw)))

    def test_non_dict_root_rejected(self):
        self.assertIn("根节点", mitre.validate_versioning([])[0])


if __name__ == "__main__":
    unittest.main()
