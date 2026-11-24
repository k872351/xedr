import tempfile
import unittest
from pathlib import Path

from scripts.audit_linux_rule_metadata import audit


class LinuxRuleMetadataAuditTests(unittest.TestCase):
    def test_invalid_metadata_and_risk_consistency(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as tmp:
            root = Path(tmp)
            for i, severity, score, extra in (
                (1, '"low"', '0', ''),
                (2, '"high"', '0', ''),
                (3, '42', 'true', 'references=[42]\n'),
                (4, '"medium"', '101', 'false_positives=[" "]\n'),
                (5, '"low"', '2.5', ''),
            ):
                (root / f'{i}.toml').write_text(
                    f'[rule]\nrule_id="fixture-{i}"\nname="fixture"\ndescription="metadata fixture"\nseverity={severity}\nrisk_score={score}\n{extra}', encoding='utf-8')
            result = audit(root)
            self.assertEqual(result['metadata_invalid']['risk_score'], 3)
            self.assertEqual(result['metadata_invalid']['severity'], 1)
            self.assertEqual(result['metadata_invalid']['references'], 1)
            self.assertEqual(result['metadata_invalid']['false_positives'], 1)
            self.assertEqual(result['risk_severity_mismatch'], 1)
            self.assertFalse(result['metadata_validation_ok'])

    def test_valid_zero_score_and_optional_guidance(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as tmp:
            root = Path(tmp)
            self.assertFalse(audit(root)['metadata_validation_ok'])
            (root / 'valid.toml').write_text('[rule]\nrule_id="fixture"\nname="fixture"\ndescription="metadata fixture"\nseverity="low"\nrisk_score=0\n', encoding='utf-8')
            result = audit(root)
            self.assertTrue(result['metadata_validation_ok'])
            self.assertEqual(result['metadata_invalid']['risk_score'], 0)

    def test_aggregate_metadata_counts_and_parse_error(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as tmp:
            root = Path(tmp)
            (root / 'one.toml').write_text('[rule]\nrule_id="fixture"\nname="fixture"\nseverity="low"\nrisk_score=0\n', encoding='utf-8')
            (root / 'two.toml').write_text('[rule]\nrule_id="fixture"\nfalse_positives=[]\n', encoding='utf-8')
            (root / 'invalid.toml').write_text('[', encoding='utf-8')
            result = audit(root)
            self.assertEqual(result['files'], 3)
            self.assertEqual(result['parsed'], 2)
            self.assertEqual(result['parse_errors'], 1)
            self.assertEqual(result['duplicate_id_groups'], 1)
            self.assertEqual(result['metadata_coverage']['risk_score'], 1)
            self.assertEqual(result['metadata_coverage']['false_positives'], 0)
            self.assertEqual(result['metadata_missing']['description'], 2)
            self.assertIsNone(result['false_positive_rate'])
            self.assertEqual(result['review_status'], 'metadata_only')

    def test_blank_guidance_is_not_counted_as_documented(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as tmp:
            root = Path(tmp)
            (root / 'blank.toml').write_text('[rule]\nrule_id=" "\nfalse_positives=[" ", ""]\nreferences=[" "]\nrisk_score=0\n', encoding='utf-8')
            result = audit(root)
            self.assertEqual(result['missing_ids'], 1)
            self.assertEqual(result['metadata_coverage']['false_positives'], 0)
            self.assertEqual(result['metadata_coverage']['references'], 0)
            self.assertEqual(result['metadata_coverage']['risk_score'], 1)

