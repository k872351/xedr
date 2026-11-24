import unittest
import json
import sqlite3
from datetime import datetime
from unittest.mock import patch

from . import abnormal_files, agent_edr, agent_rules
from .abnormal_files import _file_event_fields, _match_abfile_rules


class AbnormalFileRuleTests(unittest.TestCase):
    def test_exact_name_matches_individual_field(self):
        item = {"path": r"C:\Reports\sample.txt", "name": "sample.txt", "ext": "txt"}
        rule = {"id": "sample", "category": "abfile", "fields": ["path", "name"],
                "patterns": ["sample.txt"], "match": "exact", "file_exts": ["txt"]}
        self.assertEqual(_match_abfile_rules(item, [rule])[0]["rule_id"], "sample")
        self.assertEqual(_match_abfile_rules(item, [{**rule, "patterns": ["other.txt"]}]), [])

    def test_scope_and_extension_are_preserved(self):
        item = {"path": r"C:\Reports\sample.txt", "name": "sample.txt", "ext": "txt"}
        rule = {"id": "sample", "category": "abfile", "patterns": ["sample.txt"],
                "match": "exact", "file_exts": ["csv"]}
        self.assertEqual(_match_abfile_rules(item, [rule]), [])
        self.assertEqual(_match_abfile_rules(item, []), [])

    def test_nested_linux_file_details_and_custom_fields_are_matched(self):
        item = _file_event_fields({
            "file": {"file_path": "/tmp/drop/payload.bin", "company": "Evil Labs", "sha256": "abc123"},
            "process_name": "loader",
        })
        self.assertEqual(item["path"], "/tmp/drop/payload.bin")
        self.assertEqual(item["ext"], "bin")
        rule = {
            "id": "company-rule", "category": "abfile", "fields": ["company"],
            "patterns": ["evil labs"], "match": "substring", "file_exts": ["bin"],
        }
        self.assertEqual(_match_abfile_rules(item, [rule])[0]["rule_id"], "company-rule")

    def test_linux_path_can_be_recovered_from_event_summary(self):
        item = _file_event_fields({}, "new file: /var/tmp/loader.sh")
        self.assertEqual(item["path"], "/var/tmp/loader.sh")
        self.assertEqual(item["name"], "loader.sh")
        self.assertEqual(item["ext"], "sh")

    def test_list_pipeline_returns_rule_hit_for_stored_file_event(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("""CREATE TABLE agent_timeline (
            id TEXT, agent_id TEXT, hostname TEXT, etype TEXT, summary TEXT,
            severity TEXT, ts TEXT, detail_json TEXT
        )""")
        conn.execute(
            "INSERT INTO agent_timeline VALUES(?,?,?,?,?,?,?,?)",
            ("evt-1", "agent-1", "linux-test", "fim_add", "file added",
             "info", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
             json.dumps({"file": {"file_path": "/tmp/drop/payload.bin", "company": "Evil Labs"}})),
        )
        rule = {
            "id": "company-rule", "title": "Suspicious publisher", "category": "abfile",
            "fields": ["company"], "patterns": ["evil labs"], "match": "substring",
            "file_exts": ["bin"], "enabled": True,
        }
        with patch.object(agent_edr, "ensure"), \
             patch.object(agent_edr, "_connect", return_value=conn), \
             patch.object(agent_rules, "list_rules", return_value=[rule]):
            result = abnormal_files.list_abnormal_files()
        self.assertEqual(result["count"], 1)
        self.assertTrue(result["items"][0]["rule_hit"])
        self.assertEqual(result["items"][0]["rule_hits"][0]["rule_id"], "company-rule")
