"""Isolated checks for deployment diagnostics and durable telemetry."""
import sqlite3
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from backend import agent_protocol, agent_public_url, es_event_queue


class ReliabilityAcceptanceTests(unittest.TestCase):
    def test_health_limit_keeps_valid_quality_json(self):
        raw = agent_protocol.bounded_health_json({
            "optional": "x" * 100000,
            "capture_quality": {"etw": {"received": 12}},
        })
        data = json.loads(raw)
        self.assertTrue(data["health_truncated"])
        self.assertEqual(data["capture_quality"]["etw"]["received"], 12)
        self.assertLessEqual(len(raw.encode()), 60000)

    def test_heartbeat_period_and_revocation(self):
        now = 1_800_000_000
        last = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - 100))
        self.assertTrue(agent_protocol.is_agent_online(last, 120, now=now))
        self.assertFalse(agent_protocol.is_agent_online(last, 3, now=now))
        self.assertFalse(agent_protocol.is_agent_online(last, 120, now=now, revoked=True))
        self.assertFalse(agent_protocol.is_agent_online("", 120, now=now))

    def test_registered_device_waits_for_first_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.sqlite"
            def connect():
                conn = sqlite3.connect(path)
                conn.row_factory = sqlite3.Row
                return conn
            with connect() as conn:
                conn.executescript(agent_protocol._SCHEMA)
                agent_protocol._mig_001_agent_build_protocol(conn)
                agent_protocol._mig_002_credentials_health(conn)
                agent_protocol._mig_012_heartbeat_period_and_index_outbox(conn)
            conn.close()
            with patch.object(agent_protocol, "_connect", side_effect=connect), \
                 patch.object(agent_protocol, "ensure_db"), patch.object(agent_protocol, "bump_live"), \
                 patch.object(agent_protocol, "bump_live_heartbeat"), \
                 patch("backend.agent_store.write_agent"), patch("backend.agent_release.release_status", return_value={}), \
                 patch("backend.agent_sync.sync_revision", return_value=10), \
                 patch("backend.agent_sync.manifest", return_value={}), \
                 patch("backend.agent_edr.agent_side_bundle", return_value={"policy": {"heartbeat_sec": 120}}):
                reg = agent_protocol.register_agent({"hostname": "synthetic-device", "agent_id": "test-agent"})
                self.assertTrue(reg["ok"])
                self.assertFalse(agent_protocol.list_agents()["items"][0]["online"])
                hb = agent_protocol.heartbeat({"agent_id": "test-agent", "health": {}})
                self.assertTrue(hb["ok"])
                row = agent_protocol.list_agents()["items"][0]
                self.assertTrue(row["online"])
                self.assertEqual(row["heartbeat_period_sec"], 120)
                self.assertFalse(row["telemetry_received"])

    def test_only_explicit_package_address(self):
        with patch.object(agent_public_url, "_meta_get", return_value=""):
            with self.assertRaises(HTTPException):
                agent_public_url.public_base_url(None)
        with patch.object(agent_public_url, "_meta_get", return_value="https://example.invalid/app/"):
            self.assertEqual(agent_public_url.public_base_url(None), "https://example.invalid")
        self.assertEqual(agent_public_url.deployment_address_status("http://127.0.0.1")["server_url_source"], "invalid")

    def test_index_queue_rolls_back_with_business_event(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        es_event_queue.ensure_transactional_schema(conn)
        conn.commit()
        fields = dict(agent_id="a", hostname="h", etype="event", summary="sample", detail={}, ts="t")
        conn.execute("BEGIN")
        es_event_queue.enqueue_timeline_event(conn=conn, source_id="timeline:1", **fields)
        conn.rollback()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM es_queue").fetchone()[0], 0)
        with conn:
            one = es_event_queue.enqueue_timeline_event(conn=conn, source_id="timeline:1", **fields)
            two = es_event_queue.enqueue_timeline_event(conn=conn, source_id="timeline:2", **fields)
            self.assertNotEqual(one, two)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM es_queue").fetchone()[0], 2)

    def test_bulk_only_acknowledges_matching_successful_items(self):
        from backend import elastic_detection_es
        from unittest.mock import Mock
        client = Mock()
        client.bulk.return_value = {"items": [{"index": {"_id": "one", "status": 201}},
                                               {"index": {"_id": "two", "status": 429}}]}
        payload = dict(agent_id="a", hostname="h", etype="event", summary="sample", detail={}, ts="t")
        with patch.object(elastic_detection_es, "detection_enabled", return_value=True), \
             patch.object(elastic_detection_es, "ensure_edr_indices", return_value=True), \
             patch.object(elastic_detection_es, "_cfg", return_value={"index_edr_events": "test"}), \
             patch("backend.es_client.is_available", return_value=True), \
             patch("backend.es_client.get_client", return_value=client):
            self.assertEqual(elastic_detection_es.index_timeline_batch([("one", payload), ("two", payload)]),
                             {"one": True, "two": False})
        operations = client.bulk.call_args.kwargs["operations"]
        self.assertEqual(operations[0]["index"]["_id"], "one")

    def test_test_driver_not_in_production_package(self):
        from backend.agent_msi import driver_files
        self.assertEqual(driver_files(), [])

    def test_sync_revision_survives_new_database_connections(self):
        from backend import agent_sync
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "meta.sqlite"
            with sqlite3.connect(path) as conn:
                conn.execute("CREATE TABLE agent_meta(key TEXT PRIMARY KEY, value TEXT)")
                conn.execute("INSERT INTO agent_meta VALUES('sync_revision','100')")
            conn.close()
            with patch.object(agent_protocol, "_connect", side_effect=lambda: sqlite3.connect(path)), \
                 patch.object(agent_protocol, "bump_live"):
                self.assertEqual(agent_sync.sync_revision(), 100)
                self.assertEqual(agent_sync.bump_sync("policy"), 101)
                self.assertEqual(agent_sync.sync_revision(), 101)

    def test_index_queue_retries_and_recovers_abandoned_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "queue.sqlite"
            # Separate connections simulate worker restart after a committed claim.
            with patch.object(es_event_queue, "_path", return_value=path), \
                 patch.object(es_event_queue, "_ensure_worker"):
                es_event_queue.enqueue_timeline_event(agent_id="a", etype="event", summary="sample", detail={}, ts="t")
                conn = es_event_queue._connect()
                try:
                    conn.execute("UPDATE es_queue SET status='active', attempts=12, updated_at=0")
                    conn.commit()
                finally:
                    conn.close()
                seen = []
                def fail(items):
                    seen.extend(key for key, _ in items)
                    return {}
                with patch("backend.elastic_detection_es.index_timeline_batch", side_effect=fail):
                    self.assertTrue(es_event_queue._drain_once())
                self.assertEqual(es_event_queue.queue_stats()["counts"]["pending"], 1)
                conn = es_event_queue._connect()
                try:
                    conn.execute("UPDATE es_queue SET updated_at=0")
                    conn.commit()
                finally:
                    conn.close()
                def succeed(items):
                    self.assertEqual([key for key, _ in items], seen)
                    return {key: True for key, _ in items}
                with patch("backend.elastic_detection_es.index_timeline_batch", side_effect=succeed):
                    self.assertTrue(es_event_queue._drain_once())
                self.assertEqual(es_event_queue.queue_stats()["counts"]["done"], 1)


if __name__ == "__main__":
    unittest.main()
