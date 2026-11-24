import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import es_event_queue as eq


class EsEventQueueTests(unittest.TestCase):
    def test_enqueue_dedupes_by_event_key(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(eq.config, "DATA_ROOT", Path(td)), \
                 patch.object(eq, "_ensure_worker", lambda: None):
                a = eq.enqueue_timeline_event(
                    agent_id="a1", hostname="h", etype="proc", summary="x", detail={}, ts="2026-01-01T00:00:00Z",
                )
                b = eq.enqueue_timeline_event(
                    agent_id="a1", hostname="h", etype="proc", summary="x", detail={}, ts="2026-01-01T00:00:00Z",
                )
                self.assertEqual(a, b)
                st = eq.queue_stats()
                self.assertEqual(st["counts"].get("pending", 0), 1)

    def test_drain_marks_done(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(eq.config, "DATA_ROOT", Path(td)), \
                 patch.object(eq, "_ensure_worker", lambda: None):
                eq.stop_worker()
                eq.enqueue_timeline_event(
                    agent_id="a1", hostname="h", etype="file", summary="y", detail={"p": 1}, ts="t1",
                )
                with patch("backend.elastic_detection_es.index_timeline_batch",
                           side_effect=lambda items: {key: True for key, _ in items}):
                    self.assertTrue(eq._drain_once(limit=10))
                st = eq.queue_stats()
                self.assertEqual(st["counts"].get("done", 0), 1)


if __name__ == "__main__":
    unittest.main()
