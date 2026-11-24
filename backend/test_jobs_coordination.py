import unittest
from unittest.mock import patch

from backend import jobs


class _FakeJobDb:
    def __init__(self, row):
        self.row = dict(row)
        self._rowcount = 0
        self.closed = False

    def execute(self, sql, params=()):
        if "SET status='load'" in sql:
            now, job_id = params
            if self.row["id"] == job_id and self.row["status"] == "queued":
                self.row.update(status="load", phase="load", updated_at=now)
                self._rowcount = 1
            else:
                self._rowcount = 0
        return self

    @property
    def rowcount(self):
        return self._rowcount

    def commit(self):
        pass

    def query_all(self, sql, params=()):
        return [dict(self.row)]

    def close(self):
        self.closed = True


class JobCoordinationTests(unittest.TestCase):
    def setUp(self):
        self.old_jobs = dict(jobs._jobs)
        self.old_queue = list(jobs._queue)
        self.old_recovered = jobs._recovered
        jobs._jobs.clear()
        jobs._queue.clear()
        jobs._recovered = False

    def tearDown(self):
        jobs._jobs.clear()
        jobs._jobs.update(self.old_jobs)
        jobs._queue.clear()
        jobs._queue.extend(self.old_queue)
        jobs._recovered = self.old_recovered

    def test_atomic_claim_wins_only_once(self):
        row = {"id": "job-a", "status": "queued", "phase": "queued", "updated_at": "old"}
        jobs._jobs["job-a"] = dict(row)
        db = _FakeJobDb(row)
        with patch.object(jobs, "_JobDb", return_value=db):
            self.assertTrue(jobs._claim_queued_job("job-a"))
            self.assertFalse(jobs._claim_queued_job("job-a"))
        self.assertEqual(jobs._jobs["job-a"]["status"], "load")
        self.assertTrue(db.closed)

    def test_startup_cache_load_does_not_persist_stale_snapshot(self):
        rows = [
            {"id": "queued-a", "status": "queued", "created_at": "1"},
            {"id": "active-b", "status": "full", "created_at": "2"},
        ]
        with (
            patch.object(jobs, "_requeue_stale_jobs", return_value=0),
            patch.object(jobs, "_load_all_from_db", return_value=rows),
            patch.object(jobs, "_persist") as persist,
            patch.object(jobs, "_ensure_worker") as ensure_worker,
        ):
            self.assertEqual(jobs.recover_jobs_on_startup(), 2)
        persist.assert_not_called()
        ensure_worker.assert_called_once()
        self.assertEqual(list(jobs._queue), ["queued-a"])
        self.assertEqual(jobs._jobs["active-b"]["status"], "full")

    def test_shared_database_outage_rejects_new_jobs(self):
        db = _FakeJobDb({"id": "unused", "status": "queued"})
        db.mysql = False
        with (
            patch.object(jobs, "_shared_job_store_required", return_value=True),
            patch.object(jobs, "_JobDb", return_value=db),
        ):
            with self.assertRaises(jobs.QueueRejected) as raised:
                jobs.enqueue_analyze("report-1")
        self.assertEqual(raised.exception.code, 503)
        self.assertTrue(db.closed)


if __name__ == "__main__":
    unittest.main()
