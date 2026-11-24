package main

import (
	"context"
	"sync"
	"time"
)

// A bounded single-worker queue keeps slow follow-up work off the live loop.
type triggerScanQueue struct {
	mu      sync.Mutex
	pending map[int]bool
	jobs    chan triggerScanJob
}

type triggerScanJob struct {
	pid    int
	reason string
	queued time.Time
}

func newTriggerScanQueue() *triggerScanQueue {
	return &triggerScanQueue{pending: map[int]bool{}, jobs: make(chan triggerScanJob, 16)}
}

func (q *triggerScanQueue) offer(pid int, reason string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending[pid] {
		captureAdd("trigger_scan_requests", "coalesced", 1)
		return false
	}
	select {
	case q.jobs <- triggerScanJob{pid: pid, reason: reason, queued: time.Now()}:
		q.pending[pid] = true
		captureAdd("trigger_scan_requests", "queued", 1)
		return true
	default:
		captureAdd("trigger_scan_requests", "queue_full", 1)
		return false
	}
}

func (q *triggerScanQueue) run(ctx context.Context, handle func(triggerScanJob)) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-q.jobs:
			if ctx.Err() != nil {
				return
			}
			if time.Since(job.queued) <= 5*time.Second {
				handle(job)
			} else {
				captureAdd("trigger_scan_requests", "expired", 1)
			}
			q.mu.Lock()
			delete(q.pending, job.pid)
			q.mu.Unlock()
		}
	}
}
