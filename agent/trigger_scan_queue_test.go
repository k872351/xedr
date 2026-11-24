package main

import (
	"context"
	"testing"
	"time"
)

func TestTriggerScanQueueBoundedAndCoalesced(t *testing.T) {
	q := newTriggerScanQueue()
	for i := 1; i <= 16; i++ {
		if !q.offer(i, "synthetic") {
			t.Fatal("capacity lost")
		}
	}
	if q.offer(1, "duplicate") || q.offer(17, "overflow") {
		t.Fatal("queue accepted duplicate or overflow")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.run(ctx, func(job triggerScanJob) {
			close(started)
			<-release
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if q.offer(1, "running duplicate") || !q.offer(17, "new") {
		t.Fatal("worker blocked queue or allowed duplicate")
	}
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}
