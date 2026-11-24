package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestSlowLaneCoalescesSameKind(t *testing.T) {
	l := newSlowLane(4)
	if !l.offerSync(10) {
		t.Fatal("first sync offer should queue")
	}
	if l.offerSync(11) {
		t.Fatal("second sync offer should coalesce")
	}
	if len(l.inFlight()) != 1 {
		t.Fatalf("expected 1 in-flight kind, got %v", l.inFlight())
	}
}

func TestSlowLaneBoundsQueue(t *testing.T) {
	l := newSlowLane(2)
	if !l.offerSync(10) || !l.offerCommands([]agentCommand{{ID: "c1"}}) {
		t.Fatal("two different kinds should both queue")
	}
	if l.offerSync(11) {
		t.Fatal("queue full + same kind pending should reject")
	}
}

func TestSlowLaneSingleWorkerSequential(t *testing.T) {
	l := newSlowLane(8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var concurrent atomic.Int32
	var peak atomic.Int32
	var executed atomic.Int32
	done := make(chan struct{})
	go func() {
		l.run(ctx, func(job slowLaneJob) {
			cur := concurrent.Add(1)
			for {
				old := peak.Load()
				if cur <= old || peak.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			executed.Add(1)
			concurrent.Add(-1)
			if executed.Load() == 3 {
				close(done)
			}
		})
	}()

	l.offerSync(1)
	l.offerCommands([]agentCommand{{ID: "c1"}})
	// 等前两个消费完（在途标记释放）再投第三个，验证 worker 可持续处理
	go func() {
		for executed.Load() < 2 {
			time.Sleep(2 * time.Millisecond)
		}
		l.offerCommands([]agentCommand{{ID: "c2"}})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slow lane did not execute all jobs")
	}
	if peak.Load() != 1 {
		t.Fatalf("single worker expected peak concurrency 1, got %d", peak.Load())
	}
}

func TestSlowLaneReleaseAfterHandle(t *testing.T) {
	l := newSlowLane(2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstDone := make(chan struct{})
	go l.run(ctx, func(job slowLaneJob) {
		<-firstDone
	})
	l.offerSync(1)
	// worker 正在处理，in-flight 应保持
	time.Sleep(20 * time.Millisecond)
	if len(l.inFlight()) != 1 {
		t.Fatalf("in-flight should be held while handling, got %v", l.inFlight())
	}
	close(firstDone)
	deadline := time.Now().Add(time.Second)
	for len(l.inFlight()) > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(l.inFlight()) != 0 {
		t.Fatalf("in-flight should be released after handle, got %v", l.inFlight())
	}
}
