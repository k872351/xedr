package main

import (
	"context"
	"sync"
	"time"
)

// 快慢车道隔离（借鉴 openedr lane.hpp 的 Fast / SlowLocalFS / SlowNetwork）：
// 心跳主循环只做快车道工作（HTTP 心跳、策略验签、回执记要、周期更新），任何可能
// 耗时数十秒的操作（规则同步、命令执行/内存扫描/升级）都投递到有界慢车道单worker。
//
// 设计要点：
// - 有界队列 + 合并（coalesce）：同类慢任务只保留一个在途，避免慢任务堆积拖垮心跳。
// - 命令可丢：服务端按 lease 重投直到 ACK，慢车道丢批次不会丢命令。
// - 同步可丢：下一次心跳会再次携带 SyncRev，重复 offer 即可补上。
// - 单 worker 串行执行，保证 sync 与 commands 不会彼此重入。

type slowLaneKind string

const (
	slowLaneSync     slowLaneKind = "sync"
	slowLaneCommands slowLaneKind = "commands"
)

type slowLaneJob struct {
	kind    slowLaneKind
	syncRev int
	cmds    []agentCommand
	queued  time.Time
}

// slowLane 有界慢车道：按 kind 合并，同一时刻每类最多一个在途任务。
type slowLane struct {
	mu           sync.Mutex
	pending      map[slowLaneKind]bool
	jobs         chan slowLaneJob
	depth        int
	waitingCmds  []agentCommand // 在途时新到的命令暂存，执行完立刻续跑，避免 lease 空等
}

func newSlowLane(depth int) *slowLane {
	if depth < 2 {
		depth = 2
	}
	return &slowLane{
		pending: map[slowLaneKind]bool{},
		jobs:    make(chan slowLaneJob, depth),
		depth:   depth,
	}
}

// offerSync 投递同步任务；已有在途同步时只记录更高 rev，由下一次心跳补投。
func (l *slowLane) offerSync(rev int) bool {
	if l == nil || rev <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending[slowLaneSync] {
		captureAdd("slow_lane", "sync_coalesced", 1)
		return false
	}
	select {
	case l.jobs <- slowLaneJob{kind: slowLaneSync, syncRev: rev, queued: time.Now()}:
		l.pending[slowLaneSync] = true
		captureAdd("slow_lane", "sync_queued", 1)
		return true
	default:
		captureAdd("slow_lane", "queue_full", 1)
		return false
	}
}

// offerCommands 投递命令批次；已有在途时合并到等待队列，执行完立即续跑（避免 sent+lease 空等）。
func (l *slowLane) offerCommands(cmds []agentCommand) bool {
	if l == nil || len(cmds) == 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending[slowLaneCommands] {
		l.waitingCmds = appendCommandUnique(l.waitingCmds, cmds)
		captureAdd("slow_lane", "commands_buffered", 1)
		return true
	}
	select {
	case l.jobs <- slowLaneJob{kind: slowLaneCommands, cmds: cmds, queued: time.Now()}:
		l.pending[slowLaneCommands] = true
		captureAdd("slow_lane", "commands_queued", 1)
		return true
	default:
		l.waitingCmds = appendCommandUnique(l.waitingCmds, cmds)
		captureAdd("slow_lane", "queue_full_buffered", 1)
		return true
	}
}

func appendCommandUnique(dst, src []agentCommand) []agentCommand {
	seen := map[string]bool{}
	for _, c := range dst {
		seen[c.ID] = true
	}
	for _, c := range src {
		if c.ID == "" || seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		dst = append(dst, c)
	}
	return dst
}

// run 单 worker 串行消费慢车道，直到 ctx 取消。
func (l *slowLane) run(ctx context.Context, handle func(slowLaneJob)) {
	if l == nil || handle == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-l.jobs:
			if ctx.Err() != nil {
				return
			}
			// 过期任务直接丢弃：命令有自己的 deadline 校验，同步由下次心跳补投。
			if time.Since(job.queued) > 30*time.Second {
				captureAdd("slow_lane", "aged_out", 1)
			} else {
				started := time.Now()
				handle(job)
				recordLoopDuration("slow_lane_"+string(job.kind), time.Since(started), time.Second)
			}
			l.mu.Lock()
			delete(l.pending, job.kind)
			var next []agentCommand
			if job.kind == slowLaneCommands && len(l.waitingCmds) > 0 {
				next = l.waitingCmds
				l.waitingCmds = nil
			}
			if len(next) > 0 {
				select {
				case l.jobs <- slowLaneJob{kind: slowLaneCommands, cmds: next, queued: time.Now()}:
					l.pending[slowLaneCommands] = true
					captureAdd("slow_lane", "commands_drained", 1)
				default:
					l.waitingCmds = appendCommandUnique(l.waitingCmds, next)
				}
			}
			l.mu.Unlock()
		}
	}
}

// inFlight 返回当前在途任务类型（用于诊断快照）。
func (l *slowLane) inFlight() []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.pending))
	for k := range l.pending {
		out = append(out, string(k))
	}
	return out
}
