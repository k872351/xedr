package main

import (
	"sync/atomic"
)

// 时间线/事件字段规范版本。服务端可按 schema_version 做兼容解析。
const eventSchemaVersion = 1

var agentEventSeq atomic.Uint64

// stampEventSchema 为单条事件写入 schema_version 与单调 agent_seq（用于缺口检测）。
func stampEventSchema(ev map[string]any) {
	if ev == nil {
		return
	}
	if _, ok := ev["schema_version"]; !ok {
		ev["schema_version"] = eventSchemaVersion
	}
	if _, ok := ev["agent_seq"]; !ok {
		ev["agent_seq"] = agentEventSeq.Add(1)
	}
}

func stampEventsSchema(events []map[string]any) {
	for _, ev := range events {
		stampEventSchema(ev)
	}
}

// detectSeqGaps 检查一批事件的 agent_seq 是否连续；返回缺口列表（期望值）。
func detectSeqGaps(seqs []uint64) []uint64 {
	if len(seqs) < 2 {
		return nil
	}
	var gaps []uint64
	prev := seqs[0]
	for i := 1; i < len(seqs); i++ {
		cur := seqs[i]
		if cur <= prev {
			continue
		}
		for n := prev + 1; n < cur; n++ {
			gaps = append(gaps, n)
			if len(gaps) >= 64 {
				return gaps
			}
		}
		prev = cur
	}
	return gaps
}
