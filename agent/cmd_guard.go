package main

import (
	"encoding/json"
	"strings"
	"time"
)

// 命令执行防重：服务端 lease 过期会重投同一个命令 ID（Agent 崩溃/ACK 丢失时）。
// Agent 在本地 SQLite 记录回执：已完成的只重放 ACK，不重复执行；
// 执行到一半崩溃的“非幂等动作”不自动重跑，改为回报失败，由管理员决定。
type cmdReceipt struct {
	Status string // started | done
	OK     bool
	Result map[string]any
}

const cmdReceiptTTL = 7 * 24 * time.Hour

func (o *outbox) cmdReceipt(id string) *cmdReceipt {
	var status string
	var ok int
	var raw []byte
	err := o.st.db.QueryRow("SELECT status, ok, result FROM cmd_receipts WHERE id=?", id).Scan(&status, &ok, &raw)
	if err != nil {
		return nil
	}
	r := &cmdReceipt{Status: status, OK: ok == 1}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &r.Result)
	}
	return r
}

func (o *outbox) cmdBegin(id, action string) bool {
	if o == nil || o.st == nil || (nonIdempotentAction(strings.ToLower(action)) && o.st.path == ":memory:") {
		return false
	}
	result, err := o.st.db.Exec(
		`INSERT INTO cmd_receipts(id, action, status, started_at) VALUES(?,?, 'started', ?)
		 ON CONFLICT(id) DO NOTHING`, id, action, time.Now().UnixMilli())
	if err != nil {
		return false
	}
	// ON CONFLICT DO NOTHING：已有回执也算可追踪
	n, err := result.RowsAffected()
	return err == nil && n == 1
}

func (o *outbox) cmdFinish(id string, ok bool, result map[string]any) bool {
	if o == nil || o.st == nil {
		return false
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return false
	}
	okv := 0
	if ok {
		okv = 1
	}
	updated, err := o.st.db.Exec(
		`UPDATE cmd_receipts SET status='done', ok=?, result=?, done_at=? WHERE id=?`,
		okv, raw, time.Now().UnixMilli(), id)
	if err != nil {
		return false
	}
	n, err := updated.RowsAffected()
	return err == nil && n == 1
}

func (o *outbox) cmdPurge() {
	_, _ = o.st.db.Exec("DELETE FROM cmd_receipts WHERE started_at<?", time.Now().Add(-cmdReceiptTTL).UnixMilli())
}

// nonIdempotentAction：中途崩溃后重跑可能造成副作用叠加的动作。
func nonIdempotentAction(action string) bool {
	switch action {
	case "upgrade", "rollback_upgrade", "uninstall_agent", "kill_process",
		"isolate_network", "unisolate_network",
		"restore_file", "quarantine_file":
		return true
	}
	return false
}

func commandExpired(deadline string) bool {
	if deadline == "" {
		return false
	}
	s := strings.TrimSpace(deadline)
	now := time.Now()
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return now.UTC().After(t.UTC())
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05Z", s, time.UTC); err == nil {
		return now.UTC().After(t)
	}
	trimmed := strings.TrimSuffix(s, "Z")
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", trimmed, time.UTC); err == nil && strings.HasSuffix(s, "Z") {
		return now.UTC().After(t)
	}
	// 兼容旧版本地时间截止
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", s, time.Local); err == nil {
		return now.After(t)
	}
	return false
}
