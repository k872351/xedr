package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const linuxJournalCursorKey = "linux_journal_cursor_v1"

func journalText(value any, limit int) string {
	s, _ := value.(string)
	s = redactSensitive(strings.TrimSpace(s))
	if len(s) > limit {
		s = s[:limit]
		for !utf8.ValidString(s) && len(s) > 0 {
			s = s[:len(s)-1]
		}
	}
	return s
}

// Only retain the fields needed for host security monitoring. Never forward
// arbitrary journal environment fields or raw JSON.
func parseJournalLine(line []byte) (map[string]any, string, error) {
	var row map[string]any
	if err := json.Unmarshal(line, &row); err != nil {
		return nil, "", fmt.Errorf("invalid journal record: %w", err)
	}
	cursor, _ := row["__CURSOR"].(string)
	if cursor == "" || len(cursor) > 4096 {
		return nil, "", fmt.Errorf("journal record has no valid cursor")
	}
	msg := journalText(row["MESSAGE"], 2048)
	if msg == "" {
		return nil, cursor, nil
	}
	unit := journalText(row["_SYSTEMD_UNIT"], 128)
	provider := journalText(row["SYSLOG_IDENTIFIER"], 128)
	channel := provider
	if channel == "" {
		if row["_TRANSPORT"] == "audit" {
			channel = "audit"
		} else {
			channel = "journal"
		}
	}
	micros, _ := strconv.ParseInt(journalText(row["__REALTIME_TIMESTAMP"], 32), 10, 64)
	if micros <= 0 {
		return nil, "", fmt.Errorf("journal record has no valid timestamp")
	}
	ts := time.UnixMicro(micros).UTC().Format(time.RFC3339Nano)
	detail := map[string]any{
		"source": "linux_journal", "platform": "linux", "channel": channel,
		"provider": provider, "unit": unit, "message": msg,
		"priority": journalText(row["PRIORITY"], 8), "uid": journalText(row["_UID"], 32),
		"pid": journalText(row["_PID"], 32),
	}
	event := map[string]any{
		"etype": "linux_journal", "summary": "Linux journal: " + channel,
		"severity": "info", "ts": ts, "detail": detail,
	}
	return event, cursor, nil
}

// Commit the journal cursor and its telemetry in the same local transaction.
// If storage is unavailable or full, keep the old cursor for retry.
func (o *outbox) commitJournal(agentID, host string, events []map[string]any, cursor string) error {
	if o == nil || o.st == nil || o.st.path == ":memory:" {
		return fmt.Errorf("durable outbox unavailable")
	}
	if agentID == "" || cursor == "" {
		return fmt.Errorf("journal identity or cursor missing")
	}
	var raw []byte
	var err error
	if len(events) > 0 {
		stampEventsSchema(events)
		raw, err = json.Marshal(map[string]any{"agent_id": agentID, "hostname": host, "events": events})
		if err != nil {
			return err
		}
	}
	tx, err := o.st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var inserted int64
	if len(raw) > 0 {
		var rows, bytes int64
		if err := tx.QueryRow("SELECT COUNT(*), COALESCE(SUM(bytes),0) FROM outbox").Scan(&rows, &bytes); err != nil {
			return err
		}
		if rows >= outboxMaxRows || bytes+int64(len(raw)) > outboxMaxBytes {
			return fmt.Errorf("outbox capacity reached; journal cursor retained")
		}
		hash := sha256.Sum256([]byte("linux-journal-v1\x00" + cursor))
		now := time.Now().UnixMilli()
		result, err := tx.Exec(
			`INSERT OR IGNORE INTO outbox(uuid,stream,kind,priority,payload,bytes,available_at,created_at)
			 VALUES(?,?,?,?,?,?,?,?)`,
			hex.EncodeToString(hash[:]), outboxStream, string(outTimeline), 80, raw, len(raw), now, now)
		if err != nil {
			return err
		}
		inserted, err = result.RowsAffected()
		if err != nil {
			return err
		}
	}
	if _, err := tx.Exec("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", linuxJournalCursorKey, cursor); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	captureAdd("linux_journal", "cursor_confirmed", 1)
	if inserted > 0 {
		captureAdd("linux_journal", "persisted", len(events))
		o.enq.Add(inserted)
		o.mu.Lock()
		o.rows += inserted
		o.bytes += int64(len(raw))
		o.mu.Unlock()
		o.kick()
	} else if len(events) > 0 {
		captureAdd("linux_journal", "deduplicated", len(events))
	}
	return nil
}
