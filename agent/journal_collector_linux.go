//go:build linux

package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Poll journalctl with bounded work, a fixed local security-log scope, and a
// durable cursor. It does not alter the system journal or run log contents.
func startPlatformJournal(ctx context.Context, box *outbox, aid func() string) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if integrationEnabled("linux_journal") {
				finish := beginComponentWork("linux_journal")
				err := pollLinuxJournal(ctx, box, aid())
				finish()
				if ctx.Err() == nil {
					if err != nil {
						recordComponentObservation("linux_journal", cStateDegraded, err.Error())
					} else {
						recordComponentObservation("linux_journal", cStateHealthy, "journal read and durable cursor check completed")
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func pollLinuxJournal(ctx context.Context, box *outbox, agentID string) error {
	if box == nil || box.st == nil || box.st.path == ":memory:" {
		return fmt.Errorf("durable outbox unavailable")
	}
	var cursor string
	err := box.st.db.QueryRow("SELECT v FROM kv WHERE k=?", linuxJournalCursorKey).Scan(&cursor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		captureAdd("linux_journal", "cursor_read_failed", 1)
		return fmt.Errorf("journal cursor read failed")
	}
	args := []string{"--no-pager", "--output=json"}
	if cursor == "" {
		args = append(args, "--since=-5min")
	} else {
		args = append(args, "--after-cursor="+cursor)
	}
	args = append(args, "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session",
		"SYSLOG_IDENTIFIER=sudo", "SYSLOG_IDENTIFIER=systemd", "SYSLOG_IDENTIFIER=cron",
		"SYSLOG_IDENTIFIER=CRON", "SYSLOG_IDENTIFIER=audit", "SYSLOG_IDENTIFIER=useradd",
		"+", "_TRANSPORT=audit")
	readCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(readCtx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		captureAdd("linux_journal", "read_failed", 1)
		return fmt.Errorf("journal stream unavailable: %w", err)
	}
	if err := cmd.Start(); err != nil {
		captureAdd("linux_journal", "read_failed", 1)
		return fmt.Errorf("journalctl unavailable: %w", err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 16<<10), 1<<20)
	var events []map[string]any
	last := ""
	count := 0
	var parseErr error
	for scanner.Scan() {
		captureAdd("linux_journal", "received", 1)
		event, next, err := parseJournalLine(scanner.Bytes())
		if err != nil {
			captureAdd("linux_journal", "parse_failed", 1)
			parseErr = err
			break
		}
		last = next
		count++
		if event != nil {
			events = append(events, event)
		} else {
			captureAdd("linux_journal", "filtered", 1)
		}
		if count >= 64 {
			break
		}
	}
	scanErr := scanner.Err()
	bounded := count >= 64
	if bounded {
		captureAdd("linux_journal", "budget_limited_polls", 1)
	}
	if bounded || parseErr != nil || scanErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if parseErr != nil {
		captureAdd("linux_journal", "durability_unconfirmed", len(events))
		return parseErr
	}
	if scanErr != nil {
		captureAdd("linux_journal", "read_failed", 1)
		captureAdd("linux_journal", "durability_unconfirmed", len(events))
		return fmt.Errorf("journal read failed: %w", scanErr)
	}
	if waitErr != nil && !bounded {
		captureAdd("linux_journal", "read_failed", 1)
		captureAdd("linux_journal", "durability_unconfirmed", len(events))
		return fmt.Errorf("journalctl read failed; check access and saved cursor")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if last == "" {
		return nil
	}
	err = box.commitJournal(agentID, hostname(), events, last)
	if err != nil {
		captureAdd("linux_journal", "durability_unconfirmed", len(events))
		captureAdd("linux_journal", "cursor_commit_failed", 1)
	}
	return err
}
