//go:build !windows

package main

import "context"

var globalWinEvent *winEventWatcher

type winEventWatcher struct{ bookmarkDir string }

func newWinEventWatcher() *winEventWatcher             { return &winEventWatcher{} }
func (w *winEventWatcher) start(ctx context.Context)   {}
func (w *winEventWatcher) stop()                       {}
func (w *winEventWatcher) restart(ctx context.Context) {}
func (w *winEventWatcher) drain() []map[string]any     { return nil }

func winevtChannelStatsSnapshot() []map[string]any { return nil }
