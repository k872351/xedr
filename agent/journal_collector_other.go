//go:build !linux

package main

import "context"

func startPlatformJournal(context.Context, *outbox, func() string) {}
