//go:build !windows && !linux

package main

import "context"

func startRootcheckLoop(ctx context.Context, box *outbox, aid func() string) {}
