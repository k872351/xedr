//go:build !windows

package main

type selfProtectWatch struct{}

var spWatch = &selfProtectWatch{}

func (w *selfProtectWatch) setEmit(fn func(map[string]any)) {}

func (w *selfProtectWatch) tick() {}
