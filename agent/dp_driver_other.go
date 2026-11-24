//go:build !windows

package main

import "context"

type dpDriver struct{}

var dpDrv = &dpDriver{}

func (d *dpDriver) applyPolicy(map[string]any)  {}
func (d *dpDriver) applyCrypto(map[string]any)  {}
func (d *dpDriver) run(context.Context, string) {}
func (d *dpDriver) drain() []map[string]any     { return nil }
func (d *dpDriver) state() (bool, string)       { return false, "unsupported" }
