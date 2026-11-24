//go:build !windows && !linux

package main

import "errors"

func collectSoftware() ([]any, error) {
	return collectSoftwareLimited(maxItems)
}

func collectSoftwareLimited(_ int) ([]any, error) {
	return nil, errors.New("software inventory unsupported on this platform")
}
