package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func collectSoftware() ([]any, error) {
	return collectSoftwareLimited(maxItems)
}

func collectSoftwareLimited(limit int) ([]any, error) {
	f, err := os.Open("/var/lib/dpkg/status")
	if os.IsNotExist(err) {
		return collectRPMSoftware(limit)
	}
	if err != nil {
		return nil, fmt.Errorf("read dpkg inventory: %w", err)
	}
	defer f.Close()
	return parseDpkgInventory(f, limit)
}

func collectRPMSoftware(limit int) ([]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read RPM inventory: %w", err)
	}
	return parseRPMInventory(strings.NewReader(string(out)), limit)
}
