package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func parseDpkgInventory(r io.Reader, limit int) ([]any, error) {
	rows := []any{}
	fields := map[string]string{}
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		status := strings.Fields(fields["Status"])
		if fields["Package"] == "" || len(status) != 3 {
			return fmt.Errorf("incomplete dpkg record")
		}
		if status[2] == "installed" {
			if fields["Version"] == "" {
				return fmt.Errorf("missing dpkg package version")
			}
			if len(rows) < limit {
				rows = append(rows, map[string]any{"name": fields["Package"], "version": fields["Version"], "arch": fields["Architecture"]})
			}
		}
		clear(fields)
		return nil
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid dpkg field")
		}
		switch key {
		case "Package", "Version", "Architecture", "Status":
			fields[key] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return rows, nil
}
