package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func parseRPMInventory(r io.Reader, limit int) ([]any, error) {
	rows := []any{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[0] == "" || fields[1] == "" || fields[2] == "" {
			return nil, fmt.Errorf("invalid RPM inventory record")
		}
		if len(rows) < limit {
			rows = append(rows, map[string]any{
				"name": fields[0], "version": fields[1], "arch": fields[2],
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}
