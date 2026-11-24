//go:build !windows

package main

func winevtChannelDefs() []winevtChannel { return nil }

func winevtChannelManifest() []string { return nil }

type winevtChannel struct {
	ID      string
	Channel string
	XPath   string
}
