//go:build windows

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func readSpec(t *testing.T, spec regSpec) map[string]regValue {
	t.Helper()
	root, path := regRoot(spec)
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		t.Skipf("open %s: %v", path, err)
	}
	defer k.Close()
	out := map[string]regValue{}
	readTree(k, spec.displayRoot(), spec, spec.Depth, out)
	return out
}

func TestWinsockCatalogDecodesProviderPath(t *testing.T) {
	var spec regSpec
	for _, s := range machineRegSpecs() {
		if s.ID == "winsock_proto64" {
			spec = s
		}
	}
	vals := readSpec(t, spec)
	if len(vals) == 0 {
		t.Fatal("no winsock catalog entries read")
	}
	for full, v := range vals {
		key, name := splitValuePath(full)
		p := regPayloadPath(spec, key, name, v.Data)
		if !strings.HasSuffix(strings.ToLower(p), ".dll") {
			t.Fatalf("payload not a dll: %q from %q", p, v.Data)
		}
		t.Logf("%s -> %s", name, p)
		break
	}
}

func TestHKCUCLSIDOnlyServerKeys(t *testing.T) {
	ups := userProfiles()
	if len(ups) == 0 {
		t.Skip("no user profiles")
	}
	for _, up := range ups {
		if !userHiveLoaded(up.sid) {
			continue
		}
		vals := readSpec(t, hkcuCLSID(up.sid))
		resolved := 0
		for full, v := range vals {
			key, _ := splitValuePath(full)
			if !spec0KeyLeafOK(key) {
				t.Fatalf("unexpected key %s", key)
			}
			if regPayloadPath(hkcuCLSID(up.sid), key, "", v.Data) != "" {
				resolved++
			}
		}
		t.Logf("user %s: %d HKCU CLSID server entries, %d resolved", up.name, len(vals), resolved)
	}
	t.Logf("ps profiles candidates=%d", len(psProfilePaths()))
}

func spec0KeyLeafOK(key string) bool {
	l := strings.ToLower(key)
	return strings.HasSuffix(l, `\inprocserver32`) || strings.HasSuffix(l, `\localserver32`) || strings.HasSuffix(l, `\treatas`)
}
