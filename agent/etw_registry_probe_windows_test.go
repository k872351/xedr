//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

// 用 reg.exe 子进程改注册表，验证 Kernel-Registry ETW 能把变更归到 reg.exe 的 PID。
func TestRegistryWriterAttribution(t *testing.T) {
	if os.Getenv("EDR_ETW_PROBE") != "1" {
		t.Skip("set EDR_ETW_PROBE=1（需要管理员）")
	}
	s := etw.NewRealTimeSession("EDRRegAttrTest")
	defer s.Stop()
	if err := s.EnableProvider(etw.Provider{GUID: guidKernelRegistry.String(), EnableLevel: 0xff, MatchAnyKeyword: regETWKeywords}); err != nil {
		t.Fatal(err)
	}
	if err := setETWFlushTimer("EDRRegAttrTest", 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := etw.NewRealTimeConsumer(ctx)
	c.FromSessions(s)
	c.EventRecordCallback = func(er *etw.EventRecord) bool {
		return er.EventHeader.ProviderId.Equals(guidKernelRegistry) && regETWWantIDs[er.EventHeader.EventDescriptor.Id]
	}
	c.PreparedCallback = func(h *etw.EventRecordHelper) error {
		regETW.onPrepared(h)
		return nil
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	regETW.active.Store(true)
	defer regETW.active.Store(false)
	time.Sleep(1500 * time.Millisecond)

	key := `HKCU\Software\EDRRegAttrTest`
	add := exec.Command("reg.exe", "add", key, "/v", "EDRProbeVal", "/t", "REG_SZ", "/d", `C:\Users\Public\x.exe`, "/f")
	if err := add.Run(); err != nil {
		t.Fatal(err)
	}
	addPID := uint32(add.ProcessState.Pid())
	defer exec.Command("reg.exe", "delete", key, "/f").Run()

	sid := currentUserSID(t)
	a, ok := regETW.attribute(`HKU\`+sid+`\Software\EDRRegAttrTest`, "EDRProbeVal", "add")
	if !ok {
		time.Sleep(3 * time.Second)
		regETW.mu.Lock()
		total := regETW.next
		for i := 0; i < regETW.next; i++ {
			w := regETW.ring[i]
			if w.pid == addPID {
				t.Logf("ring: op=%d pid=%d vn=%q rel=%q obj=%s at=%s", w.op, w.pid, w.valueName, w.relName, w.keyObj, w.at.Format("15:04:05.000"))
			}
		}
		regETW.mu.Unlock()
		t.Fatalf("no attribution; ring=%d now=%s", total, time.Now().Format("15:04:05.000"))
	}
	t.Logf("attributed pid=%d (reg.exe pid=%d) confidence=%s", a.pid, addPID, a.confidence)
	if a.pid != addPID {
		t.Fatalf("want pid %d got %d", addPID, a.pid)
	}
	if a.confidence != "etw_exact" {
		t.Errorf("want etw_exact, got %s", a.confidence)
	}
}

func currentUserSID(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("whoami", "/user", "/fo", "csv", "/nh").Output()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	i := len(s) - 1
	for i >= 0 && (s[i] == '\r' || s[i] == '\n' || s[i] == '"') {
		i--
	}
	j := i
	for j >= 0 && s[j] != '"' {
		j--
	}
	return s[j+1 : i+1]
}
