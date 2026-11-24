//go:build windows

package main

import "testing"

func TestDetectLateralFromCmd(t *testing.T) {
	cases := []struct {
		img, cmd string
		want     string
	}{
		{`C:\Windows\System32\schtasks.exe`, `schtasks /s \\dc01 /create /tn x /tr calc`, "T1053.005"},
		{`C:\Windows\System32\sc.exe`, `sc \\victim create evil binPath= C:\evil.exe`, "T1543.003"},
		{`wmic.exe`, `wmic /node:10.0.0.8 process call create calc.exe`, "T1047"},
		{`powershell.exe`, `Invoke-Command -ComputerName ws01 -ScriptBlock {whoami}`, "T1021.006"},
		{`C:\Tools\PsExec.exe`, `PsExec \\host -s cmd`, "T1569.002"},
		{`cmd.exe`, `copy evil.exe \\host\admin$\evil.exe`, "T1021.002"},
		{`notepad.exe`, `notepad C:\a.txt`, ""},
	}
	for _, c := range cases {
		h := detectLateralFromCmd(c.img, c.cmd)
		got := ""
		if h != nil {
			got = h.Technique
		}
		if got != c.want {
			t.Fatalf("%q %q => %q want %q", c.img, c.cmd, got, c.want)
		}
	}
}
