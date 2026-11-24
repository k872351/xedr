package main

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestDPMessageHeader(t *testing.T) {
	m := dpMessage(dpCmdSetThreatPolicy, dpPolicyStruct(24, dpThreatFlagsAudit))
	if len(m) != dpMsgHeaderLen+24 {
		t.Fatalf("len %d", len(m))
	}
	if binary.LittleEndian.Uint32(m[0:4]) != 1 || binary.LittleEndian.Uint32(m[4:8]) != dpCmdSetThreatPolicy ||
		binary.LittleEndian.Uint32(m[8:12]) != 24 {
		t.Fatal("bad header")
	}
	if binary.LittleEndian.Uint32(m[16:20]) != 1 || binary.LittleEndian.Uint32(m[20:24]) != dpThreatFlagsAudit {
		t.Fatal("bad policy body")
	}
}

func TestDPCryptoKeysEncoding(t *testing.T) {
	k1 := make([]byte, 32)
	k1[0] = 0xAA
	ring, err := parseDPCrypto(map[string]any{
		"active_key_id": float64(2),
		"keys": []any{
			map[string]any{"id": float64(2), "key": base64.StdEncoding.EncodeToString(k1)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := encodeDPCryptoKeys(ring)
	if len(b) != 16+8*36 {
		t.Fatalf("DP_CRYPTO_KEYS size %d", len(b))
	}
	if binary.LittleEndian.Uint32(b[4:8]) != 1 || binary.LittleEndian.Uint32(b[8:12]) != 2 ||
		binary.LittleEndian.Uint32(b[16:20]) != 2 || b[20] != 0xAA {
		t.Fatal("bad key ring encoding")
	}
	if _, err := parseDPCrypto(map[string]any{"active_key_id": float64(9), "keys": []any{
		map[string]any{"id": float64(2), "key": base64.StdEncoding.EncodeToString(k1)},
	}}); err == nil {
		t.Fatal("active key outside ring accepted")
	}
}

func TestParseDPThreatEvents(t *testing.T) {
	buf := make([]byte, dpThreatHeaderLen+dpThreatEntryLen)
	binary.LittleEndian.PutUint32(buf[4:8], 1)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(buf)))
	e := buf[dpThreatHeaderLen:]
	binary.LittleEndian.PutUint64(e[8:], 133000000000000000) // 2022-ish FILETIME
	binary.LittleEndian.PutUint64(e[16:], 4242)
	binary.LittleEndian.PutUint32(e[40:], 10) // LSASS handle access
	binary.LittleEndian.PutUint32(e[44:], 5)  // credential access
	binary.LittleEndian.PutUint32(e[48:], 1003)
	binary.LittleEndian.PutUint32(e[60:], 3)
	img := utf16.Encode([]rune(`\Device\HarddiskVolume3\Tools\mimikatz.exe`))
	for i, c := range img {
		binary.LittleEndian.PutUint16(e[dpThreatImageOff+i*2:], c)
	}
	binary.LittleEndian.PutUint32(e[72:], uint32(len(img)*2))

	evs, err := parseDPThreatEvents(buf)
	if err != nil || len(evs) != 1 {
		t.Fatalf("parse: %v %d", err, len(evs))
	}
	d := evs[0]["detail"].(map[string]any)
	if evs[0]["severity"] != "high" || d["technique"] != "T1003" || d["process_name"] != "mimikatz.exe" ||
		d["pid"] != uint64(4242) || d["tactic_name"] != "凭据访问" {
		t.Fatalf("unexpected event: %#v", evs[0])
	}
}
