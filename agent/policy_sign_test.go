package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestPolicySignMessageGolden(t *testing.T) {
	// 与 backend/test_policy_sign.py::test_sign_message_golden 对齐
	want := []byte("FA-POLICY-V1\n1\n{\"heartbeat_sec\":30,\"response_enabled\":true}")
	got := policySignMessage(1, map[string]any{"heartbeat_sec": 30, "response_enabled": true})
	if !bytes.Equal(got, want) {
		t.Fatalf("message mismatch\ngot=%q\nwant=%q", got, want)
	}
}

func TestPolicySignRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pol := map[string]any{"response_enabled": true, "heartbeat_sec": 15}
	sig := ed25519.Sign(priv, policySignMessage(7, pol))
	pol["_sig"] = base64.StdEncoding.EncodeToString(sig)
	cfg := Config{PolicyPubKey: base64.StdEncoding.EncodeToString(pub)}
	if err := verifyPolicySignature(cfg, 7, pol); err != nil {
		t.Fatal(err)
	}
	pol["heartbeat_sec"] = 16
	if err := verifyPolicySignature(cfg, 7, pol); err == nil {
		t.Fatal("tampered policy must fail")
	}
}
