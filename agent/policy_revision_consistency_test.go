package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestPolicyRevisionConsistency(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	st := memoryStateDB()
	defer st.close()
	pm := newPolicyManager(st, func(map[string]any) {})
	pm.setConfig(&Config{PolicyPubKey: base64.StdEncoding.EncodeToString(pub)})
	p := map[string]any{"response_enabled": false}
	p["_sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, policySignMessage(1, p)))
	if !pm.offer(1, p) || !pm.offer(1, p) {
		t.Fatal("valid policy not accepted")
	}
	changed := map[string]any{"response_enabled": true}
	changed["_sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, policySignMessage(1, changed)))
	if pm.offer(1, changed) {
		t.Fatal("same revision with differing content accepted")
	}
}

func TestStoredPolicyRequiresVerification(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	st := memoryStateDB()
	defer st.close()
	applied := 0
	pm := newPolicyManager(st, func(map[string]any) { applied++ })
	pm.setConfig(&Config{PolicyPubKey: base64.StdEncoding.EncodeToString(pub)})
	pm.saveDoc(kvPolicyLKG, &policyDoc{Rev: 1, Policy: map[string]any{"response_enabled": false}})
	pm.saveDoc(kvPolicyPending, &policyDoc{Rev: 2, Policy: map[string]any{"response_enabled": false}})
	pm.boot()
	if applied != 0 || pm.applied != 0 || pm.lkg != nil {
		t.Fatal("unverified stored policy applied")
	}
}
