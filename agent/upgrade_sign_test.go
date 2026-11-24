package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestUpgradeSignRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sha := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	ver := "0.12.0"
	var size int64 = 12345
	msg := upgradeSignMessage(sha, ver, size)
	sig := ed25519.Sign(priv, msg)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	cfg := Config{UpgradePubKey: pubB64}
	params := map[string]any{"sig_ed25519": sigB64}
	if err := verifyUpgradeSignature(cfg, params, sha, ver, size); err != nil {
		t.Fatal(err)
	}
	if err := verifyUpgradeSignature(cfg, params, sha, ver, size+1); err == nil {
		t.Fatal("篡改 size 应失败")
	}
	if err := verifyUpgradeSignature(cfg, map[string]any{}, sha, ver, size); err == nil {
		t.Fatal("已钉扎公钥时无签名应拒绝")
	}
	// 未钉扎 → 一律拒绝（即使命令带 pubkey）
	if err := verifyUpgradeSignature(Config{}, map[string]any{}, sha, ver, size); err == nil {
		t.Fatal("未钉扎公钥应拒绝升级")
	}
	err = verifyUpgradeSignature(Config{}, map[string]any{
		"sig_ed25519": sigB64,
		"pubkey":      pubB64,
	}, sha, ver, size)
	if err == nil || !strings.Contains(err.Error(), "未配置升级公钥") {
		t.Fatalf("禁止命令 pubkey 作信任根，期望未配置升级公钥错误，got %v", err)
	}
}

func TestValidateUpgradeURL(t *testing.T) {
	if err := validateUpgradeURL(Config{}, "https://example.com/a.exe"); err != nil {
		t.Fatal(err)
	}
	if err := validateUpgradeURL(Config{}, "http://example.com/a.exe"); err == nil {
		t.Fatal("生产应拒绝明文 HTTP")
	}
	if err := validateUpgradeURL(Config{Insecure: true}, "http://example.com/a.exe"); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeUpgradeSHA256(t *testing.T) {
	ok := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	if _, err := normalizeUpgradeSHA256(ok); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeUpgradeSHA256("deadbeef"); err == nil {
		t.Fatal("短 hash 应拒绝")
	}
}
