package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// policyPubKeyB64 可由 -ldflags 注入；也可来自 Config.PolicyPubKey。
var policyPubKeyB64 = ""

func policySignMessage(rev int, pol map[string]any) []byte {
	clean := map[string]any{}
	for k, v := range pol {
		lk := strings.ToLower(k)
		if lk == "_sig" || lk == "sig" || lk == "sig_ed25519" || lk == "policy_sig" {
			continue
		}
		clean[k] = v
	}
	// 稳定序列化：按 key 排序的 JSON
	keys := make([]string, 0, len(clean))
	for k := range clean {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]any, len(clean))
	for _, k := range keys {
		ordered[k] = clean[k]
	}
	b, _ := json.Marshal(ordered)
	return []byte(fmt.Sprintf("FA-POLICY-V1\n%d\n%s", rev, string(b)))
}

func extractPolicySig(pol map[string]any) string {
	for _, k := range []string{"_sig", "sig_ed25519", "policy_sig", "sig"} {
		if s := strings.TrimSpace(fmt.Sprint(pol[k])); s != "" && s != "<nil>" {
			return s
		}
	}
	return ""
}

func pinnedPolicyPubKeys(cfg Config) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, c := range []string{policyPubKeyB64, cfg.PolicyPubKey} {
		if pk, err := parseEd25519Pub(c); err == nil {
			out = append(out, pk)
		}
	}
	return out
}

// verifyPolicySignature：生产默认与升级信任对齐——必须钉扎策略公钥并验签。
// 仅 cfg.Insecure（调试）允许无公钥时接受无签名策略。
func verifyPolicySignature(cfg Config, rev int, pol map[string]any) error {
	if pol == nil {
		return fmt.Errorf("空策略")
	}
	sigB64 := extractPolicySig(pol)
	pks := pinnedPolicyPubKeys(cfg)
	if len(pks) == 0 {
		if cfg.Insecure {
			return nil
		}
		return fmt.Errorf("未配置策略公钥，拒绝策略（生产默认强制验签；调试可设 insecure_skip_verify）")
	}
	if sigB64 == "" {
		return fmt.Errorf("策略缺少 Ed25519 签名")
	}
	raw, err := decodeSig(sigB64)
	if err != nil {
		return err
	}
	msg := policySignMessage(rev, pol)
	for _, pk := range pks {
		if ed25519.Verify(pk, msg, raw) {
			return nil
		}
	}
	return fmt.Errorf("策略签名校验失败")
}

func decodeSig(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	var raw []byte
	var err error
	if strings.HasPrefix(s, "hex:") {
		raw, err = hex.DecodeString(strings.TrimPrefix(s, "hex:"))
	} else {
		raw, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(s)
		}
		if err != nil {
			raw, err = hex.DecodeString(s)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("签名解码失败: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("签名长度 %d，期望 %d", len(raw), ed25519.SignatureSize)
	}
	return raw, nil
}
