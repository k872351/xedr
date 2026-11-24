package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestOfferRejectDoesNotAllowSideEffects(t *testing.T) {
	st := memoryStateDB()
	var applied int
	pm := newPolicyManager(st, func(p map[string]any) { applied++ })

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pm.setConfig(&Config{PolicyPubKey: base64.StdEncoding.EncodeToString(pub)})

	// 已钉扎公钥但策略无签名 → 拒绝
	if pm.offer(1, map[string]any{"response_enabled": true, "heartbeat_sec": 30}) {
		t.Fatal("未签名策略应被拒绝")
	}
	if applied != 0 {
		t.Fatalf("拒签后不得 safeApply，applied=%d", applied)
	}
	// 模拟 sync/heartbeat 调用约定：仅 offer==true 才副作用
	side := 0
	pol := map[string]any{"response_enabled": false}
	if pm.offer(2, pol) {
		side++
	}
	if side != 0 || applied != 0 {
		t.Fatalf("拒签后副作用计数应仍为 0，side=%d applied=%d", side, applied)
	}
}

func TestOfferAcceptAllowsSideEffects(t *testing.T) {
	st := memoryStateDB()
	var applied int
	pm := newPolicyManager(st, func(p map[string]any) { applied++ })
	// 生产默认：未钉扎策略公钥应拒绝；调试 Insecure 才放行
	pm.setConfig(&Config{})
	if pm.offer(1, map[string]any{"response_enabled": true, "heartbeat_sec": 30}) {
		t.Fatal("生产默认未钉扎策略公钥应拒绝")
	}
	pm.setConfig(&Config{Insecure: true})
	// 换新 rev：rev=1 已被记入 bad
	if !pm.offer(2, map[string]any{"response_enabled": true, "heartbeat_sec": 30}) {
		t.Fatal("Insecure 调试模式应接受无签名策略")
	}
	if applied != 1 {
		t.Fatalf("接受后应 safeApply，applied=%d", applied)
	}
	// 同 rev 再次 offer → true，但不重复 apply
	if !pm.offer(2, map[string]any{"response_enabled": true, "heartbeat_sec": 30}) {
		t.Fatal("已应用 rev 应返回 true 以允许心跳 patch")
	}
	if applied != 1 {
		t.Fatalf("同 rev 不应重复 safeApply，applied=%d", applied)
	}
}

func TestCmdSchedulerSameGroupMutex(t *testing.T) {
	if !cmdSchedulerTry("upgrade") {
		t.Fatal("第一次 upgrade 应成功")
	}
	if cmdSchedulerTry("uninstall_agent") {
		t.Fatal("同组 maintenance 应互斥")
	}
	if cmdSchedulerTry("upgrade") {
		t.Fatal("同 action 组应互斥")
	}
	cmdSchedulerDone("upgrade")
	if !cmdSchedulerTry("uninstall_agent") {
		t.Fatal("释放后应可调度")
	}
	cmdSchedulerDone("uninstall_agent")
}

func TestNonIdempotentIncludesIsolate(t *testing.T) {
	if !nonIdempotentAction("isolate_network") || !nonIdempotentAction("unisolate_network") {
		t.Fatal("isolate/unisolate 必须非幂等")
	}
}
