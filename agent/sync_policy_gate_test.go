package main

import "testing"

func TestRejectedPolicyDoesNotAdvanceSync(t *testing.T) {
	st := memoryStateDB()
	defer st.close()
	pm := newPolicyManager(st, func(map[string]any) { t.Fatal("unverified policy applied") })
	pm.setConfig(&Config{})
	before := localSyncRev()
	applySyncBundle(&syncBundleResp{OK: true, SyncRev: before + 1, PolicyRev: 1,
		Policy: map[string]any{"response_enabled": false}}, pm, nil)
	if localSyncRev() != before {
		t.Fatal("rejected policy advanced sync revision")
	}
	parts := syncPartsSnapshot()["parts"].(map[string]any)
	if parts["policy"].(map[string]any)["ok"] != false {
		t.Fatal("rejection not reported")
	}
}
