package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// runAgent 注册后按周期采集并实时回传，直到 ctx 取消。
func runAgent(ctx context.Context, cfg Config, cfgPath string) error {
	_ = ensureDir(cfg.StateDir)
	setupFileLog(cfg.StateDir)
	ensureAgentKeepalive()
	checkUpgradeWatchdog(cfg)

	api := newClient(cfg)
	tl := newTimelineWatcher()
	box := newOutbox(cfg.StateDir)
	globalCfg = cfg
	globalAPI = api
	loadEmbeddedMemoryRules()
	loadEmbeddedEVM()
	go func() { _ = syncMemoryYaraRules(memoryScanSettingsSnapshot().RulesRev) }()
	eventThrottle := newEventThrottle()
	inv := newInventory(box.st)
	var deltaCap atomic.Bool
	box.onReject = func(kind outboxKind, payload map[string]any, msg string) {
		if kind == outSnapshotDelta || kind == outSnapshot {
			mod := asString(payload["module"])
			gen, _ := strconv.ParseInt(asString(payload["generation"]), 10, 64)
			log.Printf("[%s] 清单 generation=%d 被拒（%s），下一轮发全量", mod, gen, msg)
			inv.invalidate(mod, gen)
		}
	}
	setProtectStateDir(cfg.StateDir)
	// 先启原生 ETW：成功则不再拉 WMI PowerShell 进程监控（否则双重采集 + 每进程 SHA256 会拖死测试机）
	etw := newETWWatcher()
	if runtime.GOOS == "windows" {
		recordComponentObservation("etw", cStateStarting, "ETW sensor initialization in progress")
	}
	etw.start(ctx)
	defer etw.stop()
	if runtime.GOOS == "windows" {
		setSensorPipeline("starting", "winevent", "")
	} else if runtime.GOOS == "linux" {
		setSensorPipeline("linux_inventory", "linux_journal", "")
	} else {
		setSensorPipeline("inventory_only", "unsupported", "")
	}
	startSensorHealLoop(ctx, etw)
	etwMode := etw.waitMode(4 * time.Second)
	if etwMode == "etw_native" || etwMode == "etw_evt" {
		recordComponentObservation("etw", cStateHealthy, etwMode)
	} else if etwMode != "stopped" && etwMode != "" {
		recordComponentObservation("etw", cStateDegraded, etwMode)
	} else if runtime.GOOS == "windows" {
		recordComponentObservation("etw", cStateFailed, "ETW sensor did not start")
	}
	captureETWStatusFn = func() (string, bool) {
		m := etw.status()
		return m, m == "etw_native" || m == "etw_evt"
	}
	startCmdBackfillLoop(ctx)
	watch := newProcessWatcher()
	wmiProc := runtime.GOOS == "windows" && (etwMode != "etw_native" || integrationEnabled("wmi_process"))
	if wmiProc {
		recordComponentObservation("wmi_process", cStateStarting, "process watcher initialization in progress")
		watch.start(ctx)
		log.Printf("process watcher: ETW=%s，WMI 进程监控=%v", etwMode, integrationEnabled("wmi_process") || etwMode != "etw_native")
	} else if runtime.GOOS == "windows" {
		log.Printf("process watcher: ETW 原生已接管，跳过 WMI")
	}
	defer watch.stop()
	// 在 winevent 订阅前尽量装好 Sysmon，否则会跳过 Sysmon 通道。
	// busy 时再试一次：安装器后台 ensure 可能刚占用互斥锁。
	for attempt := 0; runtime.GOOS == "windows" && attempt < 2; attempt++ {
		st := ensureSysmonManaged(api)
		if st == nil {
			break
		}
		log.Printf("sysmon ensure[#%d]: action=%v present=%v installed=%v err=%v",
			attempt+1, st["action"], st["present"], st["installed"], st["error"])
		act, _ := st["action"].(string)
		if act != "busy" {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(8 * time.Second):
		}
	}
	// winevent 延后启动，避免与 ETW/注册/首轮采集抢 CPU
	logTailGlobal = newLogTailWatcher()
	logTailGlobal.start(ctx)
	wevt := newWinEventWatcher()
	wevt.bookmarkDir = filepath.Join(cfg.StateDir, "bookmarks")
	globalWinEvent = wevt
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}
		wevt.start(ctx)
	}()
	defer wevt.stop()
	// Sysmon 自愈：被停止/卸载/配置被改后自动恢复，无需人工介入
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			st := ensureSysmonManaged(api)
			if act, _ := st["action"].(string); act == "installed" || act == "config_updated" {
				// 清 Sysmon 书签以触发 catch-up，避免「已装但时间线无 EventID」
				if dir := wevt.bookmarkDir; dir != "" {
					_ = os.Remove(filepath.Join(dir, "sysmon.xml"))
				}
				wevt.restart(ctx)
			}
		}
	}()
	persist := newPersistWatcher()
	wmiPersist := newWMIPersistWatcher()
	wmiPersist.start(ctx)
	regw := newRegWatcher(box.st)
	globalRegWatcher = regw
	regOn := regw.start(ctx)
	if regOn {
		recordComponentObservation("registry", cStateHealthy, "registry change watcher active")
	} else if integrationEnabled("registry") {
		recordComponentObservation("registry", cStateDegraded, "registry realtime watcher unavailable; polling remains available")
	}
	applyRegistryFIMSync(regw)
	defer regw.stop()
	persist.setRegistryRealtime(regOn)
	go persist.startLoop(ctx)
	fim := newFIMWatcher(box.st, cfg.StateDir)
	defer fim.stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				procEntities.gc(livePIDSet())
			}
		}
	}()
	kern := newKernelWatcher()
	kernelOn := kern.start(ctx)
	defer kern.stop()
	go dpDrv.run(ctx, cfg.StateDir)
	devw := newDeviceWatcher()
	if integrationEnabled("device") {
		devw.start(ctx)
	}
	// 原生 ETW 已覆盖进程/网络/文件落地，关掉 6 秒一轮的快照差分（否则反复 PowerShell 验签/扫盘）
	if etwMode == "etw_native" {
		tl.setEnabled(false)
		tl.setFileEnabled(false)
		tl.setNetEnabled(false)
		log.Printf("timeline snapshot-diff: 已关闭（由 ETW/FIM 接管）")
	}
	sensor := platformSensorMode(runtime.GOOS, wmiProc, kernelOn)

	hn := hostname()
	ip := primaryIP()
	log.Printf("forensic-agent %s  host=%s ip=%s → %s (outbox=%d sensor=%s)", agentVersion, hn, ip, cfg.ServerURL, box.pending(), sensor)

	box.cmdPurge()
	health := newHealthCollector()
	health.sensorsFn = func() map[string]any {
		if runtime.GOOS == "linux" {
			secondary := "disabled"
			if integrationEnabled("linux_journal") {
				secondary = "linux_journal"
			}
			setSensorPipeline("linux_inventory", secondary, "")
		}
		// Only publish HEALTHY when the runtime exposes a positive active signal.
		// Lack of an active signal remains UNKNOWN instead of inferring success from policy.
		if wmiProc && watch.activeNow() {
			recordComponentObservation("wmi_process", cStateHealthy, "WMI process event watcher active")
		}
		if fim.running() {
			recordComponentObservation("fim", cStateHealthy, "file integrity watcher active")
		}
		if regw.running() {
			recordComponentObservation("registry", cStateHealthy, "registry change watcher active")
		}
		s := map[string]any{
			"etw": etw.status(), "kernel": kernelOn, "mode": sensor,
			"registry_realtime": regOn, "fim": fim.running(), "entities": procEntities.size(),
			"entities_rev":         procEntities.revision(),
			"capture_status":       captureStatusSnapshot(),
			"components":           componentHealthSnapshot(),
			"inventory_components": inventoryComponentHealthSnapshot(cfg.Modules),
			"telemetry":            telemetryMetricsSnapshot(),
			"sensor_pipeline":      sensorPipelineSnapshot(),
			"winevent_channels":    len(winevtChannelDefsFiltered()),
			"winevent_manifest":    winevtChannelManifest(),
			"winevent_stats":       winevtChannelStatsSnapshot(),
			"host_metrics":         hostMetricsSnapshot(),
			"live_query_tables":    liveQueryManifest(),
			"elastic_parity":       elasticParitySnapshot(),
			"dynamic_fim":          dynamicFIMCount(),
		}
		s["capture_health"] = computeCaptureHealthScore(s)
		return s
	}
	health.authMode = func() string {
		if s, _ := api.credential(); s != "" {
			return "agent_secret"
		}
		return "shared_key"
	}
	protoSelected := 1
	health.protoFn = func() int { return protoSelected }

	// 模块采集与差分时间线在独立 goroutine 里跑（单个模块可能耗时数十秒），
	// 主循环只负责心跳/命令/实时传感器转发；共享的周期与 agent_id 用锁保护。
	var ivMu, aidMu sync.Mutex
	setIv := func(k string, v int) {
		ivMu.Lock()
		cfg.Intervals[k] = v
		ivMu.Unlock()
	}
	ivOf := func(mod string) time.Duration {
		ivMu.Lock()
		defer ivMu.Unlock()
		return cfg.interval(mod)
	}
	aidNow := func() string {
		aidMu.Lock()
		defer aidMu.Unlock()
		return cfg.AgentID
	}

	// 已有独立凭据则优先使用；失效（换机/吊销/轮换丢失）时回落共享密钥重新注册
	if cfg.Secret != "" && cfg.AgentID != "" {
		api.setCredential(cfg.Secret, cfg.AgentID)
	}
	// 凭据被服务端拒绝：丢弃本地凭据，改用共享密钥重新换取
	dropSecret := func(why error) {
		log.Printf("独立凭据被拒绝（%v），回落共享密钥重新注册", why)
		api.setCredential("", "")
		cfg.Secret, cfg.SecretBlob = "", ""
		if cfgPath != "" {
			_ = cfg.saveAgentID(cfgPath)
		}
	}
	// 注册成功后接收服务端新签发的凭据：DPAPI 加密落盘并立即启用
	adoptRegistration := func(r *registerResp) {
		aidMu.Lock()
		cfg.AgentID = r.AgentID
		aidMu.Unlock()
		protoSelected = r.ProtocolSelected
		if r.Warning != "" {
			log.Printf("协议告警: %s", r.Warning)
		}
		if r.AgentSecret != "" {
			if blob, err := protectSecret(r.AgentSecret); err == nil {
				cfg.Secret, cfg.SecretBlob = r.AgentSecret, blob
				api.setCredential(r.AgentSecret, r.AgentID)
				if cfgPath != "" {
					if e := cfg.saveAgentID(cfgPath); e != nil {
						log.Printf("保存独立凭据失败: %v", e)
					}
				}
				log.Printf("已获得独立凭据（DPAPI 保护）")
			} else {
				log.Printf("凭据加密失败，本次仍使用共享密钥: %v", err)
			}
		} else if cfg.Secret != "" {
			api.setCredential(cfg.Secret, r.AgentID)
		}
		useV2 := r.ProtocolSelected >= 2 && hasCap(r.EnabledCaps, "ingest.v2")
		box.useV2.Store(useV2)
		deltaCap.Store(useV2 && hasCap(r.EnabledCaps, "inventory.delta"))
		box.snapshotParts.Store(useV2 && hasCap(r.EnabledCaps, "inventory.parts.v1"))
		box.softwareExtended.Store(useV2 && hasCap(r.EnabledCaps, "inventory.parts.v1") && hasCap(r.EnabledCaps, "inventory.software.extended.v1"))
		box.softwarePaged.Store(useV2 && hasCap(r.EnabledCaps, "inventory.parts.v1") && hasCap(r.EnabledCaps, "inventory.software.paged.v1"))
		box.assetsPaged.Store(useV2 && hasCap(r.EnabledCaps, "inventory.parts.v1") && hasCap(r.EnabledCaps, "inventory.assets.paged.v1"))
		box.usersPaged.Store(useV2 && hasCap(r.EnabledCaps, "inventory.parts.v1") && hasCap(r.EnabledCaps, "inventory.user.paged.v1"))
		if b, err := json.Marshal(map[string]any{"proto": r.ProtocolSelected, "caps": r.EnabledCaps}); err == nil {
			box.st.kvSet("negotiated", string(b))
		}
	}
	// cachedRegistration 服务端不可达时用上次协商结果离线启动（采集照常落 outbox，联网后补发）
	cachedRegistration := func() *registerResp {
		if cfg.AgentID == "" || cfg.Once {
			return nil
		}
		var n struct {
			Proto int      `json:"proto"`
			Caps  []string `json:"caps"`
		}
		if json.Unmarshal([]byte(box.st.kvGet("negotiated")), &n) != nil {
			return nil
		}
		return &registerResp{AgentID: cfg.AgentID, ProtocolSelected: n.Proto, EnabledCaps: n.Caps}
	}
	offline := false

	var reg *registerResp
	backoff := 3 * time.Second
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		r, err := api.Register(hn, osFamily(), primaryIP(), agentVersion, cfg.AgentID)
		if err != nil && isAuthError(err) {
			if s, _ := api.credential(); s != "" {
				dropSecret(err)
				continue
			}
		}
		if err == nil && r != nil && r.AgentID != "" {
			reg = r
			break
		}
		if c := cachedRegistration(); c != nil && !isAuthError(err) {
			log.Printf("服务端不可达（%v），以缓存身份 %s 离线启动，联网后补注册", err, c.AgentID)
			reg, offline = c, true
			break
		}
		log.Printf("register 重试中: %v（%s 后再试）", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 2*time.Minute {
			backoff *= 2
		}
	}
	adoptRegistration(reg)
	if cfgPath != "" {
		_ = cfg.saveAgentID(cfgPath)
	}
	log.Printf("registered agent_id=%s modules=%v build=%s protocol=%d v2=%v server_caps=%v",
		cfg.AgentID, cfg.Modules, buildID, reg.ProtocolSelected, box.useV2.Load(), reg.ServerCaps)
	if !cfg.Once {
		go box.run(ctx, api)
		startPlatformJournal(ctx, box, aidNow)
	}

	for k, v := range reg.IntervalsSec {
		if v > 0 {
			setIv(k, v)
		}
	}

	refreshCh := make(chan struct{}, 1)
	// 有界慢车道：心跳/同步/命令_OFFLOAD。快车道只记要与更新，慢任务单 worker 串行执行。
	slow := newSlowLane(4)
	// responseEnabled 由心跳/同步路径写、命令与实时管道读；用原子避免慢车道引入数据竞争
	var responseEnabled atomic.Bool
	responseEnabled.Store(true)
	fimWanted, fimPaths := true, []string(nil)
	var ruleFIMPaths []string
	fimApplied := ""
	// fimMu 保护 FIM 策略配置：applyPolicy（快车道）与 sync bundle（慢车道）都会改
	var fimMu sync.Mutex

	// syncFIM 按策略启停 FIM；自定义目录或规则目录变化时重启监控
	syncFIM := func() {
		if cfg.Once {
			return
		}
		fimMu.Lock()
		defer fimMu.Unlock()
		fimEnabled := fimWanted && integrationEnabled("fim")
		dyn := snapshotDynamicFIMPaths()
		all := append(append(append([]string(nil), fimPaths...), ruleFIMPaths...), dyn...)
		want := fmt.Sprintf("%v|%s", fimEnabled, strings.Join(all, ";"))
		if want == fimApplied {
			return
		}
		fimApplied = want
		if fim.running() {
			recordComponentObservation("fim", cStateConfiguring, "restarting file integrity watcher with updated paths")
			fim.stop()
		}
		if fimEnabled {
			fim.setExtra(all)
			recordComponentObservation("fim", cStateStarting, "file integrity watcher initialization in progress")
			fim.start(ctx)
			if fim.running() {
				recordComponentObservation("fim", cStateHealthy, "file integrity watcher active")
			} else {
				recordComponentObservation("fim", cStateDegraded, "file integrity watcher did not become active")
			}
		} else {
			message := "file integrity monitoring disabled by policy"
			if fimWanted && !integrationEnabled("fim") {
				message = "file integrity sensor disabled by integration policy"
			}
			recordComponentObservation("fim", cStateStopped, message)
		}
	}

	applyPolicy := func(pol map[string]any, rev int) {
		if pol == nil {
			return
		}
		setAppliedPolicy(pol)
		fimMu.Lock()
		if v, ok := pol["fim_enabled"].(bool); ok {
			fimWanted = v
		}
		if arr, ok := pol["fim_paths"].([]any); ok {
			fimPaths = nil
			for _, x := range arr {
				if s := strings.TrimSpace(asString(x)); s != "" {
					fimPaths = append(fimPaths, s)
				}
			}
		}
		fimMu.Unlock()
		if arr, ok := pol["fim_web_roots"].([]any); ok {
			roots := make([]string, 0, len(arr))
			for _, x := range arr {
				if s := strings.TrimSpace(asString(x)); s != "" {
					roots = append(roots, s)
				}
			}
			applyFIMWebRoots(roots)
		}
		if iv, ok := pol["intervals_sec"].(map[string]any); ok {
			for k, v := range iv {
				switch n := v.(type) {
				case float64:
					if n > 0 {
						setIv(k, int(n))
					}
				case int:
					if n > 0 {
						setIv(k, n)
					}
				}
			}
		}
		if v, ok := pol["response_enabled"].(bool); ok {
			responseEnabled.Store(v)
		}
		applyRemoteOpsPolicy(pol)
		if v, ok := pol["timeline_process"].(bool); ok {
			tl.setEnabled(v)
		}
		if v, ok := pol["timeline_file"].(bool); ok {
			tl.setFileEnabled(v)
		}
		if v, ok := pol["timeline_network"].(bool); ok {
			tl.setNetEnabled(v)
		}
		if v, ok := pol["self_protect"].(bool); ok {
			setSelfProtect(v)
			if kern.active() {
				pid := uint32(0)
				if v {
					pid = uint32(os.Getpid())
				}
				if err := kern.protectSelf(pid); err != nil {
					log.Printf("kernel protect: %v", err)
				}
			}
		}
		applyMemoryScanPolicy(pol)
		applyDropScanPolicy(pol)
		applyIntegrationsPolicy(pol)
		applyLogTailPolicy(pol)
		applyWineventChannelsPolicy(pol)
		// 策略开启托管时补装/刷新 Sysmon，并重订 winevent 通道
		if sysmonManagedEnabled() {
			go func() {
				st := ensureSysmonManaged(api)
				if st != nil && (st["action"] == "installed" || st["action"] == "config_updated") {
					if globalWinEvent != nil {
						if dir := globalWinEvent.bookmarkDir; dir != "" {
							_ = os.Remove(filepath.Join(dir, "sysmon.xml"))
						}
						globalWinEvent.restart(ctx)
					}
				}
			}()
		}
	}
	ruleFIMSyncFn = func(paths []string) {
		fimMu.Lock()
		setRuleFIMPathsFromSync(paths, &ruleFIMPaths)
		fimMu.Unlock()
	}

	// 所有上行数据一律先落盘 outbox，再由后台发送器批量投递（崩溃/断网都不丢）
	ackReliable := func(id string, ok bool, result map[string]any) {
		queueHeartbeatAck(id, ok, result)
		box.enqueue(outAck, 100, map[string]any{"id": id, "ok": ok, "result": result})
	}

	pushTimeline := func(events []map[string]any) {
		events = filterTimelineEvents(events)
		if len(events) == 0 {
			return
		}
		annotateEntities(events)
		enrichTimelineEventsECS(events)
		stampEventsSchema(events)
		raw := make([]any, 0, len(events))
		bySource := map[string]int{}
		var acknowledgements []func()
		for _, e := range events {
			if source, ok := e[qualitySourceKey].(string); ok {
				bySource[source]++
			}
			delete(e, qualitySourceKey)
			if ack, ok := e[bookmarkAckKey].(func()); ok {
				acknowledgements = append(acknowledgements, ack)
			}
			delete(e, bookmarkAckKey)
			raw = append(raw, e)
		}
		beforeDrops := box.dropped.Load()
		committed := box.enqueue(outTimeline, 80, map[string]any{
			"agent_id": aidNow(), "hostname": hostname(), "events": raw,
		})
		durable := committed && box.st != nil && box.st.path != ":memory:" && box.dropped.Load() == beforeDrops
		for source, count := range bySource {
			if durable {
				captureAdd(source, "persisted", count)
			} else {
				captureAdd(source, "durability_unconfirmed", count)
			}
		}
		if durable {
			for _, ack := range acknowledgements {
				ack()
			}
		}
	}
	spWatch.setEmit(func(ev map[string]any) {
		if ev == nil {
			return
		}
		pushTimeline([]map[string]any{ev})
	})

	responseEvent := func(sev, title, detail string, prio int) {
		box.enqueue(outEvent, prio, map[string]any{
			"agent_id": aidNow(), "module": "response", "severity": sev,
			"title": title, "detail": detail,
		})
	}
	// 远程只读运维（读文件/目录/注册表/Shell）失败不进威胁告警，仅真实处置动作失败才报 high。
	emitCommandOutcome := func(action string, ok bool, detail string, _ map[string]any) {
		act := strings.ToLower(strings.TrimSpace(action))
		if isRemoteOpsAction(act) {
			return
		}
		if ok {
			responseEvent("info", "处置成功："+act, detail, 70)
			return
		}
		responseEvent("high", "处置失败："+act, detail, 90)
	}

	isUrgentCommand := func(action string) bool {
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "kill_process", "quarantine_file", "restore_file", "pull_file", "sample_pull", "collect_sample",
			"isolate_network", "unisolate_network", "uninstall_agent":
			return true
		default:
			return false
		}
	}

	handleCommands := func(cmds []agentCommand) {
		for _, cmd := range cmds {
			// 1) 已有回执：只重放 ACK，不重复执行（lease 过期重投 / ACK 丢失）
			if rc := box.cmdReceipt(cmd.ID); rc != nil {
				if rc.Status == "done" {
					log.Printf("command %s 已执行过，重放 ACK", cmd.ID)
					ackReliable(cmd.ID, rc.OK, rc.Result)
					continue
				}
				// started 但没有结果：上次执行中途崩溃
				if nonIdempotentAction(strings.ToLower(cmd.Action)) {
					res := map[string]any{"error": "上次执行被中断，非幂等动作不会自动重跑，请核实后重新下发", "interrupted": true}
					box.cmdFinish(cmd.ID, false, res)
					ackReliable(cmd.ID, false, res)
					continue
				}
			}
			// 2) 超过截止时间不再执行
			if commandExpired(cmd.Deadline) {
				res := map[string]any{"error": "deadline exceeded，命令已过期未执行"}
				_ = box.cmdBegin(cmd.ID, cmd.Action)
				box.cmdFinish(cmd.ID, false, res)
				ackReliable(cmd.ID, false, res)
				continue
			}
			if !responseEnabled.Load() && !isRemoteOpsAction(cmd.Action) &&
				cmd.Action != "refresh_modules" && cmd.Action != "upgrade" && cmd.Action != "uninstall_agent" &&
				cmd.Action != "scan_memory" && cmd.Action != "pull_file" && cmd.Action != "collect_diagnostics" {
				res := map[string]any{"error": "response disabled by policy"}
				_ = box.cmdBegin(cmd.ID, cmd.Action)
				box.cmdFinish(cmd.ID, false, res)
				ackReliable(cmd.ID, false, res)
				continue
			}
			if !cmdSchedulerTry(cmd.Action) {
				res := map[string]any{"error": "命令调度：与维护/扫描任务互斥，稍后重试"}
				_ = box.cmdBegin(cmd.ID, cmd.Action)
				box.cmdFinish(cmd.ID, false, res)
				ackReliable(cmd.ID, false, res)
				continue
			}
			log.Printf("exec command %s action=%s attempt=%d", cmd.ID, cmd.Action, cmd.Attempt)
			if !box.cmdBegin(cmd.ID, cmd.Action) && nonIdempotentAction(strings.ToLower(cmd.Action)) {
				cmdSchedulerDone(cmd.Action)
				fail := map[string]any{"error": "无法写入命令执行回执，已拒绝执行", "refused": true}
				ackReliable(cmd.ID, false, fail)
				emitCommandOutcome(cmd.Action, false, "no receipt", fail)
				continue
			}
			res, err := execCommand(cfg, cmd)
			cmdSchedulerDone(cmd.Action)
			if err != nil {
				log.Printf("command %s failed: %v", cmd.ID, err)
				out := map[string]any{"error": err.Error(), "result": res}
				if !box.cmdFinish(cmd.ID, false, out) {
					out["verification_required"] = true
				}
				ackReliable(cmd.ID, false, out)
				emitCommandOutcome(cmd.Action, false, err.Error(), res)
				continue
			}
			if res["verification_required"] == true {
				if !box.cmdFinish(cmd.ID, false, res) {
					res["receipt_error"] = "execution result could not be durably recorded"
				}
				ackReliable(cmd.ID, false, res)
				continue
			}
			if !box.cmdFinish(cmd.ID, true, res) {
				uncertain := map[string]any{"verification_required": true, "error": "execution result could not be durably recorded"}
				ackReliable(cmd.ID, false, uncertain)
				continue
			}
			ackReliable(cmd.ID, true, res)
			emitCommandOutcome(cmd.Action, true, mustJSON(res), res)
			if cmd.Action == "refresh_modules" {
				select {
				case refreshCh <- struct{}{}:
				default:
				}
			}
		}
	}

	// 紧急处置独立 worker：不跟规则同步抢同一慢车道
	urgentCh := make(chan []agentCommand, 16)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case batch := <-urgentCh:
				handleCommands(batch)
			}
		}
	}()

	dispatchCommands := func(cmds []agentCommand) {
		if len(cmds) == 0 {
			return
		}
		var urgent, rest []agentCommand
		for _, c := range cmds {
			if isUrgentCommand(c.Action) {
				urgent = append(urgent, c)
			} else {
				rest = append(rest, c)
			}
		}
		if len(urgent) > 0 {
			select {
			case urgentCh <- urgent:
			default:
				// 通道满时仍走慢车道，避免丢命令
				rest = append(urgent, rest...)
			}
		}
		if len(rest) > 0 {
			slow.offerCommands(rest)
		}
	}

	// 策略：先应用本地 LKG（离线重启也保持上次有效策略），之后由心跳驱动原子生效/试用/回滚
	bindEvmStore(box.st)
	_ = loadEvmLKGOffline()
	pm := newPolicyManager(box.st, func(p map[string]any) {
		applyPolicy(p, 0)
		syncFIM()
	})
	pm.setConfig(&cfg)
	globalPolicyManager = pm
	pm.boot()
	startRootcheckLoop(ctx, box, aidNow)
	startSCALoop(ctx, box, aidNow)

	// 慢车道单 worker：同步与命令执行串行，绝不阻塞心跳主循环。
	go slow.run(ctx, func(job slowLaneJob) {
		switch job.kind {
		case slowLaneSync:
			maybeSyncFromServer(api, aidNow(), job.syncRev, pm, syncFIM)
		case slowLaneCommands:
			handleCommands(job.cmds)
		}
	})
	// 启动后延迟一次全量同步，同样走慢车道，避免与心跳路径并发 applySyncBundle。
	go func() {
		time.Sleep(2 * time.Second)
		slow.offerSync(1 << 30)
	}()

	var actualHeartbeatPeriod atomic.Int64
	actualHeartbeatPeriod.Store(3)
	healthSnap := func() map[string]any {
		s := health.snapshot(box)
		s["heartbeat_period_sec"] = int(actualHeartbeatPeriod.Load())
		s["capture_quality"] = captureQualitySnapshot()
		s["loop_quality"] = loopQualitySnapshot()
		s["fim_root_health"] = rootHealthSnapshot()
		s["inventory_quality"] = inventoryQualitySnapshot()
		s["memory_scan_quality"] = memoryQualitySnapshot()
		s["policy"] = pm.state()
		s["fleet"] = fleetSnapshot(pm)
		s["host"] = hostMetadata()
		s["capability_status"] = capabilityStatusReport()
		s["yara_compiled"] = yaraCompiled
		if ud := upgradeDetailsSnapshot(cfg); ud != nil {
			s["upgrade_details"] = ud
		}
		return s
	}
	doHeartbeat := func() (*heartbeatResp, error) {
		snap := healthSnap()
		hb, err := api.Heartbeat(cfg.AgentID, primaryIP(), snap, pm)
		if err != nil && isAuthError(err) {
			if s, _ := api.credential(); s != "" {
				dropSecret(err)
				// 立即用共享密钥重新注册换取新凭据，再重试一次心跳
				if r, e2 := api.Register(hostname(), osFamily(), primaryIP(), agentVersion, cfg.AgentID); e2 == nil {
					adoptRegistration(r)
					hb, err = api.Heartbeat(cfg.AgentID, primaryIP(), snap, pm)
				}
			}
		}
		if err == nil {
			heartbeatBackoffOK()
			cpu, _ := numberOf(snap["cpu_pct"])
			rss, _ := numberOf(snap["rss_mb"])
			pm.heartbeatOK(cpu, rss)
			markUpgradeHealthy(cfg)
		} else {
			heartbeatBackoffFail()
		}
		return hb, err
	}

	reportAll := func() {
		hb, err := doHeartbeat()
		if err != nil {
			log.Printf("heartbeat: %v", err)
		} else if hb != nil {
			noteServerRevs(hb.SyncRev, hb.PolicyRev)
			if len(hb.AckedCommandIDs) > 0 {
				confirmHeartbeatAcks(hb.AckedCommandIDs)
			}
			for k, v := range hb.IntervalsSec {
				if v > 0 {
					setIv(k, v)
				}
			}
			if pm.offer(hb.PolicyRev, hb.Policy) {
				applyHeartbeatPolicyPatch(hb.Policy)
				applyIntegrationsPolicy(hb.Policy)
				dpDrv.applyPolicy(hb.Policy)
			}
			// 快车道只更新状态；同步走慢车道，紧急处置走独立通道
			if !cfg.Once {
				slow.offerSync(hb.SyncRev)
				dispatchCommands(hb.Commands)
			} else {
				maybeSyncFromServer(api, cfg.AgentID, hb.SyncRev, pm, syncFIM)
				handleCommands(hb.Commands)
			}
		}
		if !cfg.Once {
			return // 常驻模式由采集 goroutine 首轮全量采集，主循环不等
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, 2)
		for _, mod := range cfg.Modules {
			mod := mod
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				reportModule(box, inv, cfg.AgentID, mod, false)
			}()
		}
		wg.Wait()
	}

	reportAll()
	syncFIM() // 无任何策略时按默认启动 FIM
	pushTimeline([]map[string]any{{
		"etype": "sensor_status", "summary": "传感器模式: " + sensor, "severity": "info",
		"ts":     time.Now().Format("2006-01-02T15:04:05"),
		"detail": map[string]any{"sensor": sensor, "kernel": kernelOn, "etw": etw.status(), "version": agentVersion, "build_id": buildID},
	}})
	if cfg.Once {
		// once 没有后台发送器，同步发完再退出
		for i := 0; i < 5 && box.pending() > 0; i++ {
			box.flush(api)
			time.Sleep(300 * time.Millisecond)
		}
		log.Printf("once 模式完成（outbox 剩余 %d）", box.pending())
		return nil
	}

	for _, mod := range cfg.Modules {
		log.Printf("schedule %s every %s", mod, ivOf(mod))
	}

	// 模块采集：首轮全量（lastRun 为空），之后按周期；refresh_modules 命令触发立即全量
	// 重模块（software 等）启动即采会抢 CPU，首轮延后并错开；但不再等满 30 分钟周期。
	heavyFirst := map[string]bool{
		"software": true, "hotfix": true, "driver": true, "netif": true, "groups": true,
		"firewall": true, "shares": true, "certs": true, "usb": true,
	}
	go func() {
		lastRun := map[string]time.Time{}
		boot := time.Now()
		// 首轮错开：轻模块约 45s 起；重模块约 90s 起，模块间间隔 20~25s
		for i, mod := range cfg.Modules {
			var firstAt time.Time
			if runtime.GOOS == "linux" {
				// Linux collection uses local procfs/package databases; send the first
				// inventory promptly so a newly enrolled host is useful within seconds.
				delay := 3*time.Second + time.Duration(i)*3*time.Second
				switch mod {
				case "sysinfo":
					delay = 1 * time.Second
				case "process":
					delay = 3 * time.Second
				case "network":
					delay = 5 * time.Second
				case "service":
					delay = 8 * time.Second
				case "task":
					delay = 11 * time.Second
				case "startup":
					delay = 14 * time.Second
				}
				firstAt = boot.Add(delay)
			} else if heavyFirst[mod] {
				firstAt = boot.Add(90*time.Second + time.Duration(i)*25*time.Second)
			} else {
				firstAt = boot.Add(45*time.Second + time.Duration(i)*20*time.Second)
			}
			lastRun[mod] = firstAt.Add(-ivOf(mod))
		}
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		runDue := func(force bool) {
			for _, mod := range cfg.Modules {
				if ctx.Err() != nil {
					return
				}
				now := time.Now()
				if last, ok := lastRun[mod]; ok && !force && now.Sub(last) < ivOf(mod) {
					continue
				}
				reportModule(box, inv, aidNow(), mod, deltaCap.Load() && box.useV2.Load())
				lastRun[mod] = time.Now()
			}
		}
		runDue(false)
		for {
			select {
			case <-ctx.Done():
				return
			case <-refreshCh:
				runDue(true)
			case <-t.C:
				runDue(false)
			}
		}
	}()
	// 快照差分时间线（ETW 不可用时的兜底）：采集慢，同样不阻塞主循环
	go func() {
		t := time.NewTicker(6 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				tl.tickQueued(api, cfg, pushTimeline)
			}
		}
	}()

	hbSec := 3
	hb := time.NewTicker(time.Duration(hbSec) * time.Second)
	defer hb.Stop()
	liveTick := time.NewTicker(1 * time.Second)
	defer liveTick.Stop()

	// FIM 重挂独立 worker：fim.stop() 会 Wait 基线扫描，绝不能堵心跳
	fimNeedSync := make(chan struct{}, 1)
	requestFIMSync := func() {
		select {
		case fimNeedSync <- struct{}{}:
		default:
		}
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-fimNeedSync:
				time.Sleep(2 * time.Second)
				for i := 0; i < 64; i++ {
					select {
					case <-fimNeedSync:
					default:
						i = 64
					}
				}
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("syncFIM panic recovered: %v", r)
						}
					}()
					syncFIM()
				}()
			}
		}
	}()

	// pushLive 汇总各实时传感器缓冲并落 outbox
	triggerQueue := newTriggerScanQueue()
	go triggerQueue.run(ctx, func(job triggerScanJob) {
		if !integrationEnabled("memory_scan") || memoryScanSettingsSnapshot().Mode != memModeYaraTriggered {
			captureAdd("trigger_scan_requests", "disabled", 1)
			return
		}
		started := time.Now()
		defer func() { recordLoopDuration("trigger_scan_worker", time.Since(started), time.Second) }()
		res := runTriggeredMemoryScanJob(job.pid, job.reason)
		if res["ok"] == true && res["scan_status"] != "partial" {
			recordComponentObservation("memory_scan", cStateHealthy, "event-triggered memory scan completed")
		} else {
			recordComponentObservation("memory_scan", cStateDegraded, "event-triggered memory scan incomplete")
		}
		if asInt(res["finding_count"]) > 0 {
			enqueueMemoryFindings(box, aidNow(), res)
		}
	})
	pushLive := func() {
		started := time.Now()
		defer func() { recordLoopDuration("live_cycle", time.Since(started), time.Second) }()
		live := watch.drain()
		live = append(live, etw.drain()...)
		live = append(live, wevt.drain()...)
		live = append(live, persist.drain()...)
		live = append(live, wmiPersist.drain()...)
		live = append(live, regw.drain()...)
		live = append(live, fim.drain()...)
		if logTailGlobal != nil {
			live = append(live, logTailGlobal.drain()...)
		}
		live = append(live, kern.drain()...)
		live = append(live, dpDrv.drain()...)
		live = append(live, dropScan.drain()...)
		if integrationEnabled("device") {
			live = append(live, devw.drain()...)
		}
		// 过滤纯状态心跳，避免刷屏；保留首条 etw_status
		filtered := make([]map[string]any, 0, len(live))
		for _, ev := range live {
			et, _ := ev["etype"].(string)
			if et == "etw_status" || et == "winevent_status" {
				sum, _ := ev["summary"].(string)
				if strings.Contains(sum, "不可用") {
					captureFiltered(ev)
					continue
				}
			}
			filtered = append(filtered, ev)
		}
		filtered = normalizeLiveProcessEvents(filtered)
		filtered = processLiveEvents(filtered, cfg, responseEnabled.Load(), eventThrottle)
		filtered = enrichLateralEvents(filtered)
		for _, ev := range filtered {
			notePayloadFromEvent(ev)
			correlateProcessWithPayload(ev)
		}
		// Save the existing telemetry before running potentially slow follow-up work.
		pushTimeline(filtered)
		for _, ev := range filtered {
			dropScan.observe(ev)
			enqueueDropScanAlert(box, aidNow(), ev)
			if !integrationEnabled("memory_scan") {
				continue
			}
			if pid, reason := memoryScanTriggeredByEvent(ev); pid > 0 {
				triggerQueue.offer(pid, reason)
			}
		}
		// 动态 FIM 异步重挂，避免恶意样本风暴堵死心跳导致假掉线
		requestFIMSync()
	}

	// 实时采集与心跳解耦：检出风暴时控制台仍保持 online
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-liveTick.C:
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("pushLive panic recovered: %v", r)
						}
					}()
					pushLive()
				}()
			}
		}
	}()

	var lastMemScheduledScan time.Time
	lastIntegritySweep := time.Now()
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				spWatch.tick()
				ms := memoryScanSettingsSnapshot()
				if integrationEnabled("memory_scan") && ms.Mode == memModeYaraScheduled {
					recordComponentObservation("memory_scan", cStateHealthy, "scheduled memory scan worker active")
				}
				// 内存完整性巡检独立于 YARA 调度：默认「事件触发」模式下也定时全量检查
				if ms.Mode != memModeYaraScheduled && ms.IntegrityChecks && integrationEnabled("memory_scan") {
					iv := ms.IntegrityInterval
					if iv <= 0 {
						iv = 1800
					}
					if time.Since(lastIntegritySweep) >= time.Duration(iv)*time.Second {
						lastIntegritySweep = time.Now()
						if res := runIntegritySweep(); res != nil {
							if fc, _ := res["finding_count"].(int); fc > 0 {
								enqueueMemoryFindings(box, aidNow(), res)
							}
						}
					}
				}
				if ms.Mode != memModeYaraScheduled {
					continue
				}
				iv := ms.ScheduleInterval
				if iv <= 0 {
					iv = 1800
				}
				if time.Since(lastMemScheduledScan) < time.Duration(iv)*time.Second {
					continue
				}
				lastMemScheduledScan = time.Now()
				res, err := scanMemory(map[string]any{"trigger": "schedule"})
				if err != nil {
					recordComponentObservation("memory_scan", cStateDegraded, "scheduled memory scan failed: "+err.Error())
					continue
				}
				recordComponentObservation("memory_scan", cStateHealthy, "scheduled memory scan completed")
				if fc, _ := res["finding_count"].(int); fc > 0 {
					enqueueMemoryFindings(box, aidNow(), res)
				}
			}
		}
	}()

	reRegister := func() bool {
		r, err := api.Register(hostname(), osFamily(), primaryIP(), agentVersion, cfg.AgentID)
		if err != nil {
			log.Printf("re-register: %v", err)
			return false
		}
		adoptRegistration(r)
		if cfgPath != "" {
			_ = cfg.saveAgentID(cfgPath)
		}
		log.Printf("re-registered agent_id=%s", cfg.AgentID)
		return true
	}

	hbFailStreak := 0
	// soft-offline / 启动离线时用短周期重试注册，避免等完整心跳拍导致「网通却不上线」
	offlineRetry := time.NewTicker(5 * time.Second)
	defer offlineRetry.Stop()
	for {
		if offline {
			select {
			case <-ctx.Done():
				log.Println("agent 停止")
				return nil
			case <-offlineRetry.C:
				if reRegister() {
					offline = false
					hbFailStreak = 0
					log.Printf("network/register recovered, back online")
				}
			case scheduled := <-hb.C:
				recordLoopDuration("heartbeat_schedule_delay", time.Since(scheduled), time.Duration(actualHeartbeatPeriod.Load())*time.Second)
				if reRegister() {
					offline = false
					hbFailStreak = 0
					log.Printf("network/register recovered, back online")
				}
			}
			continue
		}
		select {
		case <-ctx.Done():
			log.Println("agent 停止")
			return nil
		case <-offlineRetry.C:
			// 在线时忽略短周期 ticker，仅消费避免堆积
		case scheduled := <-hb.C:
			recordLoopDuration("heartbeat_schedule_delay", time.Since(scheduled), time.Duration(actualHeartbeatPeriod.Load())*time.Second)
			out, err := doHeartbeat()
			if err != nil {
				hbFailStreak++
				log.Printf("heartbeat: %v (fail_streak=%d)", err, hbFailStreak)
				if strings.Contains(err.Error(), "未知") {
					reRegister()
				} else if isCredentialRejected(err) {
					// 服务端记录被删 / 数据库重建：独立凭据已失效，退回接入密钥重新注册
					api.setCredential("", cfg.AgentID)
					reRegister()
				} else if hbFailStreak >= 3 {
					// 连续失败：进入 soft-offline，5s 短周期重试注册（网络恢复后快速上线）
					log.Printf("heartbeat soft-offline after %d failures, will re-register", hbFailStreak)
					offline = true
					hbFailStreak = 0
				}
			} else {
				hbFailStreak = 0
				noteServerRevs(out.SyncRev, out.PolicyRev)
				if len(out.AckedCommandIDs) > 0 {
					confirmHeartbeatAcks(out.AckedCommandIDs)
				}
				for k, v := range out.IntervalsSec {
					if v > 0 {
						setIv(k, v)
					}
				}
				if pm.offer(out.PolicyRev, out.Policy) {
					applyHeartbeatPolicyPatch(out.Policy)
					applyIntegrationsPolicy(out.Policy)
					dpDrv.applyPolicy(out.Policy)
				}
				dpDrv.applyCrypto(out.DPCrypto)
				pullMemoryYaraIfNeeded(out.MemoryYaraRev)
				// 快车道：同步走慢车道；紧急处置独立执行
				slow.offerSync(out.SyncRev)
				hadCmds := len(out.Commands) > 0
				dispatchCommands(out.Commands)
				if out.RuleFIMPaths != nil {
					rp := out.RuleFIMPaths
					if len(rp) > 20 {
						rp = rp[:20]
					}
					fimMu.Lock()
					changed := strings.Join(rp, ";") != strings.Join(ruleFIMPaths, ";")
					if changed {
						ruleFIMPaths = append([]string(nil), rp...)
					}
					fimMu.Unlock()
					if changed {
						log.Printf("规则监控目录: %v", rp)
						requestFIMSync()
					}
				}
				nextHB := out.HeartbeatSec
				// 刚拿到指令：下一拍用最短心跳，尽快 ACK / 取后续批次
				if hadCmds {
					nextHB = 3
				}
				if nextHB >= 3 && nextHB <= 120 && nextHB != hbSec {
					hbSec = nextHB
					actualHeartbeatPeriod.Store(int64(hbSec))
					hb.Reset(time.Duration(hbSec) * time.Second)
				} else if hadCmds {
					hb.Reset(3 * time.Second)
				}
			}
		}
	}
}

// annotateEntities 给带 pid 的事件补进程实体；进程创建类事件附带完整实体字段。
func annotateEntities(events []map[string]any) {
	for _, ev := range events {
		d, _ := ev["detail"].(map[string]any)
		if d == nil {
			continue
		}
		e := procEntities.annotate(d, parseLocalTS(asString(ev["ts"])))
		if e == nil {
			continue
		}
		switch asString(ev["etype"]) {
		case "process_create", "process_create_live", "process_create_etw":
			mergeInto(d, procEntities.fieldsOf(e))
			if cmd := strings.TrimSpace(asString(d["command_line"])); cmd != "" {
				procEntities.applyCmdLine(uint32(asInt(d["pid"])), parseLocalTS(asString(ev["ts"])), cmd, asString(d["user"]))
			}
		case "process_exit":
			procEntities.markExited(e.ID, 0)
		}
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	if len(b) > 1500 {
		return string(b[:1500])
	}
	return string(b)
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func reportModule(box *outbox, inv *inventory, agentID, module string, deltaOK bool) {
	finishWork := beginComponentWork("inventory_" + module)
	var items []any
	var err error
	limit := inventoryCollectionLimit(module)
	if module == "software" {
		if box.useV2.Load() && box.softwareExtended.Load() && box.snapshotParts.Load() {
			limit = extendedSoftwareLimit
		}
		if box.useV2.Load() && box.softwarePaged.Load() && box.snapshotParts.Load() {
			limit = pagedSoftwareLimit
		}
		items, err = collectSoftwareLimited(limit + 1)
	} else if module == "service" || module == "hotfix" {
		if box.useV2.Load() && box.assetsPaged.Load() && box.snapshotParts.Load() {
			limit = pagedSoftwareLimit
		}
		if module == "service" {
			items, err = collectServicesLimited(limit + 1)
		} else {
			items, err = collectHotfixLimited(limit + 1)
		}
	} else if module == "user" {
		if box.useV2.Load() && box.usersPaged.Load() && box.snapshotParts.Load() {
			limit = pagedSoftwareLimit
		}
		items, err = collectUsersLimited(limit + 1)
	} else {
		items, err = collectModule(module)
	}
	finishWork()
	possibleTruncation := false
	if module == "software" || module == "service" || module == "hotfix" || module == "user" {
		items, possibleTruncation = boundInventoryProbe(items, limit)
		possibleTruncation = recordInventoryQualityWithLimit(module, len(items), limit, possibleTruncation, err)
	} else {
		possibleTruncation = recordInventoryQuality(module, len(items), err)
	}
	if err != nil {
		recordComponentObservation("inventory_"+module, cStateDegraded, err.Error())
		log.Printf("[%s] collect: %v", module, err)
		box.enqueue(outEvent, 90, map[string]any{
			"agent_id": agentID, "module": module, "severity": "high",
			"title": "采集失败：" + module,
			"detail": map[string]any{
				"collect_status": "error",
				"error_code":     "collect_failed",
				"message":        err.Error(),
				"module":         module,
			},
		})
		return
	}
	if items == nil {
		items = []any{}
	}
	if possibleTruncation {
		recordComponentObservation("inventory_"+module, cStateDegraded, fmt.Sprintf("returned %d items at collection limit; previous authoritative snapshot retained", len(items)))
		// An exact-cap result may be incomplete; do not turn a partial view into removals.
		return
	}
	collectStatus := "ok"
	if len(items) == 0 {
		collectStatus = "empty"
		recordComponentObservation("inventory_"+module, cStateHealthy, "collected empty (no data)")
	} else {
		recordComponentObservation("inventory_"+module, cStateHealthy, fmt.Sprintf("collected %d items", len(items)))
	}
	paged := (module == "software" && len(items) > extendedSoftwareLimit) || ((module == "service" || module == "hotfix" || module == "user") && len(items) > maxItems)
	var p planned
	if paged {
		p = inv.planPaged(module, agentID, items)
	} else {
		p = inv.plan(module, agentID, items, deltaOK)
	}
	if p.skip {
		return
	}
	if p.payload != nil {
		if paged {
			if module == "software" {
				p.payload["paged_software"] = true
			} else {
				p.payload["paged_inventory"] = true
			}
			if raw, marshalErr := json.Marshal(p.payload); marshalErr != nil || len(raw) > snapshotPartsMaxBytes {
				inv.invalidate(module, 0)
				recordComponentObservation("inventory_"+module, cStateDegraded, "paged inventory exceeds transfer budget; previous snapshot retained")
				return
			}
		}
		p.payload["collect_status"] = collectStatus
		if collectStatus == "empty" {
			p.payload["error_code"] = ""
		}
	}
	// 先落盘 outbox：全量会取代同模块旧全量与未发出的增量
	if !inv.enqueuePlan(module, p, box.enqueue) {
		recordComponentObservation("inventory_"+module, cStateDegraded, "inventory enqueue failed; full snapshot required")
		captureAdd("inventory_"+module, "enqueue_failed", 1)
		return
	}
	if p.kind == outSnapshotDelta {
		ups, _ := p.payload["upserts"].([]map[string]any)
		rms, _ := p.payload["removes"].([]string)
		log.Printf("[%s] queued delta gen=%v +%d -%d (共 %d)", module, p.payload["generation"], len(ups), len(rms), len(items))
	} else {
		log.Printf("[%s] queued full gen=%v %d items", module, p.payload["generation"], len(items))
	}
}
