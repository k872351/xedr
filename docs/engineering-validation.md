# EDR 工程验收说明

## 统一检查

隔离的后端 QA 容器定义位于 `deploy/Dockerfile.qa`，用于运行后端回归测试。构建上下文采用文件白名单，排除现有运行数据、发布程序及配置密钥；当前开发环境未安装 Docker，镜像构建尚待验证。

在项目根目录执行：

```powershell
.\scripts\check-edr.ps1
.\scripts\check-edr.ps1 -FullAgentTests
```

默认检查后端回归、Agent 健康评分和前端生产构建。第二条命令另行运行 Agent 全量单元测试。脚本不启动生产服务，不执行安装或升级。前端构建会更新 `agent_admin/dist`。

后端直接依赖记录在根目录 `requirements.txt`，以当前环境版本为基准；安装前应在独立测试环境验证，避免覆盖运行中的生产环境。`check-edr.ps1` 会检查 Python 依赖一致性并发现后端测试模块。

## 发布完整性和启动状态

### 采集质量专项

- Web 清单移除旧 800 条展示截断，按 20/50/100 条分页，搜索覆盖完整已保存清单；切换终端或模块时忽略过期请求。此项不提高端点实际采集上限。新增本地实时采集周期和心跳调度延迟采样，仅用于诊断，不改变扫描调度或远程执行能力。Windows 书签临时文件同步后替换，合成文件回归不替代真实轮转和断电验收。

- Linux FIM 保持原轮询周期和范围，目录缺失、权限异常、超限及哈希读取失败时保留未确认的旧基线。健康面板区分 Windows 实时监听与 Linux 轮询、完整遍历和基线保存成功。Linux journal 的读取错误、预算次数与本地事务成功分别计数；预算达到不等于数据丢失。

- 安装软件清单新增 `inventory.software.extended.v1` 能力协商：Windows/Linux 定期采集在双方支持分块及扩展协议时最多上报 1000 条，旧协议仍为 500 条。软件解析器读取额外一条用于判定真实截断；超限或读取失败保留旧权威快照，其他模块及交互式查询的条目限制不变。这是有限清单扩展，不是无限分页采集。

- `inventory.parts.v1` 仅在双方协商支持时启用，超过 192 KiB 的现有全量快照拆分为有限分块（整份传输不超过 2 MiB）；原始队列项保留至全部分块回执确认。服务端按终端与模块持久暂存、验证 SHA-256 后原子发布，缺块或冲突不会覆盖旧快照。兼容旧服务端的原协议，服务端快照内容大小限制不变；超限清单的分页采集尚未完成。

- 服务端不再静默裁剪超过模块上限的全量快照，也不将无效 items 当作空清单。版本化快照须具有一一对应的唯一键，空快照仍保留版本；差量格式异常或基线不一致时拒绝写入并保留原快照。

- 本地 SQLite 使用 WAL + synchronous=FULL。清单入队失败、最新全量被拒绝或排队快照因预算淘汰时，下次采集重新生成全量；单测覆盖这些状态转换和书签缺口上限。FULL 模式增加磁盘同步开销，需实机测量吞吐和延迟。

- 终端健康面板展示分层传感器计数、FIM 目录监听与遍历状态、清单返回数与已知上限、最近一次内存读取质量。计数是进程生命周期累计；不同阶段不能简单相加。
- Windows 日志只保存连续确认的书签。接收缓冲丢弃、原生订阅异常或保存失败必须有计数；真实主机需验证断电、轮转和回补时的缺口与重复。
- 清单触达已知上限时标为可能不完整并保留旧权威快照，不发送基于不完整数据的删除差量。完整分块采集仍待独立协议验收。
- 实机压力、资源预算和低权限兼容性未由合成测试替代；不启用新的自动处置或扫描范围。

隔离测试终端验收记录（以下均为待执行，不代表已经通过）：

| 场景 | 验收标准 |
|---|---|
| Windows 日志正常重启、日志轮转 | 已确认游标恢复；存在缺口时健康面板明确显示，不静默跳过 |
| Windows 意外断电 | 在可恢复的测试虚拟机验证队列与游标一致性，记录重复与缺失数量 |
| 队列预算达到上限 | 显示淘汰计数；受影响清单重新全量同步，旧权威快照不被不完整数据覆盖 |
| Windows / Linux 非管理员权限 | 对无法采集的已配置项目记录状态或错误，不将失败当作空清单 |
| Linux x64 / ARM64 | 分别验证采集进程、心跳及配置范围内的清单；交叉编译成功不代表运行验收 |

### 终端上线及遥测恢复专项

- 注册记录不等于安装成功；首次确认心跳后按服务端下发和终端报告的周期判断在线，窗口为 max(45, 2 × 周期 + 15) 秒。升级数据库后旧记录等待下一次真实心跳。遥测接收独立记录。
- 安装包地址必须由管理员显式配置，未配置时禁止生成。代理请求头不作为下载包的配置来源。
- 新 ES 索引任务与 Agent 业务事件在同一个 SQLite 事务提交，批量写入按稳定 ID 确认。只有具体成功的条目才完成；失败退避、租约过期后重试。生产验收需要在隔离 ES 环境停止、恢复服务，核对事件总数和重复数。
- 静态扫描驱动仅记录审计，不根据路径截断文件。默认生产安装包不包含测试签名驱动；现存驱动二进制未被替换。恢复隔离需另行通过稳定文件身份、可恢复存储、生产签名及驱动兼容性验收。
- CI 使用 agent/go.mod 的工具链版本，运行全量 Agent 单测。安装到首次上线、服务端重启与同步版本保持、审批到结果持久化需要分别执行隔离实机验收；模拟测试和交叉编译不代表完成实际处置或生产发布。

浏览器写请求按实际请求 Host、协议及端口进行同源校验；反向代理部署需保留公开 Host，并通过服务器受信任的代理设置传递 HTTPS 协议信息。

`python scripts/verify_release.py agent/build-manifest.json` 校验已有发布文件的大小和 SHA-256，不执行、不发布文件；该检查不等同于数字签名验证，也不能证明跨架构兼容性。

`/health/ready` 在核心启动失败时返回 503；核心服务启动成功但可选依赖初始化失败时返回 200，并携带 `degraded: true`。显式禁用 MySQL 而使用 SQLite 不属于异常降级。该状态仅反映启动结果，不代表持续探活。

## 备份与恢复验收

实时只读报表索引校验入口为 `python scripts/check_live_report_consistency.py`。使用当前配置的数据库连接，读取有限数量的报表元数据并输出汇总差异，不输出凭据或记录明细。两个存储的读取快照相互独立，并发写入可能造成暂时差异；缺失、禁用或超出读取上限时不会宣称一致。

报告索引双存储一致性可通过已导出的 SQLite、MySQL JSON 记录数组进行离线比较：

```powershell
python scripts/compare_report_indexes.py sqlite-reports.json mysql-reports.json
```

比较报告标识、数量字段及基本元数据，并汇总仅一侧存在或字段不同的记录数量。导出文件应来自同一业务时点，避免把正常时间差误判为数据不一致。

对独立、完整的 SQLite 备份文件执行只读完整性检查：

```powershell
python scripts/verify_sqlite_backup.py <备份文件路径>
```

该命令不会创建缺失的数据库，不恢复数据，也不替代业务一致性验收。存在 WAL 的活动数据库应通过受支持的数据库备份机制生成独立一致的备份，不能只复制主数据库文件。恢复演练应在隔离环境中进行，并核对备份时间、业务记录与恢复结果。

## 容量与高可用验收

使用 `python scripts/benchmark_report_index.py` 可测量隔离的内存数据库中合成报表元数据列表查询性能。该测试不访问生产数据库；实际性能仍需在真实数据环境中测量。

记录每次测量的终端数、平均事件量、磁盘增长量、接入处理延迟、数据库资源占用和 API 延迟。分别记录正常负载、峰值负载和故障恢复后的数据。未完成实际负载测试前不承诺容量上限。

高可用验收需独立验证数据库和搜索服务的恢复能力、各实例健康状态及后台任务是否重复执行。通过后再考虑多实例生产发布。

## 兼容性验收矩阵

下表是待验证的目标，不代表已通过认证。

| 平台 | 架构 | 验收范围 |
|---|---|---|
| Windows 10/11 | x64 | 安装、启动、正常退出、健康状态、运行资源 |
| Windows Server 2016/2019/2022/2025 | x64 | 同上，并覆盖服务器运行环境 |
| Windows 11 | ARM64 | 独立构建、依赖和兼容性验证 |
| Debian/Ubuntu、Rocky Linux | x64/ARM64 | 基础功能及不适用指标展示 |
| macOS | Intel/Apple Silicon | 暂不承诺支持 |

建议使用隔离测试虚拟机，记录系统版本、构建号、架构、权限、测试结果以及失败日志。只有实际通过的系统和架构才能列入正式支持范围。

## 当前已知验证缺口

- Agent 全量测试尚未通过；当前受限 Windows 环境阻止 Go 测试访问本机回环监听端口，并限制部分临时 SQLite 文件访问；文件身份重命名测试也失败。需在具有本机回环和可写临时目录的隔离测试机复核。
- 前端页面已拆成 4 组按需加载组件；主 JS 包约 157 KB，生产构建不再触发 500 KB 提示。页面浏览器交互和真实数据性能仍需验收。
- 后端回执测试只覆盖隔离的 SQLite 数据库，不代表 MySQL、Elasticsearch 或多实例架构已完成压力及灾难恢复验证。
- 尚未替换发布 Agent 或重新启动生产服务。

### Strict shared storage

When MySQL is enabled, strict shared storage is on by default. If MySQL is unavailable, readiness fails and business API requests return HTTP 503 instead of silently switching to node-local SQLite. Set `strict: false` (or `FORENSIC_MYSQL_STRICT=0`) only when local SQLite fallback is intentional. This prevents split writes for requests rejected by this guard; it does not migrate every SQLite subsystem to MySQL or provide automatic database failover.

### Follow-up: bounded software inventory and triggered scan scheduling

- `inventory.software.paged.v1` requires v2 and `inventory.parts.v1`; supported collectors probe up to 4,001 records and publish at most 4,000. Above 1,000 records, full snapshots are staged in bounded fragments and published only after successful reassembly. The existing 2 MiB transfer and server snapshot storage budgets still apply. Exceeding either budget must not replace the preceding authoritative snapshot. This is bounded software inventory support, not an unbounded cursor-based collector for all modules.
- Event-triggered memory scans now use a separate single worker, a 16-entry nonblocking queue, PID coalescing and a five-second queue lifetime. Queue-full, expired and disabled results are counted. The event path no longer waits for the scan result. Scheduled scans and command-driven scans are not covered by this queue.
- Real-terminal acceptance is scoped by the evidence below. On an isolated, recoverable test machine record baseline and peak CPU/memory, live cycle and heartbeat delays, queue counters, and inventory completeness; validate a normal unprivileged account without treating permission failures as empty snapshots. Before a power-loss test take a recoverable machine snapshot and obtain explicit approval for interruption; compare queue and authoritative snapshot state after recovery. WSL and synthetic fixtures cannot substitute for actual power-loss acceptance.

#### Ubuntu VM acceptance evidence (2026-11-21)

User-executed results: Ubuntu 26.04 LTS x86_64, Go 1.26.8, two vCPUs, 3.3 GiB RAM. `TestLinuxInstalledSoftwareAcceptance` as UID 1000 collected 1,682 of 1,682 installed packages; two fragments, 175,586 bytes, exact reconstruction, 24 ms total test time. The inventory and trigger queue tests passed 100 repetitions during a 30-second, two-worker `stress-ng` CPU test at 70% target load (zero stressor failures). This is a component test under actual CPU load; it does not establish production agent heartbeat or full-system latency bounds.

The four outbox restart/receipt/partial-ack tests passed. Following the user-assisted VM interruption, `TestLinuxVMRecoveryAcceptance` reported `recovered=100/100 unique=true integrity=ok` (10 ms). The fixture used a separate test directory and synthetic events; this demonstrates recovery of committed events for this VM run, not physical hardware power-loss guarantees, in-flight transaction durability, or production end-to-end delivery. Other inventory modules, Windows/ARM64, and sustained full-agent load remain unverified.

#### Ubuntu VM agent-loop soak (2026-11-21)

The user executed the three-minute `TestLinuxAgentSoak` under a two-worker 70% target CPU load. The isolated loopback sink acknowledged 41 events/fragments; 60 heartbeats arrived, maximum observed gap 3.014 s, maximum sampled agent CPU 1.2%, RSS 28.5 MiB, sampled queue depth zero, dropped/rejected zero. Sysinfo (1), software (1,685), service (317), and patch history (2,060) snapshots were observed. Service/patch pagination is negotiated via `inventory.assets.paged.v1`, with the same staged byte limits and 4,000-record ceiling as software. The first run passed the loop-level criteria, but rejected the unsigned fixture policy and returned HTTP 404 for the fixture's unimplemented sync endpoint. The fixture has since been updated to use a temporary signed test policy and require confirmed application; rerun pending. This is not an all-sensor, production backend, physical machine or long-duration acceptance result. Other inventory modules retain their existing collection boundaries.

Signed-policy rerun: PASS (180 s), 60 heartbeats, maximum heartbeat gap 3.007 s, maximum sampled CPU 0.8%, RSS 30.1 MiB, sampled queue depth 0, dropped/rejected 0, 37 acknowledged events/fragments; all four inventory modules observed. The temporary signed policy was applied and promoted to LKG after its probation (`signed_policy_applied=true`). The mock sync endpoint remains unimplemented; production backend sync and all-sensor acceptance are outside this test.

Additional server-side synthetic acceptance: `python -m unittest backend.test_paged_asset_publication` passed. The actual v2 ingest and snapshot store paths (private in-memory SQLite, post-publication side effects mocked) verified 1,501 rows each for software, service and hotfix, retention of the old snapshot until the final fragment, exact item/key reconstruction, receipt deduplication, and refusal of an invalid key set without replacing the old publication. The new opt-in `TestLinuxAssetInventoryAcceptance` checks the real Ubuntu service and patch inventories' chunk reconstruction, unique keys and SHA-256 without printing inventory contents; VM run pending.

VM asset acceptance subsequently passed as UID 1000: service 317 records, two test fragments, 95,895 bytes; patch history 2,060 records, three fragments, 394,104 bytes. Both checks reported unique keys and matching SHA-256; total test time 31 ms. The service fixture explicitly forces staging at 317 records; real service inventories above 500 are covered by the synthetic 1,501-record backend regression, not by this VM's service count.

Paged inventory scheduling improvement: unchanged software, service and hotfix full snapshots are suppressed between refreshes (ten-minute touch interval); changes, rejected/enqueue-failed generations, and periodic refreshes still produce a complete staged snapshot. Legacy full-only behavior and the existing delta mode are unchanged. The synthetic `TestPagedInventoryRefresh` exercised 20 unchanged collection ticks per module, a change, invalidation and periodic refresh; the paged and existing delta regression tests passed. This optimization is not yet measured on the VM.

Platform status correction: Linux now describes its configured collection mode as `linux_inventory`, while the journal pipeline reflects whether it is enabled. Windows-only component IDs are excluded from expected/actual fleet components on Linux and remain explicitly unsupported in the compatibility health report. This changes status reporting, not sensor coverage. Platform and health score unit tests passed. The opt-in `TestLinuxLoopbackRecoveryAcceptance` uses a closed loopback listener, 100 synthetic records in an isolated disk-backed outbox, and then a restored listener to verify automatic backoff and complete delivery. VM acceptance is pending; it does not change interface/firewall settings or use production data.

VM loopback recovery acceptance subsequently passed: the initial TCP connection was refused, all 100 events stayed pending, and after the local listener became available all 100 unique events were acknowledged within 2,108 ms; pending, dropped and rejected were all zero. The Linux platform naming and paged refresh unit tests also passed on the VM. This validates local TCP refusal/recovery and queue handling, not a physical network outage or production backend connectivity.

HTTP route acceptance extension: the real v2 route, authentication guard (fixture credential verifier), transaction and snapshot publication now have direct request-fixture regression coverage; five non-HTTP tests passed, including rejection of an invalid fixture credential. The opt-in ASGI `PagedAssetHTTPTests` remain pending because the restricted Windows runner blocks the asyncio socket-pair initialization. Run them from a normal test terminal with `EDR_HTTP_ACCEPTANCE=1`; they do not connect to the real production backend or use its database.

User-executed Windows ASGI acceptance subsequently passed all three tests in 0.404 s: complete publication and replay, invalid fixture credential rejection, and preservation of the previous publication on invalid versioned data. The Starlette/httpx deprecation warning did not affect the result. This remains isolated HTTP integration rather than deployed production backend validation.

### Follow-up acceptance (2026-11-22)

- Synthetic capacity: in-process private SQLite fixture, eight workers, single-row software snapshots for 100, 500 and 1,000 distinct fixture endpoints. All records and receipts persisted. One run took 0.013/0.049/0.103 s respectively; approximate p95 1.29/0.95/1.05 ms. No HTTP, disk I/O, rule evaluation, real database server, or external endpoint traffic was exercised; these figures are not production capacity estimates.
- Index outage: 100 synthetic queue records survived a mocked indexing connection failure, respected backoff, and all recovered with unchanged identities. The test advances only the fixture retry timestamp. Actual Elasticsearch and MySQL service interruption acceptance remains outstanding.
- Linux arm64 and Windows arm64 cross-builds completed with CGO disabled. No ARM64 artifacts were deployed, and real-device acceptance remains pending.
- The optional ASGI HTTP tests now use httpx native ASGI transport directly instead of the deprecated Starlette TestClient adapter. `requirements-test.txt` declares the test dependency. A normal-terminal opt-in rerun is required before recording this change as verified; production dependency pins are unchanged.
- Subsequent Windows-terminal ASGI rerun: all three tests passed in 0.409 s without the previous deprecation warning, as reported by the user. The test adapter compatibility change is verified.
- The isolated Linux agent-loop soak allows `EDR_AGENT_SOAK_DURATION=3m` through `72h` and requires at least 90% of expected heartbeats. Long runs still cover only the configured fixture modules and do not establish all-sensor or production backend acceptance.

### User inventory pagination and validation hardening (2026-11-22)

The existing user inventory supports a negotiated `inventory.user.paged.v1` capability on Linux and Windows. The original 500-record collection remains the default for old servers; when v2, fragment support and the new capability are available, the collector probes up to 4,001 records and stages complete snapshots of up to 4,000 records, subject to existing byte budgets. The collector's field set and source scope are unchanged. Stage-and-publish regressions with 1,501 synthetic user entries passed. Paged snapshots now require an integer, positive generation and matching unique keys; malformed generations leave the previous publication intact. Large user inventory real-machine testing and Windows collection error-path acceptance remain pending. No changes were made to other collector limits in this step.

Duplicate-key planning now tracks the next suffix per base key rather than repeatedly searching from suffix 2. The 4,000-record collision fixture, including a natural key resembling a generated suffix, passed uniqueness and key-length checks, along with existing delta and paged-refresh regressions. The long Linux soak now logs progress every five minutes and requires the final observed policy to be accepted LKG. Linux amd64 test compilation passed; a 24-hour VM run remains pending.

Snapshot read pagination: the existing authenticated GET route accepts optional offset/limit (up to 500) and a snapshot-version token. A changed snapshot yields HTTP 409 instead of mixing rows from different versions. The console reconstructs the existing full-list view from bounded responses, retries once on a version change, and supports older unpaged servers. Backend route and storage fixtures (10 tests) and frontend regression suite (21 tests) passed. This is transport pagination; server JSON decoding and client filtering still operate on the complete snapshot and endpoint collector limits are unchanged. The user reported starting the 24-hour isolated Linux soak on 2026-11-22; final results remain pending.

Strict MySQL readiness now reflects the current readiness check rather than displaying a stale successful startup component during an outage. A synthetic outage/recovery test validates HTTP 503 then 200, current component status and unchanged startup state. Nine health/startup/index queue regression tests passed. Actual MySQL interruption, startup-with-MySQL-unavailable recovery and production write-path acceptance are still outstanding.

Release download gate: Windows install packages now require a matching binary manifest, including a stale build whose manifest actually verifies. Latest-only is the default; the console requires explicit confirmation to request a verified stale build and displays architecture-specific release status/source revision. The two download guard tests, full frontend unit suite and frontend build passed. This does not establish that existing release artifacts contain the current source, nor that a generated package has successfully installed on a real terminal. No production installer was executed.

Sync policy failure gate: a rejected policy aborts subsequent bundle application and leaves the acknowledged sync revision unchanged. An unsuccessful fetch records a failure. The targeted rejected-policy and cached-policy verification regressions cover this behavior. Per-module confirmation, explicit empty-list semantics and server-side policy signing remain separate acceptance requirements.

Command safety gates: approvals and command resolution now require the exact registered agent identifier (no hostname fallback). Non-repeatable operations, including process termination, reject volatile receipt storage; a new receipt must actually claim a row. Completion receipt errors no longer report ordinary success and instead return `verification_required`. Isolated receipt and identity tests passed, using synthetic results only. This does not establish a database-enforced unique approval-to-command relationship or successful real-device action/confirmation; those remain outstanding.

Subsequent approval guard: migration 14 adds database triggers rejecting new duplicate `approval:` command keys and changes to those keys, without deleting historical duplicates. Existing linked keys are not redispatched; the approval is marked verification-required, and the console distinguishes approval from command receipt status. Linux SIGTERM reporting now says signal sent / verification required, rather than claiming termination. Diagnostic receipt ownership is checked before file persistence; completed duplicate receipts skip persistence. Backend isolated guard tests, Agent targeted regression/compile and frontend build passed. The migration has not been applied to a production database; historical duplicate reconciliation, actual execution confirmation, and a crash-recovery audit of interrupted approvals remain pending.

Host detail evidence summary separates connection, most recent collection evidence, reported data gaps and policy application. Unknown or truncated reports are not presented as complete coverage. The frontend suite (23 tests) passed; browser and deployed-server acceptance remain pending.

Installer safety follow-up: the Windows batch path refuses a pre-existing configuration, the GUI validates the existing server before copying and preserves the existing configuration, and the Linux script preflights existing versus packaged server URLs before stopping the service (requires Python 3 for existing-config validation). The native installer/MSI is excluded from newly generated Windows packages until an independent installer manifest can be verified; the package cache key was changed. Static generated-script checks and identity/release regressions passed (7 tests). No installer was executed. Timeline, alert refresh and hunt UI requests now ignore superseded results; the synthetic out-of-order hunt test and total 24 frontend tests passed, along with the frontend build. These changes do not implement server-side investigation pagination or real installation acceptance.

Alert query follow-up: the existing authenticated alert-list API accepts exact status, agent, severity, module, local timestamp range and descending ID cursor. Total is counted before the cursor; the first-page ID anchor excludes newer insertions from subsequent pages. A 1,201-record synthetic filtered query reconstructed all matching IDs across pages; invalid timestamps/statuses are rejected. The console exposes total versus loaded working-set limitations and the API client accepts the new parameters. Existing dashboard/local-filter consumers still use the bounded working set, and the anchor does not freeze edits/deletions; full UI/query/export consistency remains pending.
