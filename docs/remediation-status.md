# 整改验收台账

编号与原 60 项整改清单一致。源码改动、专项测试和实际环境验收分别记录，避免将部分完成误判为全部完成。

严格按原始验收范围统计，第二类 Linux Agent（09–20）共 12 项暂缓；其余 48 项仍有待完成或验收的内容。已完成部分代码和专项测试的条目保留在未关闭范围内，直至对应验收条件全部满足。

| 类别 | 编号 | 当前进展 |
|---|---|---|
| 跨平台与架构 | 01–08 | Windows x64、x86 独立资源、原生进程诊断 ABI、组件状态模块运行测试通过；ARM64 同模块交叉编译及 PE 架构检查通过，完整 Agent 及 ARM64 实际运行待验收 |
| Linux 基础采集 | 09–11 | 暂缓；dpkg/RPM 软件清单已有解析测试 |
| Linux 扩展模块 | 12–19 | 按用户要求暂缓 |
| Linux 资源指标 | 20 | 暂缓；已修复未实现的原生指标被显示为有效数据的问题 |
| Agent 工程化 | 21–23 | 已抽离自身 CPU 采样及状态生命周期，并覆盖初始、缺失和复位采样的回归测试；其余组件生命周期待完成 |
| 采集数据质量 | 24 | 软件清单失败与空数据已区分；异常文件规则补齐 Linux/嵌套文件详情、路径别名和自定义字段传递。真实终端命中仍待验收 |
| 性能及兼容性 | 25–28 | 待实测；正式驱动签名按用户要求暂缓，现有文件签名状态已记录 |
| Agent 本地数据库与测试 | 29–30 | 默认临时目录权限异常已确认，需在目标环境复核全量测试 |
| 多语言与资源预算 | 31–32 | 已实现 Agent 整体 CPU/内存参考预算及原生进程资源、Go 运行时两个自身诊断模块的独立耗时采样，无法以耗时替代组件 CPU/内存归属 |
| 后端存储解耦 | 33 | 已抽离文件元数据、目录索引、JSON 编解码、事件和文件批量持久化、报告及索引库 schema 迁移、数据库连接及索引行读写 |
| 其余核心模块拆分 | 34–37 | edr_api 账户及会话路由、agent_edr 时间线值格式化、agent_protocol 通用 SQLite schema 助手及 agent_rules 来源元数据已抽离；AI 管理 API 的 10 个前端接口已注册到路由。核心业务全面拆分仍待完成 |
| 双存储及迁移 | 38–39 | 已加入实时只读报表索引一致性检查工具，当前配置 MySQL 未启用且 SQLite 索引不存在；真实一致性结果暂不可用 |
| 调度与多实例 | 40–41 | 报告及索引库迁移使用 SQLite 写锁，Schema 检查不再持有进程级锁等待数据库写入，报表 JSON 单文件原子替换；后台任务协调及真实多实例仍待完成 |
| 压测、去重与资源隔离 | 42–44 | 回执重复拒绝已有回归测试，其余待验证 |
| 协议及规则测试 | 45–46 | 未关闭 |
| 存储与可观测性 | 47–48 | 容量统计缓存、启动健康及报告计数状态已改善，容量 API 区分完整、部分、跳过和错误状态 |
| 灾难恢复 | 49 | 已具备只读快速及完整完整性检查、外键检查以及隔离数据库恢复回归测试，真实业务恢复演练待验证 |
| 控制台拆分与页面 | 50–52 | 已将主控制台页面模板拆为 4 组按需加载组件；主 JS 包由 525 kB 降至 157 kB，构建不再触发 500 kB 警告。主题样式已改为覆盖异步页面组，侧栏活动标记改为与参考主题一致的蓝青色。页面浏览器交互与真实数据性能仍待验收 |
| 能力与健康展示 | 53–54 | 已实现组件状态矩阵及本次健康面板展开期间的 CPU、内存趋势；配置启用但缺少运行证据的组件显示 UNKNOWN，服务端持久化历史待完成 |
| 列表性能 | 55 | 终端分组列表分页及页脚组件已独立，万条合成记录分页测试已补充；真实数据页面性能待测量 |
| 容器化与 CI | 56–57 | 已添加 CI 检查配置及隔离 QA 容器定义，远端流水线、QA 镜像构建和生产容器化仍待验证 |
| 发布、多平台及高可用 | 58–60 | Windows x64 Agent 与安装包已按当前源码重建，发布完整性通过；Linux amd64/arm64/loong64/riscv64、Windows amd64/arm64/386 交叉编译通过。Linux 目标机运行、生产高可用及故障切换仍待实际环境验证 |

统一验收入口参见 [engineering-validation.md](engineering-validation.md)。


## Latest code remediation

- 2026-11-24: P0-01 server policy Ed25519 signing (`policy_sign.py`) wired into heartbeat/sync policy delivery; `GET /api/agent/policy-pubkey`; P0-03 `recover_stuck_approvals` for interrupted `dispatching` rows; P0-04 `scripts/audit_admin_api_auth.py`; acceptance ledger `docs/p0-acceptance.md`. Golden message aligned with Agent Go tests. Physical Agent reinstall / HTTPS / DB failover / backup restore still require ops acceptance.

- 2026-11-24: Account database initialization now requires verified WAL mode and closes failed connections. Account creation, update, deletion and password changes serialize their read/write checks in database transactions; login rechecks account state before issuing a session. Ten isolated account/session regressions passed. This does not establish production multi-instance acceptance.

- 2026-11-23: Account mutation endpoints reject ambiguous JSON field types before changing account state; Linux metadata audit validates field types, score bounds, severity consistency, required fields and empty corpus handling. All 379 Linux TOML rule records pass these structural checks; actual detection accuracy remains unmeasured. 17 targeted session, metadata and readiness tests passed. No rule matching, detection configuration or release artifacts changed.

- 2026-11-23: Linux rule quality audit (read-only metadata): 379 TOML files parsed, no missing or duplicate rule IDs; 54 include false-positive guidance and 205 include references. Missing guidance is not itself proof of a false positive. Added `scripts/audit_linux_rule_metadata.py` and a synthetic metadata test; matching conditions, severity, and enabled status remain unchanged. Actual false-positive rates require reviewed alert samples. Also completed account-mutation cache protections and preserved existing HTTP Vary headers; 17 HTTP/session/origin/health checks passed.

- 2026-11-23: console login/logout, session, password-change and account-list responses now explicitly prohibit caching of private account/session data. Added regression coverage that a must-change administrator cannot access account listing while the session endpoint still permits password-reset UI. Nineteen session/origin/diagnostic/release-guard tests passed. MSI distribution remains disabled; no release protection was bypassed and no installer was generated.

- 2026-11-23: Windows release download now rejects contradictory `status`/`is_latest` metadata even when an older-release choice is requested; the front-end explicitly labels the current script ZIP and unreleased MSI state. 26 backend release/diagnostic/health/identity-preflight checks and 4 download UI checks passed; production frontend build passed. No MSI was generated or executed, and actual authenticated Agent download and MSI release acceptance remain open.

- 2026-11-23: read-only Windows release checks report amd64 and 386 `latest` with verified manifest integrity; ARM64 is `missing`. The existing Setup EXE is not Authenticode-signed and no MSI file was found under the Agent project directory. Added download route guard tests that reject unauthenticated/non-admin requests and missing releases before package generation. Twenty backend release/identity/diagnostic checks and four frontend download presentation/mock checks passed. An attempted local HTTP test-client run stalled and was stopped; no real installation package was generated, downloaded or executed, and MSI acceptance remains open.

- 2026-11-23: public `/health/ready` now exposes allowlisted component status fields instead of internal startup exceptions and database connection details. Unexpected storage readiness-check errors return controlled HTTP 503 without exposing exception text; liveness remains separate. Two added regressions plus existing startup, report-database and queue checks passed (15 tests). These are local/mock acceptance checks and do not verify real database outage recovery. The startup failure readiness latch and actual runtime storage connectivity remain separate concerns.

- 2026-11-23: report database connections now verify the actual WAL mode returned by SQLite and reject a silent mode mismatch. Added an isolated on-disk database test for committed visibility across two connections, rollback of an uncommitted fixture update and integrity after reopening. All 42 report-module tests passed; 14 targeted storage, readiness and queue checks also passed (with overlapping report tests). Real MySQL/Elasticsearch interruption, multi-process production sharing and physical power-loss acceptance remain pending.

- 2026-11-23: Web decomposition is now a long-term maintenance task; authenticated browser acceptance remains deferred. P0 diagnostic access recheck: both listing and download require admin access, and download requires the matching completed diagnostic record. Diagnostic history/file selection now skips non-regular and concurrently unavailable entries; read failures return a controlled error. Three synthetic regression checks were added. The 15 diagnostic/identity/install-preflight/approval-guard/release-guard tests and 9 isolated storage/queue recovery checks passed. The latter are not a real MySQL/Elasticsearch outage or multi-instance acceptance. No Agent package was published or deployed.

- 2026-11-22: restored the existing cases, host baseline and telemetry archive entries in the menu, persisted navigation whitelist and renderer dispatch. Reused a standalone `SummaryCards.vue` component for endpoint and storage statistics. All 31 frontend tests and the production build passed; authenticated real-data browser acceptance is still pending. Existing identity, installer preflight, approval uniqueness, release download and cursor pagination tests passed. Added an isolated on-disk SQLite test verifying rollback of an uncommitted synthetic approval status update, persistence of the duplicate guard after reopening, and database integrity; this does not constitute an end-to-end interruption/recovery acceptance. Final server policy signing, real reinstall identity acceptance, MSI publication, actual database failover/shared persistence, further pagination and Windows/ARM64 physical acceptance remain open.

- 2026-11-22: the console's threat view is protected against cyclic parent links, wrong-version asynchronous evidence and incorrect snapshot response decoding; the restored abnormal-process/external-network page chunks have explicit loading/error UI. 27 frontend tests and production build passed. Browser interaction with real data remains unverified. Windows amd64 release status is `latest` and its manifest hash verifies; x86/ARM64 release files are missing. Both the current Agent EXE and native Setup EXE report `NotSigned` via Authenticode; the MSI distribution gate remains closed pending independent installer verification and installation acceptance.

- Restored console routes for abnormal processes, external connections and files using their existing page components. Fixed the threat-view navigation regression caused by direct access to private response-composable state; details now open before the detail request completes. Added navigation regression checks; authenticated browser acceptance remains pending. The Windows MSI path remains intentionally disabled until the native installer has an independently verified release manifest.

- MySQL enabled now defaults to strict shared-storage behavior. Startup readiness and `/health/ready` fail when required MySQL is unavailable, and business API requests receive HTTP 503 rather than falling through to node-local SQLite.
- Agent legacy outbox import now leaves malformed queues untouched and does not archive the source if persistence fails. Outbox health reports whether its queue is durable; the in-memory fallback still needs deployment-side remediation if observed.
- Remaining high-impact architecture gap: several EDR subsystems still use node-local SQLite, so full shared persistence and automatic database failover are not implemented. Real Linux endpoint telemetry and abnormal-file rule hits still require terminal-side confirmation.
- Fixed post-split console routing: `HuntPage` and `PlatformExtras` were imported but not selected by the page renderer, leaving hunt/approval/case/baseline/archive and related routes blank. Routed them with their props/events and added explicit async-chunk loading/error UI. Frontend unit checks and production build pass; browser visual confirmation is still pending.
- Follow-up root-cause fix for blank console: Vue `<script setup>` bindings were not available through the instance proxy used by extracted page groups, so child templates received an empty context. Added lazy getter/setter bindings for page template dependencies and registered page-local components. SSR now renders the overview section; 11 frontend checks and production build pass.
