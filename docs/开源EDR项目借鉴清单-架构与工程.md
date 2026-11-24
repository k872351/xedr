# 开源 EDR 项目借鉴清单（架构 / 规则数据 / 质量保障 / 工程规范）

> 生成时间：2026-11-22
> 参考目录：`D:/360极速浏览器X下载/edr/`（EDR-DataProtector-main、openedr-main、wazuh-main）
> 视角说明：上一轮调研聚焦 UI / 可视化；**本轮专门看架构设计、规则与数据模型、质量保障、工程规范**——这些是自建项目更稀缺、也更难自己想到的部分。
> 核实方式：逐文件读取一手代码/文档，注明来源路径，并对照当前项目 `D:/GeRen/web/edr`。

---

## 先说结论：三个项目各有所长，别平均用力

| 项目 | 真实定位 | 对当前项目最值钱的部分 |
|---|---|---|
| **DataProtector** | 唯一带完整工程的产品级 EDR（内核驱动 + .NET 服务 + Vue 后台 + 沙箱/静态分析） | 架构铁律、模块解耦、内置 YARA 资产组织、AI 工程记忆文件 |
| **wazuh** | 成熟的开源 SOC 平台（规则/合规/API 极完备），Web UI 在独立仓库 | **SCA 合规检查数据模型**、164 条 CI、端到端测试体系、MITRE 建模 |
| **openedr** | C++ 采集 Agent，遥测落地 ElasticSearch | 基础事件粒度采集 + 本地缓存批量上报的**可恢复遥测架构** |

**一句话**：学 DataProtector 的"怎么把复杂系统拆干净"，学 wazuh 的"怎么把检测/合规做成数据"，学 openedr 的"怎么让遥测不丢"。

---

## 一、架构设计：最值得抄的是"分层铁律"

### 1. 内核轻、用户态重——一条写在文件里的架构铁律

来源：`EDR-DataProtector-main/README.zh-CN.md:116-125`、`AGENTS.md:22-45`

DataProtector 把一条原则当成**绑定式决策**写进项目记忆：

> 重型、规则驱动的扫描绝不放内核。内核只负责发现事件、捕获元数据、通知用户态；由签名用户态服务跑 YARA/规则引擎并返回裁决，内核只执行裁决。

理由写得很透：检测内容（YARA/签名/ML）必须能**不重签内核驱动就更新**；内核复杂解析 = 全集群蓝屏风险；新引擎要能在用户态即插即用。

**对照当前项目**：你的清单里正好有"内存扫描占用实时采集主路径""触发式扫描拖慢事件上报和心跳"两条。DataProtector 的做法给出了解法——**扫描交给有界的用户态工作队列，主采集路径只做事件捕获和持久化，裁决异步回挂**。这不是加个线程池那么简单，而是把"采集"和"研判"在架构上彻底分开。建议照这个思路重构 `agent/agent_loop.go` 的触发式扫描。

### 2. 一个能力一个服务类

来源：`EDR-DataProtector-main/DataProtectorWebBridge/Services/`（AgentSyncClient.cs、CentralPolicyStore.cs、StaticScanEngine.cs、YaraScanEngine.cs、RemoteTaskExecutor.cs、AuditLog.cs、VirtualSandboxRunner.cs 等十几个独立服务）

WebBridge 把每个能力拆成独立 Service 类，中心服务端 / 端点 Agent / 独立模式共用同一批服务。通信走稳定的 C ABI（`DataProtectorPolicyApi.dll`）和 HTTP。

**对照当前项目**：后端 246 个 py 模块虽然也拆得很细，但缺少"稳定接口层 + 能力服务层"的清晰分层。如果后续要做组件拆分（你清单里的长期项），可以参考这种"能力服务化 + 稳定 ABI 隔离"的边界划法。

### 3. 把架构决策写进项目文件（ADR 的轻量版）

来源：`EDR-DataProtector-main/AGENTS.md`——开头就写"这是 AI 和开发者的持久项目记忆，动手前先读，架构决策变了就更新"，然后把核心规则、理由、构建方式、组件清单全写进去。

**对照当前项目**：你有 `.workbuddy/memory/`（工作日志），但那是"发生了什么"，不是"为什么这么设计"。建议单独建一份 `docs/架构决策记录.md`，把"主机名不作身份""版本存 DB 不存进程内存""扫描不进主路径"这类关键决策连理由一起记下来——下次改代码或换 AI 接手时不会踩回去。

### 4. 快慢车道隔离——直接解决"慢任务延迟心跳"（高优先级）

来源：`openedr-main/edrav2/iprj/libedr/inc/lane.hpp`、`events.cpp`

openedr 把事件分发明确分成三条车道：`Fast`（进程内同步）、`SlowLocalFS`（本地磁盘队列）、`SlowNetwork`（网络上报）。快车道只做轻量排队，慢操作全部落到独立车道，绝不阻塞快路径。

**对照当前项目**：你的清单里明确提到"命令执行和同步在心跳主循环内同步处理，慢任务可能延迟下一次心跳"。这正是快慢车道要解决的问题——`agent/agent_loop.go` 里应把命令执行/内存扫描/规则同步从心跳主循环移到有界慢车道，心跳只走快车道。

### 5. 策略对账自愈（applied-rev + apply-status 双字段）

来源：`EDR-DataProtector-main/DataProtectorWebBridge/Services/AgentSyncClient.cs`（已验证 :47/:97/:225/:273）

Agent 心跳里同时上报 `appliedPolicyVersion`（已应用版本）和 `lastApplyStatus`（0x00000000=成功，非0=失败）。服务端发现版本落后**或**状态非成功时，立即下发完整策略重新对账（:225）。还会主动查询内核实际生效的策略（`QueryKernelUserHookDefensePolicy`，:273）与期望值比对，而不只看"我发过没发过"。

**对照当前项目**：清单里"服务端重启后在线 Agent 可能继续使用旧规则""策略回滚原因不明确"——这套"上报实际状态 + 服务端主动对账 + 查内核真值"正是答案。你有 `policy_state.go` 的 LKG 机制，缺的是把 applied-rev + apply-status 回传并让服务端据此自愈。

### 6. 插件/能力注册表 + 配置化管道

来源：`openedr-main/edrav2/iprj/prj/cppcore/`（component.hpp / core.hpp / object.hpp / config.hpp）+ `libedr/edr.hpp`

openedr 用 `REGISTER_PLUGIN` 宏把组件以名字注册进注册表，运行时按配置动态组装管道；核心库（`libcore`）完全不知道上层业务（`libedr`）。加新采集器 = 注册一个插件 + 加一段配置，不改主循环。

**对照当前项目**：246 个 py 模块虽多，但缺少统一的"能力注册表 + 配置驱动组装"机制，加采集点往往要改多处。如果这个解耦方向对你有价值，可以借鉴这种"注册即接入"的模式。

---

## 二、规则与数据模型：wazuh 的 SCA 是最大差距

### 1. 一条检查项 = 合规映射 + 修复建议 + ATT&CK 映射

来源：`wazuh-main/ruleset/sca/windows/cis_win11_enterprise.yml:22-70`（共 72 份 SCA 基线）

wazuh 的一条配置检查长这样（字段极丰富）：

- `policy`：id / name / description / references
- `requirements`：运行前提 + 条件
- `checks[]`：每条含 id / name / description / **rationale（为什么）** / **impact（影响）** / **remediation（怎么修）**
- `compliance`：一次映射到 PCI-DSS、GDPR、HIPAA、ISO-27001、NIST-800-53、NIST-800-171、FedRAMP、CIS、CMMC、NIS2、TSC 等十几种框架
- `mitre`：战术（TA0006 凭据访问等）+ 技术（T1078 有效账户等）

**对照当前项目（已按源码修正）**：`baselines/win11_baseline.json` 只有 1 份且是降噪白名单；但项目**已有 SCA 解析器** `backend/wazuh_ruleset.py`，`parse_sca_file()`（:89-130）会扫描 wazuh 的 `ruleset/sca/`。问题是它**只解析了一半字段**——`checks_out`（:106-118）保留了 id/name/condition/rule_kinds/agent_capable/mitre，却把 `compliance`、`rationale`、`remediation`、`description` **全部丢弃**（`grep compliance|remediation|rationale` 在该文件零命中）。所以缺口不是"没有解析器"，而是"合规数据被解析掉了"。

**可落地建议**：这是最划算的改进——`parse_sca_file()` 只需多保留几个字段（compliance 字典 + remediation），就能把现成的 72 份基线变成可展示的合规资产，前端加个"合规检查"视图即可。你清单里"Linux SCA 五项内置基线不宜展示为完整合规评估"——正好用这套数据模型做扎实。另外 wazuh 有专门的合规键合法性测试（`tests/.../cases_compliance_format.yaml`，白名单列出 10 个合法键），建议给 `scripts/validate_rules.py` 也加 `ALLOWED_COMPLIANCE_KEYS` 校验，非法键告警而非静默忽略。

### 2. MITRE 建成可查询关系表

来源：`wazuh-main/tools/mitre/mitredb.py:47-90`、`api/api/controllers/mitre_controller.py`

wazuh 把 `enterprise-attack.json`（STIX）落成 SQLAlchemy 关系表，`Technique` 带 `subtechnique_of / revoked_by / deprecated / mitre_version`，并建模 data_sources / defenses_bypassed / mitigate / phase 等关系；API 统一支持 `offset/limit/sort/search/select/q/distinct`。

**对照当前项目**：你有 `backend/mitre.py`。借鉴重点是**保留版本演进字段**（revoked_by / deprecated），以及统一检索参数约定——ATT&CK 每年更新，没有这些字段以后很难维护。

### 3. YARA 资产的工程化处理

来源：`EDR-DataProtector-main/third_party/yara-rules/README.md`

两个细节很实用（**已按实现代码修正，README 字面描述与实际不同**）：

- **"先逐个验证、再合并成单一对象"的隔离加载**：`YaraScanEngine.cs:381-387` 的实际做法是——先用一个一次性测试编译器逐个验证规则文件（坏文件跳过，不污染共享编译器），再把所有干净规则编译进**一个共享 YR_RULES 对象**，每个文件用唯一 namespace 避免标识符冲突。兼顾了"单文件失败不影响全局"和"内存有界（一个 arena 而非几千个）+ 扫描快（一次遍历而非 N 次）"。这比我最初据 README 写的"每文件独立对象"更优，是更值得抄的做法。
- **许可证合规清单**：明确列出每套规则的许可证（DRL 1.1 / GPL-2.0 / Elastic License 2.0 / MIT）及商用限制，并声明"仅内部测试用，商用前需替换"。

**对照当前项目**：YARA 资产其实比它更丰富（2759 vs 2317 个文件，含 valhalla-sigma），但缺这两件事：① 是否有"单文件失败隔离"机制值得检查；② 没有许可证说明，这些规则若来自公开仓库，商用时要能说清来源和授权。

---

## 三、质量保障：wazuh 的端到端测试是现成模板

### 1. 按守护进程/功能分目录的集成测试

来源：`wazuh-main/tests/integration/`——test_agentd / test_authd / test_api / test_enrollment / test_aws … 每个下面再分场景（CA rotation、startup hash validation、reenrollment、drop privileges…）

测试用 pytest + fixture 控制真实服务进程 + 模拟器（`RemotedSimulator`），能覆盖"重启/重连/注册/凭据轮换"这类状态机场景。

**对照当前项目**：你的清单里三条端到端验收缺口——"安装到首次上线""后台重启到策略恢复""审批到处置结果持久化"——wazuh 的 test_enrollment（含 reenrollment、CA rotation、startup hash validation）几乎是逐条对应的模板。当前项目有 **49 个 `test_*.py`（全在 backend/）+ 12 个 `*.test.js`**（口径说明：我初版写的"61"是全局混算，准确数字如此），且有 `scripts/check-edr.ps1` 统一检查入口和 `quality.yml` 两个 job，但测试多为单元/接口，缺这种带真实进程和模拟器的状态机测试。

### 2. 164 条 CI workflow

来源：`wazuh-main/.github/workflows/`——按用途前缀分类（4_builder* / 4_codeanalysis* / 4_testcomponent* / 4_testintegration_*），覆盖多平台构建、代码分析（coverity / bandit / clangformat）、按组件逐项测试。

**对照当前项目**：`quality.yml` 已有两个 job（quality + agent-matrix-smoke），且已更新为**不再默认 SkipAgent**（`-FullAgentTests` 全量 Go 测试）。借鉴点是**按组件拆分 CI 任务**、加变更驱动的按需测试，以及把 Agent 测试的"安装→验收→失败取证"补完整。（注：我初版据旧清单写的"用 SkipAgent 跳过"已过时，已在报告中修正。）

### 3. 样本回放框架——你清单里"样本回放"缺口的现成答案（高优先级）

来源：`wazuh-main/src/engine/tools/engine-suite/src/engine_test/README.md`（已验证真实存在）

`engine-test` 就是"规则回放/样本测试"工具：把样本日志送进隔离的测试 session，打印策略命中结果，还能输出每个 asset 的处理轨迹（`-d`）、过滤特定 asset（`-t`）、JSON 输出（`-j`）。测试 session 与生产隔离，不污染真实环境。CI 里有独立的 `4_testintegration_ruleset.yml` 流水线。

**对照当前项目**：`backend/test_elastic_detection_import.py` 只测"ID 命名/目录扫描"，`scripts/validate_rules.py` 只做 schema 校验——**没有任何"喂一条事件→看命中哪条规则→断言字段"的回放能力**。这正是你清单里"规则变更 diff、样本回放"想要的东西。

**可落地建议**：建 `tests/rule_replay/`，样本用 JSONL 且每条带 `expected: {rule_id, severity, mitre[]}`；实现一个 CLI 读样本 → 走 `backend/rules_loader.py` 匹配 → 输出命中并对比 expected；CI 中规则变更必须过回放。这是**当前检测体系最值得补的一块**。

---

## 四、威胁关联评分：DataProtector 的"分析大脑"（高优先级）

来源：`EDR-DataProtector-main/DataProtector/DpThreatEngine.c`（75KB，已验证）+ `DataProtector.h` + `AGENTS.md:81-91`

这是三个项目里唯一完整的"检测→评分→关联→响应"闭环，被称作 analytic brain。核心机制：

- **信号权重表**：35 个归一化信号，每个是 `{权重, 战术, ATT&CK技术号}`，如 `LsassHandleAccess={48, CredentialAccess, 1003}`、`RansomwareMassFileAccess={60, Impact, 1486}`；权重 1–60。
- **时间衰减**：30 秒衰减 8 分，孤立低权重信号自然消散。
- **同信号冷却 + 收益递减**：30 秒内重复信号权重减半（有下限）；同一技术第 3 次命中起给关联奖励。
- **跨战术关联奖励**：每多一个新战术 +12 分——"杀伤链 breadth 是最强入侵信号"。
- **血缘传播**：子进程得分向父进程传播，恶意 lineage root 与子孙一起处置。
- **分级响应**：阈值 30/60/90/130 → audit→alert→block→isolate→terminate，由策略 flag 决定允许到哪级。
- **攻击故事线**：48 步环形缓冲，按血缘根聚合成时间有序行为链。

**对照当前项目**：`config/correlation_rules.json` 已有 frequency/sequence/first_seen 三类，`backend/correlation_engine.py` 实现了匹配和去重表，`backend/agent_process_tree.py`、`backend/attack_story_format.py` 基础设施齐全——**但缺评分/衰减/冷却/跨战术奖励/血缘传播这套算法**。

**可落地建议**：把"信号→(权重,战术,技术号)"抽成可配置 JSON（扩展现有 `correlation_rules.json`），在 `correlation_engine.py` 加时间衰减 + 重复收益递减 + 跨战术奖励，利用 `agent_process_tree.py` 做父进程传播，用 `attack_story_format.py` 把孤立告警串成故事线。**这是让检测从"单规则命中"升级为"攻击链研判"的关键一步**。

---

## 五、可恢复遥测：openedr 的采集架构

来源：`openedr-main/README.md:10-12`、docs/screenshots/

openedr 的核心架构：以**基础事件粒度**采集 → Agent **本地缓存遥测** → **批量上报**到自托管 ElasticSearch → 上层做进程血缘关联和 MITRE 映射。

**对照当前项目**：清单里"遥测入库到检索做成可恢复流程""ES 恢复后已确认事件能补齐"——openedr 的"本地缓存 + 批量上报"正是这个模式。当前 `agent/agent_ingest_receipts.py`、`es_event_queue.db` 已经有回执和队列雏形，可以借鉴它把"持久队列 → 批量消费 → 稳定事件 ID"这条链路做完整。

---

## 六、工程规范与 CI 编排（当前项目投入产出比最高的洼地）

### 1. 根目录 5 个规范文件全部缺失（P0，成本极低）

实测当前项目根目录：**LICENSE / CONTRIBUTING.md / SECURITY.md / CHANGELOG.md / VERSION 全部没有**。可抄的模板：

- `SECURITY.md` ← wazuh `SECURITY.md`（版本日期、GHSA/CVE 分级、7 步披露流程、90 天时限、致谢）。注意别抄 openedr 的——它是未填充的占位模板（反面教材）。
- `CHANGELOG.md` ← wazuh `CHANGELOG.md`（按组件分块 × Added/Changed/Fixed 表格 + issue 链接）。Agent 已 0.13.6 且发布件 stale，这份文件很有必要。
- `VERSION.json` ← wazuh `VERSION.json`（`version + stage` 分离，CI 可用它选分支）。
- `CONTRIBUTING.md` ← openedr 的分支政策（只向 develop PR、main 保留发布历史）+ DataProtector 的 conventional commit 约定。
- `LICENSE` ← 三项目均有（GPLv2 / GPLv3 / MIT），按你的授权意愿选。

### 2. CI 编排：从"每次全跑"到"改哪测哪"

来源：wazuh `.github/actions/5_testintegration_detect-changes/action.yml` + `.github/test_modules_linux.json`

wazuh 用一份 JSON 声明"测试模块 ↔ 源码路径 glob ↔ tier ↔ timeout"，PR 时按 diff 匹配路径，只生成需要重跑的模块矩阵——164 个 workflow 不会每次全跑。workflow 本身用 `on.workflow_call` 做成"一个通用流水线 + N 个薄参数配置"。

**对照当前项目**：`quality.yml` 目前每次全跑、`check-edr.ps1` 已是统一入口。借鉴点：加一份"路径→测试模块"映射，配合 `-SkipAgent` 这类开关做按需触发；用 `pytest.ini` 的 `--strict-markers` + tier 标记（wazuh `tests/integration/pytest.ini`）分 tier0 快速门 / tier1 全量门。

### 3. PR 模板 Definition of Done + CHANGELOG 强制

来源：wazuh `.github/pull_request_template.md`、`.github/workflows/5_codequality_changelog.yml`

PR 模板把"完成定义"写成清单（各平台无警告编译、内存测试、结果与证据、配置变更、新增测试）；CHANGELOG 流水线用 `changelog-enforcer` 强制每个非 draft PR 必须改 CHANGELOG 或打 `no-changelog` 标签，且监听 `unlabeled` 防止骗绿。

### 4. 本地提交前质量门（git hooks）

来源：`DataProtectorWebAdmin/package.json:101-104`

```json
"simple-git-hooks": {
  "commit-msg": "pnpm sa git-commit-verify",
  "pre-commit": "pnpm typecheck && pnpm lint && pnpm fmt && git diff --exit-code"
}
```

`git diff --exit-code` 确保格式化没留下未提交改动，很巧妙。当前项目有 `check-edr.ps1` 但只在 CI 跑——配成 pre-commit 跑子集（后端 unittest + 依赖 pin 检查）收益很高。

### 5. 日志规范与配置分层

- wazuh `docs/ref/modules/logging/configuration.md`：五级日志（DEBUG/INFO/WARNING/ERROR/CRITICAL）+ 层级化 tag（`wazuh-manager-modulesd:vulnerability-scanner`）+ plain/json 双格式 + 结构化字段 + 按天/大小轮转。当前项目 `docs/telemetry_schema.md` 管的是遥测字段，日志文件本身缺类似规范。
- wazuh `etc/internal_options.conf`（默认值）+ `local_internal_options.conf`（本地覆盖，先读覆盖）+ DataProtector `.env`（把业务成功码/登出码/过期码抽到配置）。当前 `config/*.example.json` 方向正确，可再补"默认值 / 本地覆盖 / 环境覆盖"三层和响应码配置化。

### 6. 第三方组件许可证清单

DataProtector README 用整张表列明每个第三方组件（WDK、Ghidra、UPX、MinHook、YARA…）的位置、用途和许可证。当前项目 YARA/Sigma 规则资产庞大，同样建议补一份来源与授权说明。

---

## 七、落地建议（按性价比排序）

| 优先级 | 借鉴点 | 来源 | 当前收益 |
|---|---|---|---|
| **P0·极低成本** | **补齐根目录 5 个规范文件**（SECURITY/CHANGELOG/VERSION/CONTRIBUTING/LICENSE） | wazuh + openedr + DataProtector | 全缺；照模板改即可，Agent 已 0.13.6 亟需 CHANGELOG |
| **P0** | **样本回放回归框架**（`tests/rule_replay/` + CLI + CI 门禁） | wazuh `engine_test/README.md` | 直接填上清单"样本回放/规则 diff"缺口 |
| **P0** | **多信号风险评分**（衰减/冷却/跨战术奖励/血缘传播/故事线） | DataProtector `DpThreatEngine.c` | 检测从"单规则命中"升级为"攻击链研判"；基础设施已齐 |
| **P0** | **快慢车道隔离**（心跳走快车道，命令/扫描走有界慢车道） | openedr `lane.hpp` | 直接解清单"慢任务延迟心跳" |
| 高 | **策略对账自愈**（applied-rev + apply-status 上报 + 内核真值查询） | DataProtector `AgentSyncClient.cs` | 解"重启后 Agent 用旧规则""回滚原因不明" |
| 高 | SCA 合规字段补全（`wazuh_ruleset.py` 保留 compliance/remediation） | wazuh `ruleset/sca/` | 现成 72 份基线立刻变成合规资产，改动极小 |
| 高 | 端到端状态机测试 + Agent 安装包级 E2E 六步链 | wazuh `tests/integration/`、`5_testintegration_linux-integration-tests.yml` | 对上清单三条验收缺口；当前只有交叉编译 smoke，缺"装上真机跑通" |
| 高 | CI 按需测试（路径→模块 JSON 映射 + tier 分级 + PR DoD 模板） | wazuh `detect-changes/action.yml`、`pytest.ini` | 从"每次全跑"变"改哪测哪"，模块多后必须做 |
| 高 | MITRE `revoked_by/deprecated/data_source` | wazuh `tools/mitre/mitredb.py` | 当前中文目录无版本状态；补 data_source 可做覆盖度分析 |
| 高 | 扫描与采集解耦、有界工作队列 | DataProtector `AGENTS.md` | 解决"扫描拖慢主路径" |
| 中 | pre-commit git hooks（跑 check-edr.ps1 子集） | DataProtector `package.json:101` | 质量门左移到本地 |
| 中 | 合规键白名单 + 闭集字段 schema 校验 | wazuh `cases_compliance_format.yaml`、迁移文档 | 规则导入即校验，不等运行时静默失败 |
| 中 | YARA 先验证后合并加载 + 许可证清单 | DataProtector `YaraScanEngine.cs:381` | 单文件坏规则不拖垮全局 + 商用合规 |
| 中 | IOC NDJSON+MD5 增量同步 | wazuh `engine-test .../ioc/update.py` | 情报库增量同步 |
| 中 | 组件注册表 + 配置化管道 | openedr `cppcore/` REGISTER_PLUGIN | 加采集点不改主循环 |
| 中 | 本地缓存批量上报的可恢复遥测 | openedr README | ES 恢复后补齐已确认事件 |
| 中 | 日志规范 + 配置三层化 + ADR/AGENTS.md | wazuh logging 文档、DataProtector `AGENTS.md` | 可观测性与工程记忆 |

**一个关键提醒**：当前项目检测资产规模已经很大（`rules/linux` 379、`rules/windows` 499、`rules/cross-platform` 148、`rules/yara` 3636 个文件），**短板不在规则数量，而在"回放验证 + 信号级关联评分 + MITRE 版本治理"**。资源应集中在这三处，而不是继续堆规则。

**不建议做的**：直接搬 UI 组件（技术栈不同：它们是 Naive UI / SoybeanAdmin，你是自绘 Vue）；为了"功能全"去堆沙箱分析、USB 加密这类需要专门后端/驱动支撑的模块——没有对应的服务就只是空壳。

---

*说明：本清单为主持人一手核实 + 三个并行深挖任务交叉验证的结果。如后续发现新的可借鉴点，会补充到本文。*
