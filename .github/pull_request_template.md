## 变更说明

<!-- 一句话说明改了什么、为什么 -->

## 类型

- [ ] feat 新功能
- [ ] fix 修复
- [ ] refactor 重构
- [ ] perf 性能
- [ ] test 测试
- [ ] docs 文档
- [ ] chore 构建/CI/规则资产

## Definition of Done（完成定义）

> 借鉴 wazuh `.github/pull_request_template.md`。逐项确认，未涉及写 `N/A`。

### 构建与编译
- [ ] 后端 `python -m unittest discover -s backend -t . -p "test_*.py"` 通过
- [ ] Agent `cd agent && go build ./...` 无警告、`go test ./... -count=1` 通过
- [ ] 管理台 `cd agent_admin && npm test && npm run build` 通过
- [ ] `python tests/rule_replay/run_replay.py` 规则回放通过
- [ ] `python scripts/detect_changes.py --self-test` 通过（CI 映射未损坏）

### 结果与证据
- [ ] 附上关键验证输出/截图（不要只写「已测」）
- [ ] 涉及界面改动：附修改前后对比图
- [ ] 涉及协议/策略改动：说明对旧版本 Agent 的**兼容性**

### 配置与资产
- [ ] 未提交 `config/*.json`（含密钥）与 `*.json.local`
- [ ] 新增配置已补 `*.example.json` 模板字段与默认值
- [ ] 新增/改动检测规则：已补一条回放样本（`tests/rule_replay/samples/`）
- [ ] 引入外部规则/依赖：已登记 `docs/第三方组件许可证清单.md`（来源 + 授权 + 商用限制）

### 测试
- [ ] 新增逻辑有对应单测（后端 `backend/test_*.py` / Agent `agent/*_test.go` / 前端 `*.test.js`）
- [ ] 涉及状态机（注册/心跳/策略/命令/处置）：已评估是否需补端到端用例
- [ ] 未削弱既有断言、未跳过失败用例

### 文档与记忆
- [ ] `CHANGELOG.md` 已更新（或标注 `no-changelog` 标签并说明原因）
- [ ] 涉及架构决策：已更新 `docs/架构决策记录.md` 与 `AGENTS.md`
- [ ] 涉及安全：已按 `SECURITY.md` 评估

### 自查
- [ ] 未把慢任务放回心跳主循环（ADR-005）
- [ ] 未用主机名推导终端身份（ADR-001）
- [ ] 未在日志中输出密钥/token（见 `docs/日志规范.md`）
- [ ] 提交信息符合 Conventional Commits（见 `CONTRIBUTING.md`）

## 关联

- 相关 issue / 文档：
- 影响的模块（backend / agent / web / rules / ci）：
