<template>
<section v-if="page === 'rules'" class="page rules-page">
        <header class="page-hd">
          <div>
            <h1>Agent 规则</h1>
            <p class="desc">检出规则 / 日志规则 / 内存 YARA / 告警加白。日志规则命中后进入「威胁事件」（标题「日志规则：…」），不在规则页本身列表。</p>
          </div>
          <div class="hd-right">
            <template v-if="rulesSection === 'detect'">
              <button type="button" class="btn" @click="loadRules">刷新</button>
              <button type="button" class="btn primary" @click="startCreateRule">新增规则</button>
            </template>
            <template v-else-if="rulesSection === 'abfile'">
              <button type="button" class="btn" @click="loadRules">刷新</button>
              <button type="button" class="btn primary" @click="startCreateAbfileRule">新增异常文件规则</button>
            </template>
            <template v-else-if="rulesSection === 'logrules'">
              <button type="button" class="btn" @click="openLogRuleAlerts">查看告警</button>
              <button type="button" class="btn" :disabled="logRulesBusy" @click="loadLogRules(false)">
                {{ logRulesBusy ? '加载中…' : '刷新' }}
              </button>
              <button type="button" class="btn primary" :disabled="logRulesBusy" @click="loadLogRules(true)" title="从磁盘重新扫描 YAML（改规则文件后用）">
                重新索引
              </button>
            </template>
            <template v-else-if="rulesSection === 'whitelist'">
              <button type="button" class="btn" @click="loadWhitelistOnly">刷新</button>
              <button type="button" class="btn sm" @click="goMenu('policy')">EDR 策略（完整）</button>
            </template>
            <button
              v-else
              type="button"
              class="btn primary"
              :disabled="memoryYaraBusy"
              @click="loadMemoryYara"
            >
              {{ memoryYaraBusy ? '加载中…' : '刷新规则包' }}
            </button>
          </div>
        </header>

        <nav class="rules-subnav" role="tablist" aria-label="规则分类">
          <button
            type="button"
            role="tab"
            class="rules-tab"
            :class="{ on: rulesSection === 'detect' }"
            :aria-selected="rulesSection === 'detect'"
            @click="rulesSection = 'detect'"
          >
            检出规则
            <span class="rules-tab-meta">{{ agentRules.length }} 条</span>
          </button>
          <button
            type="button"
            role="tab"
            class="rules-tab"
            :class="{ on: rulesSection === 'abfile' }"
            :aria-selected="rulesSection === 'abfile'"
            @click="rulesSection = 'abfile'; loadRules()"
          >
            异常文件规则
            <span class="rules-tab-meta">{{ abfileRules.length }} 条</span>
          </button>
          <button
            type="button"
            role="tab"
            class="rules-tab"
            :class="{ on: rulesSection === 'logrules' }"
            :aria-selected="rulesSection === 'logrules'"
            @click="openRulesLogSection"
          >
            日志规则
            <span v-if="logRulesPack?.ok" class="rules-tab-meta">{{ logRulesPack.loaded?.count || 0 }} 已加载</span>
          </button>
          <button
            type="button"
            role="tab"
            class="rules-tab"
            :class="{ on: rulesSection === 'memory' }"
            :aria-selected="rulesSection === 'memory'"
            @click="openRulesMemorySection"
          >
            内存 YARA
            <span v-if="memoryYaraPack?.ok" class="rules-tab-meta">
              {{ memoryYaraPack.rule_count ?? (memoryYaraPack.items || []).length }} 字符串
            </span>
          </button>
          <button
            type="button"
            role="tab"
            class="rules-tab"
            :class="{ on: rulesSection === 'whitelist' }"
            :aria-selected="rulesSection === 'whitelist'"
            @click="openRulesWhitelistSection"
          >
            告警加白
            <span class="rules-tab-meta">{{ whitelistEnabledCount }}/{{ whitelist.length }}</span>
          </button>
        </nav>

        <div v-if="agentSyncManifest?.ok" class="agent-sync-wrap">
          <div class="agent-sync-bar">
            <span
              class="agent-sync-rev"
              title="sync_rev：服务端「下发版本号」。Agent 心跳/同步时带上本地 rev，若小于此值则拉取 EVM、策略、集成开关等；改规则或下方开关保存后会自动 +1。"
            >
              sync_rev <b class="mono">{{ agentSyncManifest.sync_rev }}</b>
            </span>
            <span class="muted mono" title="各配置块 hash 聚合">agg {{ agentSyncManifest.aggregate_hash }}</span>
            <span v-if="agentIntegrations?.server" class="muted sm" title="云端入库检测开关">
              云端：EVM {{ agentIntegrations.server.evm_ingest !== false ? '开' : '关' }}
              · LOLBin {{ agentIntegrations.server.lolbin_ingest !== false ? '开' : '关' }}
            </span>
            <button type="button" class="btn sm" :disabled="agentSyncBusy" @click="loadAgentSyncManifest">
              {{ agentSyncBusy ? '…' : '刷新摘要' }}
            </button>
            <button
              type="button"
              class="btn sm"
              :class="{ on: agentIntegrationsOpen }"
              @click="toggleAgentIntegrationsPanel"
            >
              端上能力开关
            </button>
            <button
              v-if="isAdmin"
              type="button"
              class="btn sm ghost"
              :disabled="agentSyncBumpBusy"
              title="不修改配置，仅递增 sync_rev，促使 Agent 尽快重新拉取"
              @click="manualBumpAgentSync"
            >
              {{ agentSyncBumpBusy ? '…' : '强制同步' }}
            </button>
          </div>
          <div v-if="agentIntegrationsOpen && agentIntegrations?.ok" class="agent-int-panel panel pad">
            <div class="agent-int-intro">
              <p>
                <span class="pill sm on">端上</span>
                改后 <code class="mono">sync_rev</code> +1，终端约 1–2 分钟内同步。
                <span class="pill sm cloud">云端</span>
                时间线入库后在服务端匹配，<strong>立即生效</strong>、与端上 EVM 独立。
              </p>
              <p v-if="!isAdmin" class="warn sm">需管理员账号才能修改开关。</p>
            </div>

            <details v-if="agentSyncManifest?.parts" class="agent-sync-parts">
              <summary>配置块摘要（policy / evm / memory_yara …）</summary>
              <div class="agent-sync-parts-grid">
                <div
                  v-for="(p, key) in agentSyncManifest.parts"
                  :key="key"
                  class="agent-sync-part-cell"
                  :title="JSON.stringify(p)"
                >
                  <span class="part-name">{{ key }}</span>
                  <code class="mono">{{ p.rev || p.hash }}</code>
                </div>
              </div>
            </details>

            <section
              v-for="grp in AGENT_INTEGRATION_GROUPS"
              :key="grp.id"
              class="agent-int-section"
            >
              <h4 class="agent-int-hd">{{ grp.title }}</h4>
              <p v-if="grp.hint" class="hint sm agent-int-grp-hint">{{ grp.hint }}</p>
              <div class="agent-int-cards">
                <div
                  v-for="key in grp.keys"
                  :key="'a-' + key"
                  class="agent-int-card"
                  :class="{ off: agentIntegrations.defaults?.[key] === false }"
                >
                  <label class="agent-int-switch" :title="key">
                    <input
                      type="checkbox"
                      :disabled="!isAdmin || agentIntegrationsBusy"
                      :checked="agentIntegrations.defaults?.[key] !== false"
                      @change="setAgentIntegration(key, $event.target.checked)"
                    />
                    <span class="agent-int-switch-ui" aria-hidden="true" />
                  </label>
                  <div class="agent-int-card-text">
                    <span class="agent-int-card-title">{{ agentIntegrations.labels?.[key] || key }}</span>
                    <code class="agent-int-card-key mono">{{ key }}</code>
                  </div>
                </div>
              </div>
            </section>

            <section class="agent-int-section agent-int-section-cloud">
              <h4 class="agent-int-hd">云端（服务端入库）</h4>
              <p class="hint sm">{{ agentIntegrations.server_note }}</p>
              <div class="agent-int-cards compact">
                <div
                  v-for="key in SERVER_DETECTION_UI_KEYS"
                  :key="'s-' + key"
                  class="agent-int-card"
                  :class="{ off: agentIntegrations.server?.[key] === false }"
                >
                  <label class="agent-int-switch" :title="key">
                    <input
                      type="checkbox"
                      :disabled="!isAdmin || agentIntegrationsBusy"
                      :checked="agentIntegrations.server?.[key] !== false"
                      @change="setServerDetection(key, $event.target.checked)"
                    />
                    <span class="agent-int-switch-ui" aria-hidden="true" />
                  </label>
                  <div class="agent-int-card-text">
                    <span class="agent-int-card-title">{{ agentIntegrations.labels?.[key] || key }}</span>
                    <code class="agent-int-card-key mono">{{ key }}</code>
                  </div>
                </div>
              </div>
            </section>

            <details class="agent-deploy-ref">
              <summary>互联网 / 大规模 Agent 在线 — 环境与容量参考</summary>
              <div class="agent-deploy-body">
                <div class="agent-deploy-cols">
                  <div>
                    <h5>基础环境</h5>
                    <ul>
                      <li><strong>公网入口</strong>：HTTPS（TLS 1.2+），建议 WAF + 限流；Agent 仅走 <code class="mono">/api/agent/*</code>，管理台独立域名或 IP 白名单。</li>
                      <li><strong>反向代理</strong>：Nginx / Caddy；长连接 SSE 需调大 <code class="mono">proxy_read_timeout</code>（建议 ≥300s）。</li>
                      <li><strong>应用</strong>：Python 3.10+，Uvicorn/Gunicorn 多 worker（CPU 核数或 2×核）；静态管理台可 CDN。</li>
                      <li><strong>Redis</strong>（推荐）：会话、去重、live 计数；配置见 <code class="mono">redis_config.json</code> / 环境变量。</li>
                      <li><strong>Elasticsearch</strong>（可选）：时间线/狩猎检索；无 ES 时核心告警仍走 SQLite。</li>
                      <li><strong>磁盘</strong>：<code class="mono">reports/agents.db</code> 与日志分区；时间线量大时单独数据盘，定期归档。</li>
                    </ul>
                  </div>
                  <div>
                    <h5>并发与在线规模（经验值）</h5>
                    <ul>
                      <li>默认心跳 <code class="mono">heartbeat_sec≈3</code>：1000 在线 ≈ <strong>330 次/秒</strong> 心跳；5000 在线 ≈ <strong>1600+ 次/秒</strong>。上万 Agent 建议策略里改为 <strong>15–30s</strong> 心跳。</li>
                      <li>时间线批量上报与快照：峰值取决于 ETW 开项；开满 <code class="mono">sensor-etw-proc</code> 类 info 进程会显著增流量，生产可关纯遥测、保留 LOLBin/EVM 相关。</li>
                      <li>内存 YARA / 全量 ETW：主要吃<strong>终端 CPU/内存</strong>；服务端按入库 QPS 扩容 worker 与 DB。</li>
                      <li><strong>SQLite 单写</strong>：适合百～数千 Agent；<strong>5000+ 长期在线</strong> 建议规划 PostgreSQL + 队列（当前代码以 SQLite 为主，需架构升级）。</li>
                    </ul>
                  </div>
                  <div>
                    <h5>安全与网络</h5>
                    <ul>
                      <li>Agent 安装包内嵌密钥，公网务必<strong>一机一密 / 定期轮换</strong>，禁用弱共享密钥。</li>
                      <li>出站：终端需能访问平台 <code class="mono">443</code>；无需 inbound 到终端。</li>
                      <li>关 <code class="mono">wmi_process</code> 可减 WMI 负载（默认关）；关 <code class="mono">winevent</code> 仅在有 ETW 时考虑。</li>
                    </ul>
                  </div>
                </div>
                <p class="hint sm">
                  以上为当前 Forensic Agent 架构下的部署参考，非硬性 SLA；实际上线前请用目标 Agent 数量做压测（心跳 + 时间线 + 规则 sync 各一轮）。
                </p>
              </div>
            </details>

            <p v-if="agentIntegrationsErr" class="err-text">{{ agentIntegrationsErr }}</p>
          </div>
        </div>

        <div v-show="rulesSection === 'detect'" class="rules-layout">
          <div class="panel fill">
            <div class="panel-hd">
              <h3>规则列表 ({{ filteredAgentRules.length }} / {{ agentRules.length }})</h3>
              <span class="meta">启用 {{ agentRules.filter(r => r.enabled).length }} 条</span>
            </div>
            <div class="rules-toolbar">
              <div class="rules-filter-row">
                <span class="rules-toolbar-label">筛选</span>
                <div class="chip-row rules-filter-chips">
                  <button type="button" class="chip-btn" :class="{ on: rulesFilter === 'all' }" @click="rulesFilter = 'all'">全部</button>
                  <button type="button" class="chip-btn" :class="{ on: rulesFilter === 'sensor' }" @click="rulesFilter = 'sensor'">内置传感器</button>
                  <button type="button" class="chip-btn" :class="{ on: rulesFilter === 'custom' }" @click="rulesFilter = 'custom'">快照规则</button>
                  <button type="button" class="chip-btn" :class="{ on: rulesFilter === 'elastic' }" @click="rulesFilter = 'elastic'">Elastic</button>
                  <button type="button" class="chip-btn linux-chip" :class="{ on: rulesFilter === 'linux' }" @click="rulesFilter = 'linux'">Linux</button>
                </div>
              </div>
              <div v-if="isAdmin" class="rules-bulk-bar">
                <div class="rules-bulk-card">
                  <span class="rules-bulk-card-hd">当前筛选</span>
                  <div class="rules-bulk-pair">
                    <button type="button" class="rbb on" :disabled="rulesBulkBusy || !filteredAgentRules.length" @click="bulkRulesEnabled(true)">
                      {{ rulesBulkBusy ? '…' : '全部开启' }}
                    </button>
                    <button type="button" class="rbb off" :disabled="rulesBulkBusy || !filteredAgentRules.length" @click="bulkRulesEnabled(false)">
                      全部关闭
                    </button>
                  </div>
                </div>
                <div class="rules-bulk-card elastic">
                  <span class="rules-bulk-card-hd">Elastic</span>
                  <div class="rules-bulk-actions">
                    <div class="rules-bulk-pair" title="Elastic 快照规则">
                      <em>快照</em>
                      <button type="button" class="rbb on" :disabled="rulesBulkBusy" @click="bulkElasticRules(true)">开</button>
                      <button type="button" class="rbb off" :disabled="rulesBulkBusy" @click="bulkElasticRules(false)">关</button>
                    </div>
                    <div class="rules-bulk-pair" title="Elastic EVM 规则">
                      <em>EVM</em>
                      <button type="button" class="rbb on" :disabled="rulesBulkBusy" @click="bulkElasticEvm(true)">开</button>
                      <button type="button" class="rbb off" :disabled="rulesBulkBusy" @click="bulkElasticEvm(false)">关</button>
                    </div>
                  </div>
                </div>
                <div v-if="linuxRuleCounts.total" class="rules-bulk-card linux">
                  <span class="rules-bulk-card-hd">Linux 规则</span>
                  <div class="rules-bulk-pair">
                    <button type="button" class="rbb on" :disabled="rulesBulkBusy || !linuxRuleCounts.total" @click="bulkLinuxRules(true)">全部开启</button>
                    <button type="button" class="rbb off" :disabled="rulesBulkBusy || !linuxRuleCounts.total" @click="bulkLinuxRules(false)">全部关闭</button>
                  </div>
                  <small>{{ linuxRuleCounts.total }} 条（Agent {{ linuxRuleCounts.agent }} / EVM {{ linuxRuleCounts.evm }}）</small>
                </div>
              </div>
              <p v-else class="hint sm rules-bulk-hint">批量开启/关闭需管理员账号；单条规则可用左侧「启用」开关（若账号有权限）。</p>
            </div>
            <div class="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>启用</th>
                    <th>标题</th>
                    <th>来源</th>
                    <th>级别</th>
                    <th>类型 / 关键字</th>
                    <th>说明</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody v-for="group in groupedAgentRules" :key="group.key">
                  <tr class="rule-platform-heading" :data-platform="group.key">
                    <td colspan="7"><strong>{{ group.label }}</strong><span>{{ group.rows.filter(r => r.enabled).length }} / {{ group.rows.length }} 已开启</span></td>
                  </tr>
                  <tr
                    v-for="r in group.rows"
                    :key="r.id"
                    class="row-click"
                    :class="{ active: editingRule?.id === r.id && !ruleCreating }"
                    @click="startEditRule(r)"
                  >
                    <td @click.stop>
                      <label class="switch">
                        <input type="checkbox" :checked="r.enabled" @change="toggleRule(r, $event.target.checked)" />
                        <i />
                      </label>
                    </td>
                    <td>
                      <b class="strong">{{ r.title }}</b>
                      <div class="meta">{{ r.id }}</div>
                    </td>
                    <td>
                      <span v-if="r.builtin || r.source === 'sensor'" class="pill on">内置传感器</span>
                      <span v-else-if="isElasticRule(r)" class="pill on accent">
                        {{ r.rule_channel === 'evm' || /\.(evm|fim)$/i.test(String(r.id || '')) ? 'Elastic EVM' : 'Elastic 快照' }}
                      </span>
                      <span v-else class="pill">快照规则</span>
                    </td>
                    <td><span class="sev" :data-s="r.severity">{{ sevLabel(r.severity) }}</span></td>
                    <td class="muted">
                      <template v-if="r.builtin || r.source === 'sensor'">
                        <div>{{ r.etype || 'timeline' }}</div>
                        <div v-if="r.summary_contains" class="meta">关键字：{{ r.summary_contains }}</div>
                      </template>
                      <template v-else-if="isElasticRule(r) && (r.rule_channel === 'evm' || r.etype)">
                        <div>{{ r.etype || 'timeline' }}</div>
                        <div v-if="(r.patterns || []).length" class="meta">{{ (r.patterns || []).slice(0, 2).join(' / ') }}{{ (r.patterns || []).length > 2 ? '…' : '' }}</div>
                      </template>
                      <template v-else>
                        <div>{{ (r.modules || []).map(modLabel).join('、') || '—' }}</div>
                        <div v-if="(r.patterns || []).length" class="meta">{{ (r.patterns || []).slice(0, 2).join(' / ') }}{{ (r.patterns || []).length > 2 ? '…' : '' }}</div>
                      </template>
                    </td>
                    <td class="muted" :title="r.note">{{ r.note || '—' }}</td>
                    <td class="ops" @click.stop>
                      <button type="button" class="link" @click="startEditRule(r)">编辑</button>
                      <button
                        v-if="!(r.builtin || r.source === 'sensor')"
                        type="button"
                        class="link danger"
                        @click="removeRule(r)"
                      >删除</button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-if="!filteredAgentRules.length" class="empty">当前筛选下无规则</p>
            </div>
          </div>

          <aside class="panel pad rule-editor">
            <h3>{{ ruleCreating ? '新增规则' : (editingRule ? ((editingRule.builtin || editingRule.source === 'sensor') ? '编辑内置传感器' : (isEditingElastic ? 'Elastic 规则' : '编辑规则')) : '规则编辑') }}</h3>
            <p v-if="!ruleCreating && !editingRule" class="hint rule-editor-pad">选中左侧规则编辑，或点击「新增规则」。下方可选快速模板一键填充。</p>
            <div v-if="ruleCreating || editingRule" class="rule-editor-body">
              <p v-if="isEditingElastic" class="hint warn">
                本端为从 Elastic 官方 query 抽取的<strong>子串近似</strong>，不是 Stack 上完整的 EQL/KQL（无 AND/序列/索引条件）。
                误报多时可先关闭「Elastic 快照」、仅保留 EVM，或到 Elasticsearch 引擎跑完整规则。
              </p>
              <div v-if="isEditingElastic" class="form-lab">
                <span>Elastic 官方 query（只读）</span>
                <p v-if="elasticOfficialBusy" class="muted">加载官方规则…</p>
                <template v-else-if="elasticOfficialDetail?.ok">
                  <p class="meta mono">{{ elasticOfficialDetail.rel_path }} · {{ elasticOfficialDetail.language || elasticOfficialDetail.type }}</p>
                  <textarea class="field area mono" rows="8" readonly :value="elasticOfficialDetail.query || '（无 query 字段）'" />
                  <p class="hint">{{ elasticOfficialDetail.official_note }}</p>
                </template>
                <p v-else class="muted">{{ elasticOfficialDetail?.error || '未加载官方 query' }}</p>
              </div>
              <p v-if="isEditingSensor" class="hint">
                数据源固定为时间线传感器；命中条件见下方「规则内容」。规则 ID 不可改、不可删；可恢复默认。
              </p>
              <div v-if="isEditingSensor" class="sensor-rule-card">
                <h4>规则内容</h4>
                <div class="sensor-rule-row"><span>规则 ID</span><code class="mono">{{ editingRule.id }}</code></div>
                <div class="sensor-rule-row"><span>事件类型</span><b class="mono">{{ ruleForm.etype || editingRule.etype || '—' }}</b></div>
                <div class="sensor-rule-row">
                  <span>摘要关键字</span>
                  <b>{{ (ruleForm.patternsText || '').split('\n').map((s) => s.trim()).filter(Boolean)[0] || editingRule.summary_contains || '—' }}</b>
                </div>
                <div class="sensor-rule-row"><span>规则说明</span><p>{{ ruleForm.note || editingRule.note || '—' }}</p></div>
                <div v-if="(ruleForm.patternsText || '').split('\n').filter((s) => s.trim()).length > 1" class="sensor-rule-row">
                  <span>全部特征</span>
                  <pre class="mono">{{ ruleForm.patternsText }}</pre>
                </div>
              </div>
              <div v-if="ruleCreating" class="form-lab">
                <span>快速模板</span>
                <div class="chip-row">
                  <button
                    v-for="t in RULE_TEMPLATES"
                    :key="t.id"
                    type="button"
                    class="chip-btn"
                    @click="applyRuleTemplate(t)"
                  >{{ t.label }}</button>
                </div>
              </div>
              <label v-if="isEditingSensor" class="form-lab">
                <span>规则 ID</span>
                <input class="field mono" :value="editingRule.id" disabled />
              </label>
              <label class="form-lab">
                <span>标题 *</span>
                <input v-model="ruleForm.title" class="field" placeholder="例如：PowerShell 编码执行" />
              </label>
              <label class="form-lab">
                <span>严重级别</span>
                <select v-model="ruleForm.severity" class="field">
                  <option value="critical">严重</option>
                  <option value="high">高危</option>
                  <option value="medium">中危</option>
                  <option value="low">低危</option>
                  <option value="info">信息</option>
                </select>
              </label>
              <template v-if="isEditingSensor || isEditingEvmOnly">
                <label class="form-lab">
                  <span>事件类型 (etype)</span>
                  <input v-model="ruleForm.etype" class="field" :disabled="isEditingEvmOnly" placeholder="如 file_create / process_create_etw" />
                </label>
              </template>
              <div v-if="!isEditingEvmOnly" class="form-lab">
                <span>{{ isEditingSensor ? '数据源' : '适用模块 *（可多选）' }}</span>
                <div v-if="isEditingSensor" class="sensor-source">
                  <span class="pill on">时间线传感器</span>
                  <small>由事件类型 etype 决定采集通道</small>
                </div>
                <div class="mod-pills">
                  <button
                    v-if="!isEditingSensor"
                    v-for="m in Object.keys(LABELS)"
                    :key="m"
                    type="button"
                    class="mod-pill"
                    :class="{ on: ruleForm.modules.includes(m) }"
                    @click="toggleRuleModule(m)"
                  >{{ LABELS[m] }}</button>
                </div>
              </div>
              <div class="form-lab">
                <span>文件类型（可选，限制扩展名；空=不限）</span>
                <div class="chip-row">
                  <button
                    v-for="ext in FILE_EXT_OPTIONS"
                    :key="ext"
                    type="button"
                    class="chip-btn"
                    :class="{ on: ruleForm.fileExts.includes(ext) }"
                    @click="toggleFileExt(ext)"
                  >.{{ ext }}</button>
                </div>
                <input
                  v-model="ruleForm.fileExtsText"
                  class="field"
                  style="margin-top:8px"
                  placeholder="也可手写：exe,dll,ps1"
                  @change="syncFileExtsFromText"
                />
              </div>
              <label class="form-lab">
                <span>签名条件</span>
                <select v-model="ruleForm.signedFilter" class="field">
                  <option value="">不限</option>
                  <option value="unsigned">仅未签名 / 签名异常</option>
                  <option value="signed">仅有效签名</option>
                </select>
              </label>
              <label class="form-lab">
                <span>路径前缀（可选，逗号分隔）</span>
                <input v-model="ruleForm.pathPrefixesText" class="field" placeholder="例如 C:\ 或 C:\Users\ 限制命中范围" />
                <p class="hint" style="margin:6px 0 0">
                  盘符根投放：regex
                  <code class="mono">^[A-Za-z]:\\[^\\]+\.(exe|dll|…)$</code>，模块 file+process。
                  ProgramData/Temp 未签名：路径前缀
                  <code class="mono">C:\ProgramData,C:\Windows\Temp</code>，签名选「仅未签名」，扩展名 exe,dll,…，特征填
                  <code class="mono">*</code>（已内置规则 agent-progdata-temp-unsigned）。
                </p>
              </label>
              <div class="form-lab">
                <span>匹配字段</span>
                <div class="chip-row sm">
                  <button
                    v-for="f in suggestedFields"
                    :key="f"
                    type="button"
                    class="chip-btn"
                    :class="{ on: fieldsSet.has(f) }"
                    @click="toggleField(f)"
                  >{{ COL_LABELS[f] || f }}</button>
                </div>
                <input v-model="ruleForm.fieldsText" class="field" style="margin-top:8px" placeholder="path,command_line,name" />
              </div>
              <label class="form-lab">
                <span>匹配特征 *（每行一条）</span>
                <textarea v-model="ruleForm.patternsText" class="field area" rows="5" placeholder="-enc &#10;\\temp\\" />
              </label>
              <label class="form-lab">
                <span>匹配方式</span>
                <select v-model="ruleForm.match" class="field">
                  <option value="substring">包含（推荐）</option>
                  <option value="regex">正则</option>
                  <option value="exact">精确</option>
                </select>
              </label>
              <label class="form-lab">
                <span>备注</span>
                <input v-model="ruleForm.note" class="field" placeholder="可选说明" />
              </label>
              <label class="chk">
                <input type="checkbox" v-model="ruleForm.enabled" />
                启用此规则
              </label>
              <p v-if="ruleFormError" class="err-text">{{ ruleFormError }}</p>
              <div class="row rule-editor-actions">
                <button
                  v-if="!isEditingEvmOnly"
                  type="button"
                  class="btn primary"
                  :disabled="ruleSaving"
                  @click="saveRuleForm"
                >
                  {{ ruleSaving ? '保存中…' : '保存' }}
                </button>
                <p v-else class="hint">EVM 规则在 <code class="mono">elastic_evm_import.json</code> 中维护；此处仅查看与开关。</p>
                <button
                  v-if="isEditingSensor"
                  type="button"
                  class="btn"
                  :disabled="ruleSaving"
                  @click="resetSensorRule"
                >恢复默认</button>
                <button type="button" class="btn" @click="cancelRuleForm">取消</button>
              </div>
            </div>
          </aside>
        </div>

        <div v-show="rulesSection === 'abfile'" class="rules-layout">
          <div class="panel fill">
            <div class="abfile-result-note" role="note">
              <span>异常文件查询与告警记录分别展示。规则保存后，可在异常文件页面查询已记录文件事件的匹配结果；查询命中不等同于已生成告警。</span>
              <button type="button" class="btn sm" @click="goMenu('abnormal-files')">查看异常文件</button>
            </div>
            <div class="panel-hd">
              <h3>异常文件规则 ({{ abfileRules.length }})</h3>
              <span class="meta">匹配当天新增文件的路径 / 文件名 / 扩展名</span>
            </div>
            <p class="hint sm" style="padding:0 14px 8px;margin:0">
              路径前缀：<code class="mono">C:\Users\Public\</code> = 该目录及<strong>所有子目录</strong>；
              末尾多写一个 <code class="mono">\</code>（如 <code class="mono">C:\Users\Public\\</code>）= <strong>仅该目录根一层</strong>。
              特征可填 <code class="mono">*</code>，只靠前缀/扩展名约束。命中在「异常文件」页高亮。
            </p>
            <div class="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>启用</th>
                    <th>标题</th>
                    <th>严重级别</th>
                    <th>路径前缀</th>
                    <th>扩展名</th>
                    <th>特征</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="r in abfileRules"
                    :key="r.id"
                    :class="{ on: editingRule?.id === r.id }"
                    @click="startEditRule(r)"
                  >
                    <td @click.stop>
                      <input type="checkbox" :checked="r.enabled !== false" @change="toggleRule(r, $event.target.checked)" />
                    </td>
                    <td>{{ r.title }}</td>
                    <td><span class="sev" :data-s="r.severity">{{ sevLabel(r.severity) }}</span></td>
                    <td class="mono muted">{{ (r.path_prefixes || []).join(', ') || '—' }}</td>
                    <td class="mono muted">{{ (r.file_exts || []).join(',') || '不限' }}</td>
                    <td class="mono muted">{{ (r.patterns || []).slice(0, 2).join(' · ') || '—' }}</td>
                    <td>
                      <button type="button" class="btn-text sm" @click.stop="startEditRule(r)">编辑</button>
                      <button v-if="isAdmin" type="button" class="btn-text sm danger" @click.stop="removeRule(r)">删除</button>
                    </td>
                  </tr>
                  <tr v-if="!abfileRules.length">
                    <td colspan="7" class="empty">暂无异常文件规则，点右上角「新增异常文件规则」</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <aside class="panel rule-editor" v-if="ruleCreating || (editingRule && isAbfileRule(editingRule))">
            <div class="panel-hd bare">
              <h3>{{ ruleCreating ? '新增异常文件规则' : '编辑异常文件规则' }}</h3>
            </div>
            <div class="rule-form">
              <label>
                <span>标题 *</span>
                <input v-model="ruleForm.title" class="field" placeholder="例如：Temp 目录投放 exe" />
              </label>
              <label>
                <span>严重级别</span>
                <select v-model="ruleForm.severity" class="field">
                  <option value="critical">严重</option>
                  <option value="high">高危</option>
                  <option value="medium">中危</option>
                  <option value="low">低危</option>
                </select>
              </label>
              <label>
                <span>路径前缀（可选，多条逗号分隔）</span>
                <input v-model="ruleForm.pathPrefixesText" class="field" placeholder="C:\Users\Public\  或  仅根：C:\Users\Public\\" />
              </label>
              <p class="hint sm" style="margin:-4px 0 8px">
                <code class="mono">C:\Users\Public\</code> = 含子目录；末尾多一个 <code class="mono">\</code>
                （<code class="mono">C:\Users\Public\\</code>）= 只要根目录文件。
              </p>
              <label>
                <span>文件扩展名</span>
                <input v-model="ruleForm.fileExtsText" class="field" placeholder="exe,dll,ps1,bat" @change="syncFileExtsFromText" />
              </label>
              <label>
                <span>签名条件</span>
                <select v-model="ruleForm.signedFilter" class="field">
                  <option value="">不限</option>
                  <option value="unsigned">仅未签名</option>
                  <option value="signed">仅有效签名</option>
                </select>
              </label>
              <label>
                <span>匹配特征（路径/文件名，一行一条；可填 *）</span>
                <textarea v-model="ruleForm.patternsText" class="field area" rows="5" placeholder="*&#10;\\Temp\\&#10;\\Downloads\\" />
              </label>
              <label>
                <span>匹配方式</span>
                <select v-model="ruleForm.match" class="field">
                  <option value="substring">子串</option>
                  <option value="regex">正则</option>
                  <option value="exact">精确</option>
                </select>
              </label>
              <label>
                <span>说明</span>
                <input v-model="ruleForm.note" class="field" placeholder="可选" />
              </label>
              <label class="chk-inline">
                <input type="checkbox" v-model="ruleForm.enabled" /> 启用
              </label>
              <p v-if="ruleFormError" class="err-text">{{ ruleFormError }}</p>
              <div class="row rule-editor-actions">
                <button type="button" class="btn primary" :disabled="ruleSaving" @click="saveRuleForm">
                  {{ ruleSaving ? '保存中…' : '保存' }}
                </button>
                <button type="button" class="btn" @click="cancelRuleForm">取消</button>
              </div>
            </div>
          </aside>
        </div>

        <div v-show="rulesSection === 'whitelist'" class="rules-layout wl-layout">
          <div class="panel fill pad">
            <h3 style="margin:0 0 4px">告警加白（抑制规则）</h3>
            <p class="muted" style="margin:0 0 12px;font-size:13px">
              与检出规则不同：加白后<strong>不再产生同类告警</strong>（所有检测来源、含 Elastic/传感器/ES EQL 均生效）。
              终端通过 sync 的 <code class="mono">whitelist</code> 块同步。也可在威胁事件里点「加白」快速创建。
            </p>
            <div v-if="isAdmin" class="hunt-bar" style="margin-bottom:12px">
              <select v-model="wlKind" class="search sev-filter">
                <option v-for="(lb, k) in ALLOW_KIND_LABELS" :key="k" :value="k">{{ lb }}</option>
              </select>
              <input v-model="wlValue" class="search grow" placeholder="匹配值，如 C:\Tools\*.exe" />
              <input v-model="wlRule" class="search" style="max-width:200px" placeholder="限定告警标题（可选 *）" />
              <input v-model="wlNote" class="search" style="max-width:160px" placeholder="备注" />
              <button type="button" class="btn primary" @click="addWl">添加</button>
            </div>
            <div class="chip-row" style="padding:0 0 10px">
              <input v-model="wlSearch" class="search grow" placeholder="搜索值 / 备注 / 标题限定…" style="max-width:320px" />
              <button type="button" class="chip-btn" :class="{ on: wlListFilter === 'all' }" @click="wlListFilter = 'all'">全部</button>
              <button type="button" class="chip-btn" :class="{ on: wlListFilter === 'enabled' }" @click="wlListFilter = 'enabled'">启用中</button>
              <button type="button" class="chip-btn" :class="{ on: wlListFilter === 'disabled' }" @click="wlListFilter = 'disabled'">已停用</button>
            </div>
            <div class="table-scroll">
              <table v-if="filteredWhitelist.length">
                <thead>
                  <tr>
                    <th>类型</th><th>值</th><th>限定告警</th><th>范围</th><th>命中</th><th>最近命中</th><th>备注</th><th>状态</th><th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="w in filteredWhitelist"
                    :key="w.id"
                    class="wl-row"
                    :class="{ 'wl-off': !w.enabled, on: wlSelectedId === w.id }"
                    @click="openWlDetail(w)"
                  >
                    <td>{{ ALLOW_KIND_LABELS[w.kind] || w.kind }}</td>
                    <td class="mono wl-val" :title="w.value">{{ w.value }}</td>
                    <td class="wl-val" :title="w.rule">{{ w.rule || '全部' }}</td>
                    <td>{{ w.agent_id ? agentLabel(w.agent_id) : '全部终端' }}</td>
                    <td>{{ w.hits || 0 }}</td>
                    <td>{{ w.last_hit_at ? fmtTime(w.last_hit_at) : '—' }}</td>
                    <td>{{ w.note || '—' }}</td>
                    <td @click.stop>
                      <button v-if="isAdmin" type="button" class="btn-text" @click="toggleWl(w)">{{ w.enabled ? '启用中' : '已停用' }}</button>
                      <span v-else>{{ w.enabled ? '启用' : '停用' }}</span>
                    </td>
                    <td @click.stop class="wl-acts">
                      <button type="button" class="btn-text" @click="openWlDetail(w)">详情</button>
                      <button v-if="isAdmin" type="button" class="btn-text" @click="openWlDetail(w); startWlEdit(w)">编辑</button>
                      <button v-if="isAdmin" type="button" class="btn-text" style="color:var(--danger)" @click="delWl(w.id)">删除</button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-else class="empty sm">暂无加白条目（或当前筛选无结果）</p>
            </div>
          </div>
          <aside class="panel pad wl-side">
            <template v-if="selectedWhitelist">
              <div class="wl-detail-hd">
                <h3 style="margin:0">{{ wlEditing ? '编辑加白' : '加白详情' }}</h3>
                <button type="button" class="btn-text" @click="closeWlDetail">关闭</button>
              </div>
              <template v-if="wlEditing && wlEditForm">
                <div class="wl-edit-form">
                  <label>
                    <span>类型</span>
                    <select v-model="wlEditForm.kind" class="field">
                      <option v-for="(lb, k) in ALLOW_KIND_LABELS" :key="k" :value="k">{{ lb }}</option>
                    </select>
                  </label>
                  <label>
                    <span>匹配值</span>
                    <input v-model="wlEditForm.value" class="field mono" placeholder="支持 * 通配" />
                  </label>
                  <p class="hint sm">{{ wlKindHint(wlEditForm.kind) }}</p>
                  <label>
                    <span>限定告警标题</span>
                    <input v-model="wlEditForm.rule" class="field" placeholder="可选，支持 *；空=全部" />
                  </label>
                  <label>
                    <span>生效范围</span>
                    <select v-model="wlEditForm.agent_id" class="field">
                      <option value="">全部终端</option>
                      <option
                        v-if="wlEditForm.agent_id && !agents.some((a) => a.agent_id === wlEditForm.agent_id)"
                        :value="wlEditForm.agent_id"
                      >{{ agentLabel(wlEditForm.agent_id) }}</option>
                      <option v-for="a in agents" :key="a.agent_id" :value="a.agent_id">
                        {{ a.hostname || short(a.agent_id) }}
                      </option>
                    </select>
                  </label>
                  <label>
                    <span>备注</span>
                    <input v-model="wlEditForm.note" class="field" placeholder="可选说明" />
                  </label>
                  <label class="chk">
                    <input type="checkbox" v-model="wlEditForm.apply_existing" />
                    保存后回溯：把已存在、命中的未处置告警标为无需处置
                  </label>
                  <p v-if="wlEditErr" class="err-text">{{ wlEditErr }}</p>
                </div>
                <div class="wl-detail-acts" v-if="isAdmin">
                  <button type="button" class="btn primary sm" :disabled="wlEditBusy" @click="saveWlEdit">
                    {{ wlEditBusy ? '保存中…' : '保存' }}
                  </button>
                  <button type="button" class="btn sm" :disabled="wlEditBusy" @click="cancelWlEdit">取消</button>
                </div>
              </template>
              <template v-else>
                <div class="wl-match-box">
                  <div class="wl-match-top">
                    <span class="sev" :data-s="selectedWhitelist.enabled ? 'low' : 'medium'">{{ selectedWhitelist.enabled ? '启用中' : '已停用' }}</span>
                    <span class="wl-kind-pill">{{ ALLOW_KIND_LABELS[selectedWhitelist.kind] || selectedWhitelist.kind }}</span>
                  </div>
                  <label>匹配值</label>
                  <code class="wl-match-val">{{ selectedWhitelist.value || '—' }}</code>
                  <button type="button" class="btn-text sm" @click="copyText(selectedWhitelist.value)">复制匹配值</button>
                  <p v-if="wlValueLooksOdd(selectedWhitelist)" class="wl-warn">
                    当前「类型」为{{ ALLOW_KIND_LABELS[selectedWhitelist.kind] || selectedWhitelist.kind }}，
                    但匹配值看起来不像{{ wlKindHint(selectedWhitelist.kind) }}。可能加白时选错了类型，仅抑制标题含该字符串的告警时请改用「告警标题」。
                  </p>
                </div>
                <dl class="wl-detail-dl">
                  <div><dt>限定告警</dt><dd class="break">{{ selectedWhitelist.rule || '全部告警标题' }}</dd></div>
                  <div><dt>生效范围</dt><dd>{{ selectedWhitelist.agent_id ? (agentLabel(selectedWhitelist.agent_id) + ' · ' + selectedWhitelist.agent_id) : '全部终端' }}</dd></div>
                  <div><dt>命中次数</dt><dd>{{ selectedWhitelist.hits || 0 }}</dd></div>
                  <div><dt>最近命中</dt><dd>{{ selectedWhitelist.last_hit_at ? fmtTime(selectedWhitelist.last_hit_at) : '尚未命中' }}</dd></div>
                  <div><dt>备注</dt><dd class="break">{{ selectedWhitelist.note || '—' }}</dd></div>
                  <div><dt>创建人</dt><dd>{{ selectedWhitelist.created_by || '—' }}</dd></div>
                  <div><dt>创建时间</dt><dd>{{ selectedWhitelist.created_at ? fmtTime(selectedWhitelist.created_at) : '—' }}</dd></div>
                  <div v-if="selectedWhitelist.source_event_id">
                    <dt>来源事件</dt>
                    <dd>
                      <button type="button" class="btn-text" @click="openEventById(selectedWhitelist.source_event_id)">#{{ selectedWhitelist.source_event_id }} 查看事件</button>
                    </dd>
                  </div>
                  <div><dt>条目 ID</dt><dd class="mono sm break">{{ selectedWhitelist.id }}</dd></div>
                </dl>
                <div class="wl-explain">
                  <h4>匹配说明</h4>
                  <p>{{ wlKindHint(selectedWhitelist.kind) }}</p>
                  <h4>生效方式</h4>
                  <ul>
                    <li>写入平台库后，经 Agent <code class="mono">sync</code> 下发 <code class="mono">whitelist</code>。</li>
                    <li>命中后同类告警不再产生（含传感器 / Elastic / EVM 等来源）。</li>
                    <li>限定告警标题为 <code class="mono">{{ selectedWhitelist.rule || '（全部）' }}</code>。</li>
                  </ul>
                </div>
                <div class="wl-detail-acts" v-if="isAdmin">
                  <button type="button" class="btn sm primary" @click="startWlEdit(selectedWhitelist)">编辑</button>
                  <button type="button" class="btn sm" @click="toggleWl(selectedWhitelist)">{{ selectedWhitelist.enabled ? '停用' : '启用' }}</button>
                  <button type="button" class="btn sm" style="color:var(--danger)" @click="delWl(selectedWhitelist.id)">删除</button>
                </div>
              </template>
            </template>
            <template v-else>
              <h3 style="margin:0 0 10px">加白详情</h3>
              <p class="muted" style="margin:0 0 12px;font-size:13px">点击左侧列表中的一行查看完整字段与生效说明。</p>
              <h4 style="margin:0 0 8px">如何生效</h4>
              <ul class="wl-help">
                <li>保存后写入平台库，并通过 Agent <strong>sync</strong> 下发 <code class="mono">whitelist</code> 块。</li>
                <li>命中加白的进程名 / 路径 / 哈希 / 注册表等，<strong>不再重复告警</strong>。</li>
                <li>「限定告警标题」可填关键词或 <code class="mono">*</code>，避免误伤其它规则。</li>
              </ul>
              <p class="hint sm" style="margin-top:14px">当前 {{ whitelistEnabledCount }}/{{ whitelist.length }} 条启用。</p>
            </template>
          </aside>
        </div>

        <div v-show="rulesSection === 'logrules'" class="logrules-layout">
          <p v-if="logRulesErr" class="err-text">{{ logRulesErr }}</p>
          <div v-else-if="logRulesPack?.ok" class="logrules-body">
            <div class="logrules-head">
              <div class="panel pad lr-where">
                <b>告警出现在哪里？</b>
                <p>
                  日志规则不在本页列表出告警。Agent 上报带 <code>EventID</code> 的 Winlog 后，服务端匹配
                  <strong>medium+</strong> 会晋升为威胁事件，标题形如
                  <code>日志规则：…</code>，可在
                  <button type="button" class="btn-text" @click="openLogRuleAlerts">威胁事件</button>
                  与
                  <button type="button" class="btn-text" @click="goMenu('behaviors')">检出行为</button>
                  中查看。
                </p>
                <p class="muted sm">
                  当前常见卡点：时间线只有进程/ETW、没有 winevent EventID → 规则无法匹配（下方点「开始诊断」可确认）。
                </p>
              </div>
              <div class="lr-diag panel pad">
                <div class="lr-diag-hd">
                  <div>
                    <h4>命中诊断</h4>
                    <p class="muted sm">一眼看出：没采到 EventID / 级别不够 / 被加白</p>
                  </div>
                  <div class="hunt-bar" style="margin:0">
                    <select v-model="logRuleDiagAgent" class="search">
                      <option value="">全部终端样本</option>
                      <option v-for="a in agents" :key="a.agent_id" :value="a.agent_id">{{ a.hostname || short(a.agent_id) }}</option>
                    </select>
                    <button type="button" class="btn primary sm" :disabled="logRuleDiagBusy" @click="runLogRuleDiagnose">
                      {{ logRuleDiagBusy ? '诊断中…' : '开始诊断' }}
                    </button>
                  </div>
                </div>
                <div v-if="logRuleDiag?.ok" class="lr-diag-body">
                  <div class="lr-diag-kpis">
                    <div><em>样本</em><b>{{ logRuleDiag.sample_size || 0 }}</b></div>
                    <div><em>带 EventID</em><b>{{ logRuleDiag.with_event_id || 0 }}</b><small>{{ logRuleDiag.eid_ratio || 0 }}%</small></div>
                    <div><em>规则命中</em><b>{{ logRuleDiag.match_hits || 0 }}</b></div>
                    <div><em>可晋升</em><b>{{ logRuleDiag.promoteable || 0 }}</b></div>
                    <div><em>级别不够</em><b>{{ logRuleDiag.low_only || 0 }}</b></div>
                    <div><em>被加白</em><b>{{ logRuleDiag.suppressed || 0 }}</b></div>
                  </div>
                  <ul class="lr-diag-reasons">
                    <li v-for="(r, i) in (logRuleDiag.reasons || [])" :key="i" :data-l="r.level">{{ r.text }}</li>
                  </ul>
                  <div v-if="(logRuleDiag.sample_hits || []).length" class="lr-diag-samples">
                    <b>可晋升样例</b>
                    <span v-for="(h, i) in logRuleDiag.sample_hits" :key="'h'+i" class="chip soft">{{ h.level }} · {{ h.title }} · EID {{ h.event_id || '—' }}</span>
                  </div>
                  <div v-if="(logRuleDiag.sample_suppressed || []).length" class="lr-diag-samples">
                    <b>加白抑制样例</b>
                    <span v-for="(h, i) in logRuleDiag.sample_suppressed" :key="'s'+i" class="chip soft">{{ h.title }}</span>
                  </div>
                </div>
                <p v-else class="muted sm" style="margin:8px 0 0">点「开始诊断」分析近期时间线与规则匹配情况。</p>
              </div>
              <div class="mem-yara-top">
                <div class="mem-yara-stats">
                  <div class="mem-yara-stat">
                    <label>已加载</label>
                    <b>{{ logRulesPack.loaded?.count || 0 }}</b>
                  </div>
                  <div class="mem-yara-stat">
                    <label>无 EventID</label>
                    <b>{{ logRulesPack.loaded?.no_eid || 0 }}</b>
                  </div>
                  <div class="mem-yara-stat">
                    <label>解析错误</label>
                    <b>{{ logRulesPack.loaded?.errors || 0 }}</b>
                  </div>
                  <div class="mem-yara-stat">
                    <label>匹配门槛</label>
                    <b>{{ logRulesPack.loaded?.min_level || 'low' }}+</b>
                  </div>
                </div>
                <p class="hint sm" style="margin:8px 0 0">{{ logRulesPack.note }}</p>
              </div>
              <div class="mem-yara-toggles" style="margin-top:12px">
                <div
                  v-for="r in (logRulesPack.roots || [])"
                  :key="r.id"
                  class="mem-yara-tog"
                  :class="{ off: r.enabled === false }"
                >
                  <span>
                    {{ logRulesPack.group_labels?.[r.id] || r.label || r.id }}
                    <em class="muted sm"> · {{ r.file_count || 0 }} 文件{{ r.present ? '' : ' · 目录缺失' }}</em>
                  </span>
                  <label class="switch mem-yara-switch" @click.stop>
                    <input
                      type="checkbox"
                      :disabled="!isAdmin || logRulesControlsBusy || !r.present"
                      :checked="r.enabled !== false"
                      @change="setLogRulesGroup(r.id, $event.target.checked)"
                    />
                    <i aria-hidden="true" />
                  </label>
                </div>
              </div>
              <div class="logrules-meta" v-if="logRulesPack.loaded?.by_source">
                <h4>来源分布</h4>
                <div class="logrules-chips">
                  <span v-for="(n, k) in logRulesPack.loaded.by_source" :key="k" class="chip soft">{{ k }} {{ n }}</span>
                </div>
                <h4 style="margin-top:10px">级别分布</h4>
                <div class="logrules-chips">
                  <span v-for="(n, k) in logRulesPack.loaded.by_level" :key="k" class="chip soft">{{ k }} {{ n }}</span>
                </div>
              </div>
            </div>
            <div class="logrules-sample">
              <header class="ai-panel-hd">
                <h4>规则样例</h4>
                <span class="muted sm">前 {{ (logRulesPack.sample || []).length }} 条 · 可滚动</span>
              </header>
              <div class="logrules-table-wrap">
                <table class="ai-mini-tbl">
                  <thead><tr><th>标题</th><th>级别</th><th>来源</th><th>EventID</th></tr></thead>
                  <tbody>
                    <tr v-for="(r, i) in (logRulesPack.sample || [])" :key="i">
                      <td :title="r.title">{{ r.title || '—' }}</td>
                      <td>{{ r.level || '—' }}</td>
                      <td class="mono">{{ r.source_group || '—' }}</td>
                      <td class="mono">{{ (r.event_ids || []).join(', ') || '—' }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
          <div v-else class="empty">
            <p>{{ logRulesBusy ? '正在加载日志规则…' : '日志规则加载中…' }}</p>
            <button v-if="!logRulesBusy" type="button" class="btn sm primary" @click="loadLogRules(false)">立即加载</button>
          </div>
        </div>

        <div v-show="rulesSection === 'memory'" class="mem-yara-layout">
          <p v-if="memoryYaraErr" class="err-text">{{ memoryYaraErr }}</p>
          <p v-if="memoryYaraErr" class="hint sm">
            规则目录：<code class="mono">agent/memory-yara/</code> · 点「刷新规则包」重试。
          </p>

          <template v-else-if="memoryYaraPack?.ok">
            <div class="mem-yara-top">
              <div class="mem-yara-stats">
                <div class="mem-yara-stat">
                  <label>包版本</label>
                  <b class="mono" :title="memoryYaraPack.rev">{{ shortHash(memoryYaraPack.rev || memoryYaraPack.manifest?.version || '—') }}</b>
                </div>
                <button type="button" class="mem-yara-stat click" :class="{ on: memoryYaraView === 'strings' }" @click="memoryYaraView = 'strings'">
                  <label>字符串规则</label>
                  <b>{{ memoryYaraPack.rule_count ?? 0 }}/{{ memoryYaraPack.rule_count_total ?? (memoryYaraPack.items || []).length }}</b>
                </button>
                <button type="button" class="mem-yara-stat click accent" :class="{ on: memoryYaraView === 'yar' }" @click="memoryYaraView = 'yar'">
                  <label>YARA 文件</label>
                  <b>{{ memoryYaraPack.yar_active ?? 0 }}/{{ memoryYaraPack.yar_total || (memoryYaraPack.yar_files_all || []).length || 0 }}</b>
                </button>
                <button type="button" class="mem-yara-stat click" :class="{ on: memoryYaraView === 'meta' }" @click="memoryYaraView = 'meta'">
                  <label>Valhalla</label>
                  <b>{{ memoryYaraPack.valhalla?.present ? ('≈ ' + (memoryYaraPack.valhalla.rule_count || '?')) : '—' }}</b>
                </button>
              </div>
              <div class="mem-yara-toggles" v-if="memoryYaraPack.controls">
                <div
                  v-for="gk in MEMORY_YARA_GROUP_KEYS"
                  :key="'myg-'+gk"
                  class="mem-yara-tog"
                  :class="{ off: memoryYaraPack.controls.groups?.[gk] === false }"
                >
                  <span>{{ memoryYaraPack.group_labels?.[gk] || gk }}</span>
                  <label class="switch mem-yara-switch" @click.stop>
                    <input
                      type="checkbox"
                      :disabled="!isAdmin || memoryYaraControlsBusy"
                      :checked="memoryYaraPack.controls.groups?.[gk] !== false"
                      @change="setMemoryYaraGroup(gk, $event.target.checked)"
                    />
                    <i aria-hidden="true" />
                  </label>
                </div>
              </div>
            </div>

            <nav class="mem-yara-subnav">
              <button type="button" :class="{ on: memoryYaraView === 'strings' }" @click="memoryYaraView = 'strings'">
                字符串规则 <em>{{ (memoryYaraPack.items || []).length }}</em>
              </button>
              <button type="button" :class="{ on: memoryYaraView === 'yar' }" @click="memoryYaraView = 'yar'">
                YARA 文件 <em>{{ memoryYaraPack.yar_total || (memoryYaraPack.yar_files_all || []).length || 0 }}</em>
              </button>
              <button type="button" :class="{ on: memoryYaraView === 'meta' }" @click="memoryYaraView = 'meta'">包信息</button>
            </nav>

            <div v-show="memoryYaraView === 'strings'" class="mem-yara-body" :class="{ dim: memoryYaraPack.controls?.groups?.string_rules === false }">
              <div class="mem-yara-toolbar">
                <div>
                  <h3>rules.json 轻量字符串</h3>
                  <p>不编译 YARA 也能扫；全量签名在「YARA 文件」。Sync 下发，改完下次同步生效。</p>
                </div>
                <div class="mem-yara-toolbar-actions" v-if="isAdmin">
                  <button type="button" class="btn sm" :disabled="memoryYaraControlsBusy || memoryYaraPack.controls?.groups?.string_rules === false" @click="setAllMemoryYaraStringRules(true)">全部启用</button>
                  <button type="button" class="btn sm" :disabled="memoryYaraControlsBusy || memoryYaraPack.controls?.groups?.string_rules === false" @click="setAllMemoryYaraStringRules(false)">全部关闭</button>
                </div>
              </div>
              <p v-if="memoryYaraPack.controls?.groups?.string_rules === false" class="mem-yara-banner">本组总开关已关，单条不可改，Agent 不下发字符串规则。</p>
              <div class="mem-yara-scroll">
                <table class="mem-yara-table">
                  <colgroup>
                    <col v-if="isAdmin" style="width:64px" />
                    <col style="width:22%" />
                    <col style="width:22%" />
                    <col style="width:72px" />
                    <col style="width:16%" />
                    <col />
                  </colgroup>
                  <thead>
                    <tr>
                      <th v-if="isAdmin">启用</th>
                      <th>ID</th>
                      <th>标题</th>
                      <th>级别</th>
                      <th>MITRE</th>
                      <th>匹配串</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="r in memoryYaraPack.items || []" :key="r.id" :class="{ 'row-off': r.enabled === false }">
                      <td v-if="isAdmin">
                        <label class="switch mem-yara-switch">
                          <input
                            type="checkbox"
                            :disabled="memoryYaraControlsBusy || memoryYaraPack.controls?.groups?.string_rules === false"
                            :checked="r.enabled !== false"
                            @change="toggleMemoryYaraStringRule(r, $event.target.checked)"
                          />
                          <i aria-hidden="true" />
                        </label>
                      </td>
                      <td class="mono">{{ r.id }}</td>
                      <td><b>{{ r.title }}</b></td>
                      <td><span class="sev" :data-s="r.severity">{{ sevLabel(r.severity) }}</span></td>
                      <td class="mono muted">{{ (r.mitre || []).join(', ') || '—' }}</td>
                      <td class="mono muted mem-yara-str" :title="(r.strings || []).join(' | ')">
                        {{ ((r.strings || []).slice(0, 3).join(' · ')) || '—' }}{{ (r.strings || []).length > 3 ? '…' : '' }}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div v-show="memoryYaraView === 'yar'" class="mem-yara-body">
              <div class="mem-yara-toolbar">
                <div>
                  <h3>YARA 规则文件</h3>
                  <p><code class="mono">agent/memory-yara/</code> · ep_*.yar（Hacktool/勒索/Trojan）+ 内置 .yar。分组开关在上方。</p>
                </div>
                <span class="meta">{{ memoryYaraPack.yar_active ?? 0 }} / {{ memoryYaraPack.yar_total || 0 }} 启用</span>
              </div>
              <div class="mem-yara-scroll">
                <table class="mem-yara-table">
                  <colgroup>
                    <col style="width:72px" />
                    <col />
                    <col style="width:240px" />
                  </colgroup>
                  <thead>
                    <tr><th>状态</th><th>文件</th><th>分组</th></tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="f in (memoryYaraPack.yar_files_all || []).length ? memoryYaraPack.yar_files_all : (memoryYaraPack.yar_files || []).map((n) => ({ name: n, enabled: true, group: 'protections_yara' }))"
                      :key="f.name || f"
                      :class="{ 'row-off': f.enabled === false }"
                    >
                      <td><span class="pill sm" :class="f.enabled === false ? '' : 'on'">{{ f.enabled === false ? '关闭' : '启用' }}</span></td>
                      <td class="mono">{{ f.name || f }}</td>
                      <td class="muted">{{ memoryYaraPack.group_labels?.[f.group] || f.group || '—' }}</td>
                    </tr>
                    <tr v-if="!(memoryYaraPack.yar_files_all || []).length && !(memoryYaraPack.yar_files || []).length">
                      <td colspan="3" class="muted">未发现 .yar 文件</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div v-show="memoryYaraView === 'meta'" class="mem-yara-body meta">
              <div class="mem-yara-meta-grid">
                <section>
                  <h4>轻量包</h4>
                  <dl>
                    <div><dt>名称</dt><dd>{{ memoryYaraPack.manifest?.name || '—' }}</dd></div>
                    <div><dt>版本</dt><dd class="mono">{{ memoryYaraPack.manifest?.version || memoryYaraPack.rev || '—' }}</dd></div>
                    <div v-if="memoryYaraPack.manifest?.updated_at"><dt>更新</dt><dd>{{ memoryYaraPack.manifest.updated_at }}</dd></div>
                    <div v-if="memoryYaraPack.sha256"><dt>SHA256</dt><dd class="mono" :title="memoryYaraPack.sha256">{{ shortHash(memoryYaraPack.sha256) }}</dd></div>
                    <div class="full" v-if="memoryYaraPack.manifest?.description"><dt>说明</dt><dd>{{ memoryYaraPack.manifest.description }}</dd></div>
                  </dl>
                </section>
                <section v-if="memoryYaraPack.valhalla?.present">
                  <h4>Valhalla 主库 <span class="pill sm" :class="{ on: memoryYaraPack.valhalla_included_in_agent_bundle }">{{ memoryYaraPack.valhalla_included_in_agent_bundle ? '已编入包' : '未编入包' }}</span></h4>
                  <dl>
                    <div><dt>路径</dt><dd class="mono">{{ memoryYaraPack.valhalla.path }}</dd></div>
                    <div><dt>大小</dt><dd>{{ fmtSize(memoryYaraPack.valhalla.size) }}</dd></div>
                    <div v-if="memoryYaraPack.valhalla.retrieved"><dt>检索</dt><dd>{{ memoryYaraPack.valhalla.retrieved }}</dd></div>
                    <div class="full"><dt>说明</dt><dd>{{ memoryYaraPack.valhalla.note }}</dd></div>
                  </dl>
                </section>
                <section>
                  <h4>仓库路径</h4>
                  <dl>
                    <div><dt>主库</dt><dd class="mono">{{ memoryYaraPack.repo_paths?.yara_corpus || 'yara/' }}</dd></div>
                    <div><dt>轻量包</dt><dd class="mono">{{ memoryYaraPack.repo_paths?.agent_memory_pack || 'agent/memory-yara/' }}</dd></div>
                    <div class="full" v-if="memoryYaraPack.sigma_note"><dt>注意</dt><dd>{{ memoryYaraPack.sigma_note }}</dd></div>
                  </dl>
                </section>
              </div>
            </div>
          </template>
          <p v-else-if="!memoryYaraBusy" class="empty">暂无规则包数据，点右上角「刷新规则包」</p>
        </div>
      </section>

<section v-if="page === 'resp-results'" class="page">
        <header class="page-hd">
          <div>
            <h1>处置结果</h1>
            <p class="desc">
              全平台下发的响应指令。状态「等待下发」表示 Agent 尚未领取（常见原因：终端离线或进程已退出）。
            </p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn" :disabled="fleetCmdBusy" @click="loadFleetCommands">
              {{ fleetCmdBusy ? '刷新中…' : '刷新' }}
            </button>
          </div>
        </header>

        <div class="panel pad" style="margin-bottom:12px">
          <div class="toolbar" style="gap:10px;flex-wrap:wrap;align-items:center">
            <label class="sm">
              状态
              <select v-model="fleetCmdStatus" class="field sm">
                <option value="stuck">未完成（等待/执行中）</option>
                <option value="">全部</option>
                <option value="pending">等待下发</option>
                <option value="sent">已送达执行中</option>
                <option value="done">成功</option>
                <option value="failed">失败</option>
              </select>
            </label>
            <label class="sm">
              终端
              <select v-model="fleetCmdAgent" class="field sm" @change="loadFleetCommands">
                <option value="">全部终端</option>
                <option v-for="a in agents" :key="a.agent_id" :value="a.agent_id">
                  {{ a.hostname || a.agent_id }}{{ a.online ? '' : '（离线）' }}
                </option>
              </select>
            </label>
            <span class="muted sm">
              未完成 {{ fleetCmdStuckCount }} · 列表 {{ fleetCommandsView.length }}
            </span>
          </div>
        </div>

        <div class="split resp-results-split" :class="{ 'has-detail': !!fleetCmdSelected }">
          <div class="panel record-panel">
            <div class="panel-hd"><h3>处置记录</h3><span class="record-count">{{ fleetCommandsView.length }} 条记录</span></div>
            <div v-if="fleetCommandsView.length" class="table-scroll record-table"><table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>终端</th>
                  <th>动作</th>
                  <th>状态</th>
                  <th>摘要</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="c in fleetCommandsView"
                  :key="c.id"
                  :class="{
                    active: fleetCmdSelected?.id === c.id,
                    'row-warn': c.status === 'pending' || c.status === 'sent',
                    'row-fail': c.status === 'failed',
                  }"
                  style="cursor:pointer"
                  @click="selectFleetCmd(c)"
                >
                  <td>{{ fmtTime(c.updated_at || c.created_at) }}</td>
                  <td>
                    <div>{{ agentLabel(c.agent_id) }}</div>
                    <div class="muted mono sm">{{ short(c.agent_id) }}</div>
                  </td>
                  <td>{{ actionLabel(c.action) }}</td>
                  <td>
                    <span class="cmd-st" :data-s="c.status">{{ cmdStatusLabel(c.status) }}</span>
                    <div v-if="c.status === 'pending'" class="muted sm">终端未领取</div>
                  </td>
                  <td class="muted" :title="c.result_json || c.params_json">
                    <template v-if="c.status === 'done' || c.status === 'failed'">
                      {{ friendlyCmdResult(c.action, c.result_json) }}
                    </template>
                    <template v-else>{{ shortJson(c.params_json) }}</template>
                  </td>
                  <td>
                    <button type="button" class="btn-text" @click.stop="selectFleetCmd(c)">详情</button>
                  </td>
                </tr>
              </tbody>
            </table></div>
            <div v-else class="record-empty"><span class="record-empty-mark" aria-hidden="true">—</span><strong>
              {{ fleetCmdBusy ? '加载中…' : (fleetCmdStatus === 'stuck' ? '没有卡住的指令（pending/sent）' : '暂无处置指令') }}
            </strong></div>
          </div>

          <aside v-if="fleetCmdSelected" class="panel snap-detail fleet-cmd-detail">
            <div class="sd-hd">
              <div>
                <b>{{ actionLabel(fleetCmdSelected.action) }} · {{ cmdStatusLabel(fleetCmdSelected.status) }}</b>
                <small>{{ agentLabel(fleetCmdSelected.agent_id) }} · {{ short(fleetCmdSelected.id) }}</small>
              </div>
              <button type="button" class="icon-x" @click="fleetCmdSelected = null">×</button>
            </div>

            <dl class="sd-dl compact-gap">
              <div>
                <dt>终端</dt>
                <dd>
                  <button type="button" class="btn-text" @click="openFleetCmdHost(fleetCmdSelected)">
                    {{ agentLabel(fleetCmdSelected.agent_id) }}
                  </button>
                  <span class="muted mono"> · {{ fleetCmdSelected.agent_id }}</span>
                </dd>
              </div>
              <div>
                <dt>状态</dt>
                <dd>
                  <span class="cmd-st" :data-s="fleetCmdSelected.status">{{ cmdStatusLabel(fleetCmdSelected.status) }}</span>
                  <span v-if="fleetCmdSelected.attempts != null" class="muted"> · 尝试 {{ fleetCmdSelected.attempts }}</span>
                </dd>
              </div>
              <div>
                <dt>创建</dt>
                <dd>创建 {{ fmtTime(fleetCmdSelected.created_at) }} · 更新 {{ fmtTime(fleetCmdSelected.updated_at) }}</dd>
              </div>
              <div v-if="fleetCmdSelected.created_by">
                <dt>操作者</dt>
                <dd>{{ fleetCmdSelected.created_by }}</dd>
              </div>
              <div v-if="fleetCmdDetailNote.text">
                <dt>{{ fleetCmdDetailNote.label }}</dt>
                <dd :class="{ 'fleet-cmd-err': fleetCmdDetailNote.err }">{{ fleetCmdDetailNote.text }}</dd>
              </div>
            </dl>

            <div class="sd-actions" v-if="fleetCmdParamRows.length">
              <h4>处置目标 / 参数</h4>
              <dl class="sd-dl compact-gap">
                <div v-for="row in fleetCmdParamRows" :key="row.k">
                  <dt>{{ row.k }}</dt>
                  <dd class="mono">{{ row.v }}</dd>
                </div>
              </dl>
            </div>

            <div class="sd-actions" v-if="fleetCmdResultRows.length">
              <h4>执行结果</h4>
              <dl class="sd-dl compact-gap">
                <div v-for="row in fleetCmdResultRows" :key="row.k">
                  <dt>{{ row.k }}</dt>
                  <dd>{{ row.v }}</dd>
                </div>
              </dl>
            </div>

            <div class="sd-actions" v-if="fleetCmdFindings.length">
              <h4>命中项 · {{ fleetCmdFindings.length }}</h4>
              <div class="fleet-find-list">
                <div
                  v-for="(f, i) in fleetCmdFindings"
                  :key="i"
                  class="fleet-find-row"
                  :data-sev="f.severity || 'medium'"
                >
                  <div class="fleet-find-top">
                    <b>{{ f.summary || f.type || f.rule_id || '命中' }}</b>
                    <em v-if="f.severity">{{ f.severity }}</em>
                  </div>
                  <div class="muted sm mono">
                    <template v-if="f.name || f.pid">{{ f.name || '—' }} · PID {{ f.pid ?? '—' }}</template>
                    <template v-if="f.address"> · {{ f.address }}</template>
                    <template v-if="f.engine"> · {{ f.engine }}</template>
                    <template v-if="f.type"> · {{ f.type }}</template>
                  </div>
                  <div v-if="f.evidence" class="sm">{{ f.evidence }}</div>
                </div>
              </div>
            </div>

            <div class="sd-actions" v-if="fleetCmdFailItems.length">
              <h4>失败项 · {{ fleetCmdFailItems.length }}</h4>
              <ul class="fleet-fail-list">
                <li v-for="(it, i) in fleetCmdFailItems" :key="i">{{ it }}</li>
              </ul>
            </div>

            <div class="sd-actions" v-if="fleetCmdEntries.length">
              <h4>返回条目 · {{ fleetCmdEntries.length }}</h4>
              <div class="fleet-find-list">
                <div v-for="(e, i) in fleetCmdEntries.slice(0, 40)" :key="i" class="fleet-find-row">
                  <div class="fleet-find-top">
                    <b class="mono">{{ e.name || e.path || e.drive || JSON.stringify(e).slice(0, 80) }}</b>
                    <em v-if="e.dir">目录</em>
                  </div>
                  <div v-if="e.path || e.size != null" class="muted sm mono">
                    <template v-if="e.path">{{ e.path }}</template>
                    <template v-if="e.size != null"> · {{ e.size }} B</template>
                  </div>
                </div>
              </div>
              <p v-if="fleetCmdEntries.length > 40" class="muted sm">仅显示前 40 条</p>
            </div>

            <details class="sd-actions fleet-cmd-raw">
              <summary>原始参数 / 结果 JSON</summary>
              <pre class="raw-detail">参数:
{{ prettyJson(fleetCmdSelected.params_json) }}

结果:
{{ prettyJson(fleetCmdSelected.result_json) }}</pre>
            </details>
          </aside>
        </div>
      </section>

<section v-if="page === 'ai-analyze'" class="page ai-page">
        <header class="page-hd">
          <div>
            <h1>AI 分析</h1>
            <p class="desc">Agentic SOC 风格 · Team Leader 调度多 Agent · 感知—调查—研判—处置建议（人工审核）</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn sm" :disabled="aiHostsLoading" @click="loadAiAnalyzePage({ force: true })">
              {{ aiHostsLoading ? '刷新中…' : '刷新终端' }}
            </button>
            <button
              v-if="isAdmin"
              type="button"
              class="btn sm"
              @click="setSection('settings')"
            >模型配置</button>
          </div>
        </header>

        <div class="ai-status-bar panel pad">
          <div class="ai-status-main">
            <span class="pill" :class="aiStatusInfo.configured ? 'ok' : 'warn'">
              {{ aiStatusInfo.configured ? '模型已就绪' : '模型未配置' }}
            </span>
            <span class="mono muted">{{ aiStatusInfo.base_url || '—' }}</span>
            <span class="mono">{{ aiStatusInfo.model || '—' }}</span>
            <span class="muted">来源 {{ aiStatusInfo.source || '—' }} · 超时 {{ aiStatusInfo.timeout || 120 }}s</span>
          </div>
          <div class="ai-status-skills muted">
            Skill 根目录：<code class="mono">{{ aiStatusInfo.skills_root || 'skills' }}</code>
            · 库内索引 {{ aiStatusInfo.skills_total || aiSkillsMeta.total_indexed || '—' }}
            · EDR 相关 {{ aiStatusInfo.skills_edr || aiSkillsMeta.edr_relevant || aiSkills.length }}
            · 列表展示 {{ aiSkills.length }}
          </div>
        </div>

        <div class="ai-layout">
          <aside class="ai-host-pane panel">
            <div class="panel-hd">
              <h3>在线终端 <em>{{ aiOnlineHosts.length }}</em></h3>
              <label class="ai-only-online">
                <input type="checkbox" v-model="aiOnlyOnline" /> 仅在线
                <span v-if="aiHostsLoading" class="muted sm">同步中</span>
              </label>
            </div>
            <div class="ai-host-list">
              <button
                v-for="h in aiVisibleHosts"
                :key="h.agent_id"
                type="button"
                class="ai-host-row"
                :class="{ on: aiSelectedId === h.agent_id, offline: !h.online }"
                :disabled="aiBusy && aiSelectedId === h.agent_id"
                @click="runAiAnalyze(h)"
              >
                <span class="ai-host-dot" :class="{ on: h.online }" />
                <span class="ai-host-meta">
                  <b>{{ h.hostname || h.agent_id }}</b>
                  <small class="mono">{{ h.ip || h.last_ip || '—' }} · {{ h.online ? '在线' : '离线' }}</small>
                </span>
                <span class="ai-host-badges">
                  <em v-if="h.open_threat_count" class="pill danger">威胁 {{ h.open_threat_count }}</em>
                  <em v-else-if="h.threat_count" class="pill soft">历史 {{ h.threat_count }}</em>
                </span>
              </button>
              <p v-if="!aiVisibleHosts.length && aiHostsLoading" class="empty sm">正在拉取在线终端…</p>
              <p v-else-if="!aiVisibleHosts.length" class="empty sm">暂无终端，请先部署 Agent 或点「刷新终端」</p>
            </div>
          </aside>

          <main class="ai-result-pane panel">
            <div class="panel-hd">
              <h3>
                研判结果
                <template v-if="aiSelectedHost"> · {{ aiSelectedHost.hostname || aiSelectedHost.agent_id }}</template>
              </h3>
              <span v-if="aiRefining" class="pill warn">模型精炼中…</span>
              <span v-else-if="aiResult" class="muted">{{ aiResult.mode }} · {{ aiResult.elapsed_ms || 0 }} ms</span>
            </div>

            <div v-if="aiBusy && !aiResult" class="ai-busy">
              <div class="ai-spinner" />
              <p>正在快速汇总快照 / 威胁事件 / 日志…</p>
              <p class="muted sm">约 1 秒内先出启发式结论，随后自动精炼。</p>
            </div>

            <div v-else-if="aiErrorText" class="ai-empty">
              <p class="hint warn">分析失败：{{ aiErrorText }}</p>
              <p class="muted">可再次点击左侧终端重试；若模型超时，仍会尽量返回启发式结论。</p>
            </div>

            <div v-else-if="aiResult" class="ai-result-body">
              <div class="ai-hero">
                <div class="ai-hero-verdict">
                  <span class="ai-verdict" :data-v="aiResult.result?.verdict || ''">{{ aiResult.result?.verdict || '待研判' }}</span>
                  <div class="ai-hero-meta">
                    <b :class="'sev-' + String(aiResult.result?.risk_level || '').toLowerCase()">
                      {{ aiResult.result?.risk_level || '—' }} · {{ aiResult.result?.risk_score ?? '—' }}
                    </b>
                    <small class="mono muted">{{ aiResult.mode }} · {{ aiResult.model || 'Agent Team' }} · {{ aiResult.elapsed_ms || 0 }} ms</small>
                  </div>
                </div>
                <div class="ai-hero-stats">
                  <button type="button" class="ai-hero-stat" @click="aiTab = 'threats'">
                    <label>威胁</label>
                    <b>{{ (aiResult.result?.threat_events || []).length || aiResult.pack_stats?.threat_events || 0 }}</b>
                  </button>
                  <button type="button" class="ai-hero-stat" @click="aiTab = 'logs'">
                    <label>日志 / 规则</label>
                    <b>{{ aiResult.pack_stats?.security_logs || 0 }} / {{ aiResult.pack_stats?.log_rule_hits || 0 }}</b>
                  </button>
                  <button type="button" class="ai-hero-stat" @click="aiTab = 'entity'">
                    <label>实体</label>
                    <b>{{ (aiResult.result?.entities || []).length }}</b>
                  </button>
                  <button type="button" class="ai-hero-stat" @click="aiTab = 'resp'">
                    <label>处置建议</label>
                    <b>{{ (aiResult.result?.dispositions || []).length }}</b>
                  </button>
                </div>
              </div>

              <p class="ai-scope-banner" v-if="aiResult.result?.data_scope">
                <b>分析范围</b>
                <span>{{ aiResult.result.data_scope.note }}</span>
                <em class="muted">
                  快照 {{ (aiResult.result.data_scope.snapshots || []).length }} 类 ·
                  威胁 {{ aiResult.result.data_scope.threat_events || 0 }} ·
                  时间线 {{ aiResult.result.data_scope.timeline || 0 }} ·
                  调查日志 {{ aiResult.result.data_scope.investigate_logs || 0 }} ·
                  规则命中 {{ aiResult.result.data_scope.log_rule_hits || 0 }}
                </em>
              </p>

              <nav class="ai-tabs">
                <button type="button" :class="{ on: aiTab === 'overview' }" @click="aiTab = 'overview'">概览</button>
                <button type="button" :class="{ on: aiTab === 'chain' }" @click="aiTab = 'chain'">
                  攻击链路
                  <em v-if="aiResult.result?.attack_graph?.stage_count">{{ aiResult.result.attack_graph.stage_count }}</em>
                </button>
                <button type="button" :class="{ on: aiTab === 'threats' }" @click="aiTab = 'threats'">
                  AI 研判事件
                  <em v-if="(aiResult.result?.threat_events || []).length">{{ (aiResult.result.threat_events || []).length }}</em>
                </button>
                <button type="button" :class="{ on: aiTab === 'think' }" @click="aiTab = 'think'">
                  AI 思维链
                  <em v-if="(aiResult.result?.thinking_chain || []).length">{{ (aiResult.result.thinking_chain || []).length }}</em>
                </button>
                <button type="button" :class="{ on: aiTab === 'logs' }" @click="aiTab = 'logs'">
                  日志取证
                  <em v-if="(aiResult.result?.forensics_logs || aiResult.result?.security_logs || []).length">
                    {{ (aiResult.result?.forensics_logs || aiResult.result?.security_logs || []).length }}
                  </em>
                </button>
                <button type="button" :class="{ on: aiTab === 'entity' }" @click="aiTab = 'entity'">实体</button>
                <button type="button" :class="{ on: aiTab === 'report' }" @click="aiTab = 'report'">报告</button>
                <button type="button" :class="{ on: aiTab === 'resp' }" @click="aiTab = 'resp'">处置</button>
              </nav>

              <div v-show="aiTab === 'overview'" class="ai-tab-pane ai-overview">
                <div v-if="(aiResult.result?.team?.agents || []).length" class="ai-team-strip">
                  <div
                    v-for="a in aiResult.result.team.agents"
                    :key="a.id"
                    class="ai-team-pill"
                    :title="a.summary"
                  >
                    <i />
                    <span>
                      <b>{{ a.name }}</b>
                      <small>{{ a.role }}</small>
                    </span>
                    <em>{{ a.status === 'done' ? '完成' : a.status }}</em>
                  </div>
                </div>

                <div class="ai-board">
                  <section class="ai-board-main">
                    <div class="ai-panel">
                      <header class="ai-panel-hd">
                        <h4>AI 研判事件</h4>
                        <button type="button" class="btn-text sm" @click="aiTab = 'threats'">全部 →</button>
                      </header>
                      <div v-if="(aiResult.result?.threat_events || []).length" class="ai-threat-preview">
                        <button
                          v-for="(ev, i) in (aiResult.result.threat_events || []).slice(0, 6)"
                          :key="ev.id || i"
                          type="button"
                          class="ai-threat-row"
                          @click="aiThreatIdx = i; aiTab = 'threats'"
                        >
                          <span class="pill" :data-ai="ev.ai?.conclusion || ''">{{ ev.ai?.conclusion || '待研判' }}</span>
                          <span class="ai-threat-row-body">
                            <b>{{ ev.title || '未命名告警' }}</b>
                            <small>{{ (ev.ai?.reasoning && ev.ai.reasoning[0]) || ev.ai?.note || '—' }}</small>
                          </span>
                          <em class="muted sm">{{ ev.ai?.confidence != null ? ev.ai.confidence + '%' : '' }}</em>
                        </button>
                      </div>
                      <p v-else class="ai-panel-empty">暂无 AI 研判事件</p>
                    </div>

                    <div class="ai-panel">
                      <header class="ai-panel-hd">
                        <h4>攻击时间线</h4>
                        <span class="muted sm">威胁 + 安全日志</span>
                      </header>
                      <ol v-if="(aiResult.result?.attack_timeline || []).length" class="ai-rail">
                        <li v-for="(t, i) in aiResult.result.attack_timeline.slice(0, 10)" :key="i">
                          <span class="ai-rail-dot" :data-k="t.kind || ''" />
                          <div>
                            <div class="ai-rail-top">
                              <time>{{ t.ts || '—' }}</time>
                              <span class="pill soft">{{ t.kind }}</span>
                            </div>
                            <b>{{ t.title }}</b>
                            <small v-if="t.detail">{{ t.detail }}</small>
                          </div>
                        </li>
                      </ol>
                      <p v-else class="ai-panel-empty">暂无攻击时间线节点</p>
                    </div>
                  </section>

                  <aside class="ai-board-side">
                    <div class="ai-panel">
                      <header class="ai-panel-hd"><h4>调查流水线</h4></header>
                      <ol v-if="(aiResult.result?.pipeline || []).length" class="ai-steps">
                        <li v-for="(p, i) in aiResult.result.pipeline" :key="i">
                          <span class="ai-step-no">{{ i + 1 }}</span>
                          <div>
                            <b>{{ p.stage }}</b>
                            <span>{{ p.goal }}</span>
                            <small v-if="typeof p.output === 'string'">{{ p.output }}</small>
                            <small v-else-if="p.output?.what">{{ p.output.what }}</small>
                            <em v-if="(p.deliverables || []).length">{{ (p.deliverables || []).join(' · ') }}</em>
                          </div>
                        </li>
                      </ol>
                      <p v-else class="ai-panel-empty">暂无流水线</p>
                    </div>

                    <div v-if="aiResult.result?.alert_meta" class="ai-panel">
                      <header class="ai-panel-hd"><h4>告警基本信息</h4></header>
                      <dl class="ai-meta-compact">
                        <div><dt>来源</dt><dd>{{ aiResult.result.alert_meta.source || '—' }}</dd></div>
                        <div><dt>分析规则</dt><dd>{{ aiResult.result.alert_meta.analysis_rule || '—' }}</dd></div>
                        <div><dt>关联告警</dt><dd>{{ aiResult.result.alert_meta.related_alerts ?? '—' }}</dd></div>
                        <div><dt>资产</dt><dd>{{ aiResult.result.alert_meta.hostname || '—' }}</dd></div>
                        <div class="full"><dt>ATT&CK</dt><dd>{{ (aiResult.result.alert_meta.attck_stages || []).join(' · ') || '—' }}</dd></div>
                        <div class="full" v-if="aiResult.result?.root_cause"><dt>根因</dt><dd>{{ aiResult.result.root_cause }}</dd></div>
                      </dl>
                    </div>

                    <div class="ai-panel ai-quick">
                      <header class="ai-panel-hd"><h4>快捷入口</h4></header>
                      <div class="ai-quick-row">
                        <button type="button" @click="aiTab = 'think'">思维链 {{ (aiResult.result?.thinking_chain || []).length }}</button>
                        <button type="button" @click="aiTab = 'logs'">日志 {{ (aiResult.result?.security_logs || []).length }}</button>
                        <button type="button" @click="aiTab = 'report'">报告</button>
                        <button type="button" @click="aiTab = 'resp'">处置 {{ (aiResult.result?.dispositions || []).length }}</button>
                      </div>
                    </div>
                  </aside>
                </div>
              </div>

              <div v-show="aiTab === 'chain'" class="ai-tab-pane ai-chain-pane">
                <div class="ai-section-hd">
                  <div>
                    <label>攻击链路图</label>
                    <span class="muted sm">{{ aiResult.result?.attack_graph?.summary || '将主机 → 各 ATT&CK 阶段 → 证据串联' }}</span>
                  </div>
                  <button type="button" class="btn-text sm" @click="aiTab = 'logs'">日志取证 →</button>
                </div>
                <div v-if="(aiResult.result?.attack_graph?.nodes || []).length" class="ai-chain-board">
                  <div class="ai-chain-flow">
                    <template v-for="(n, i) in aiResult.result.attack_graph.nodes" :key="n.id">
                      <div
                        class="ai-chain-node"
                        :class="[n.type, { on: aiChainNodeId === n.id }]"
                        @click="aiChainNodeId = n.id"
                      >
                        <span class="ai-chain-badge">{{ n.type === 'host' ? '主机' : (i) }}</span>
                        <b>{{ n.label }}</b>
                        <small v-if="n.sub">{{ n.sub }}</small>
                        <em v-if="n.count">{{ n.count }} 证据</em>
                      </div>
                      <div
                        v-if="i < aiResult.result.attack_graph.nodes.length - 1"
                        class="ai-chain-arrow"
                        aria-hidden="true"
                      >→</div>
                    </template>
                  </div>
                  <div class="ai-chain-detail" v-if="aiChainNode">
                    <header>
                      <h4>{{ aiChainNode.label }}</h4>
                      <span class="muted sm">{{ aiChainNode.sub || aiChainNode.type }}</span>
                    </header>
                    <div v-if="(aiChainNode.items || []).length" class="ai-chain-items">
                      <article v-for="(it, ii) in aiChainNode.items" :key="ii" class="ai-chain-item" :data-k="it.kind">
                        <div class="ai-chain-item-top">
                          <span class="pill soft">{{ it.kind }}</span>
                          <time>{{ it.ts || '—' }}</time>
                        </div>
                        <b>{{ it.title }}</b>
                        <p>{{ it.detail || '—' }}</p>
                      </article>
                    </div>
                    <p v-else class="muted">该节点无挂接明细证据</p>
                    <div class="ai-threat-actions">
                      <button type="button" class="btn sm" @click="aiTab = 'threats'">看 AI 研判事件</button>
                      <button type="button" class="btn sm" @click="aiTab = 'entity'">看实体</button>
                    </div>
                  </div>
                </div>
                <div v-else class="ai-panel-empty fill">暂无线路节点。请确认 Agent 已回传威胁/日志后再分析。</div>
              </div>

              <div v-show="aiTab === 'threats'" class="ai-tab-pane">
                <div class="ai-threats-head">
                  <label>AI 研判事件（本地 Agent / 模型结论，非原始告警照搬）</label>
                  <span class="muted sm">
                    {{ (aiResult.result?.threat_events || []).length }} 条 ·
                    主机结论 {{ aiResult.result?.verdict || '—' }} ·
                    点行看推理与处置建议
                  </span>
                </div>
                <div class="ai-threats-layout">
                  <div class="ai-threats-list">
                    <table class="ai-mini-tbl">
                      <thead>
                        <tr>
                          <th>AI 结论</th>
                          <th>置信</th>
                          <th>原告警</th>
                          <th>角色</th>
                          <th>阶段</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr
                          v-for="(ev, i) in (aiResult.result?.threat_events || [])"
                          :key="ev.id || i"
                          :class="{ on: aiThreatIdx === i }"
                          @click="aiThreatIdx = i"
                        >
                          <td>
                            <span class="pill" :data-ai="ev.ai?.conclusion || ''">{{ ev.ai?.conclusion || '待研判' }}</span>
                          </td>
                          <td class="mono">{{ ev.ai?.confidence != null ? ev.ai.confidence + '%' : '—' }}</td>
                          <td :title="ev.title">
                            <b class="ai-threat-title">{{ ev.title || '未命名告警' }}</b>
                            <small class="muted">EDR {{ ev.severity || '—' }} · {{ ev.process_name || ev.path || ev.etype || '' }}</small>
                          </td>
                          <td>
                            <span class="pill soft" :data-role="ev.ai?.role || ''">{{ ev.ai?.role || '—' }}</span>
                          </td>
                          <td>{{ ev.ai?.chain_stage || '—' }}</td>
                        </tr>
                        <tr v-if="!(aiResult.result?.threat_events || []).length">
                          <td colspan="5" class="muted">暂无可供 AI 研判的威胁；请确认终端已上报告警。</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  <aside v-if="aiThreatCard" class="ai-threat-card">
                    <div class="ai-threat-card-top">
                      <span class="pill" :data-ai="aiThreatCard.ai?.conclusion || ''">{{ aiThreatCard.ai?.conclusion || '待研判' }}</span>
                      <b v-if="aiThreatCard.ai?.confidence != null">置信 {{ aiThreatCard.ai.confidence }}%</b>
                    </div>
                    <h4>{{ aiThreatCard.title || '研判详情' }}</h4>
                    <p class="muted sm">原 EDR #{{ aiThreatCard.id || '—' }} · {{ aiThreatCard.severity || '—' }} · {{ aiThreatCard.etype || '—' }}</p>
                    <div class="ai-think-block">
                      <label>AI 结论说明</label>
                      <p>{{ aiThreatCard.ai?.note || '暂无' }}</p>
                    </div>
                    <div class="ai-think-block" v-if="(aiThreatCard.ai?.reasoning || []).length">
                      <label>AI 推理过程</label>
                      <ul>
                        <li v-for="(r, ri) in aiThreatCard.ai.reasoning" :key="ri">{{ r }}</li>
                      </ul>
                    </div>
                    <div class="ai-think-block">
                      <label>处置建议</label>
                      <p>{{ aiThreatCard.ai?.recommendation || '—' }}</p>
                    </div>
                    <div class="ai-think-block" v-if="(aiThreatCard.ai?.attck || []).length">
                      <label>关联 ATT&CK</label>
                      <p>{{ (aiThreatCard.ai.attck || []).join(' · ') }}</p>
                    </div>
                    <div class="ai-think-block" v-if="(aiThreatCard.ai?.entities || []).length">
                      <label>关联实体</label>
                      <ul>
                        <li v-for="(en, ei) in aiThreatCard.ai.entities" :key="ei">
                          [{{ en.type }}/{{ en.risk }}] <code>{{ en.value }}</code>
                        </li>
                      </ul>
                    </div>
                    <div class="ai-think-block" v-if="(aiThreatCard.ai?.signals || []).length">
                      <label>命中信号</label>
                      <p>{{ (aiThreatCard.ai.signals || []).join(' · ') }}</p>
                    </div>
                    <div class="ai-think-block">
                      <label>原始证据（EDR）</label>
                      <p class="mono sm">{{ aiThreatCard.matched || aiThreatCard.summary || '—' }}</p>
                      <p v-if="aiThreatCard.command_line" class="mono sm">{{ aiThreatCard.command_line }}</p>
                    </div>
                    <div class="ai-threat-actions">
                      <button type="button" class="btn sm" @click="aiTab = 'think'">看 AI 思维链</button>
                      <button type="button" class="btn sm" @click="aiTab = 'resp'">去处置</button>
                      <button type="button" class="btn sm" @click="goMenu('events')">原始威胁事件</button>
                    </div>
                  </aside>
                </div>
              </div>

              <div v-show="aiTab === 'think'" class="ai-tab-pane">
                <div class="ai-think-banner">
                  <b>AI ReAct 思维链</b>
                  <span class="muted sm">每步含线索 / 假设 / 推理 / 观察，并挂接本机告警与日志证据；模型精炼后会追加一步。</span>
                </div>
                <div v-if="(aiResult.result?.thinking_chain || []).length" class="ai-think">
                  <div class="ai-think-layout">
                    <aside class="ai-think-steps">
                      <button
                        v-for="(s, i) in aiResult.result.thinking_chain"
                        :key="s.id || i"
                        type="button"
                        class="ai-think-step"
                        :class="{ on: aiThinkIdx === i, llm: s.phase === '模型精炼' }"
                        @click="aiThinkIdx = i"
                      >
                        <b>{{ i + 1 }}. {{ s.title }}</b>
                        <small>{{ s.phase }} · {{ s.agent }}</small>
                      </button>
                    </aside>
                    <div v-if="aiThinkStep" class="ai-think-detail">
                      <h4>{{ aiThinkStep.title }}</h4>
                      <p class="muted sm">{{ aiThinkStep.phase }} · {{ aiThinkStep.agent }}</p>
                      <div class="ai-think-block"><label>线索摘要</label><p>{{ aiThinkStep.clue || '—' }}</p></div>
                      <div class="ai-think-block"><label>初始假设</label><p>{{ aiThinkStep.hypothesis || '—' }}</p></div>
                      <div class="ai-think-block">
                        <label>推理过程</label>
                        <ul><li v-for="(r, ri) in (aiThinkStep.reasoning || [])" :key="ri">{{ r }}</li></ul>
                      </div>
                      <div class="ai-think-block"><label>观察结果</label><p>{{ aiThinkStep.observation || '—' }}</p></div>
                      <div class="ai-think-block" v-if="(aiThinkStep.evidence || []).length">
                        <label>本步 AI 证据</label>
                        <ul class="ai-evidence-list">
                          <li v-for="(ev, ei) in aiThinkStep.evidence" :key="ei">{{ ev }}</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
                <p v-else class="muted">暂无思维链</p>
              </div>

              <div v-show="aiTab === 'logs'" class="ai-tab-pane ai-logs-pane">
                <div class="ai-section-hd">
                  <div>
                    <label>日志取证</label>
                    <span class="muted sm">点击一行打开详情 · 分类可筛选 · 右侧为 log_rules 命中</span>
                  </div>
                  <span class="muted sm">
                    规则库 {{ aiResult.pack_stats?.log_rules_indexed || 0 }} ·
                    命中 {{ (aiResult.result?.log_rule_hits || []).length }}
                  </span>
                </div>
                <div class="ai-log-cats">
                  <button
                    type="button"
                    class="chip soft"
                    :class="{ on: !aiLogCat }"
                    @click="aiLogCat = ''"
                  >全部 {{ aiForensicsLogs.length }}</button>
                  <button
                    v-for="(n, k) in aiLogCategoryMap"
                    :key="k"
                    type="button"
                    class="chip soft"
                    :class="{ on: aiLogCat === k }"
                    @click="aiLogCat = (aiLogCat === k ? '' : k)"
                  >{{ k }} {{ n }}</button>
                  <span v-if="!Object.keys(aiLogCategoryMap).length" class="muted">分类为空</span>
                </div>
                <div class="ai-log-board" :class="{ 'has-detail': !!aiLogCard }">
                  <div class="ai-log-main">
                    <header class="ai-panel-hd">
                      <h4>回传日志 {{ aiLogCat ? '· ' + aiLogCat : '' }}</h4>
                      <span class="muted sm">{{ aiFilteredForensicsLogs.length }} 条 · 点行看详情</span>
                    </header>
                    <div class="ai-log-table-wrap">
                      <table class="ai-mini-tbl">
                        <thead>
                          <tr><th>时间</th><th>类型</th><th>分类</th><th>摘要 / 命令行</th></tr>
                        </thead>
                        <tbody>
                          <tr
                            v-for="(l, i) in aiFilteredForensicsLogs.slice(0, 80)"
                            :key="i"
                            class="row-click"
                            :class="{ on: aiLogIdx === i }"
                            @click="openAiLogDetail(i)"
                          >
                            <td class="muted">{{ l.ts || '—' }}</td>
                            <td class="mono">{{ l.etype || '—' }}</td>
                            <td>
                              <button type="button" class="chip soft sm" @click.stop="aiLogCat = l.category || ''">
                                {{ l.category || 'other' }}
                              </button>
                            </td>
                            <td :title="l.command_line || l.summary">{{ l.summary || l.command_line || '—' }}</td>
                          </tr>
                          <tr v-if="!aiFilteredForensicsLogs.length">
                            <td colspan="4" class="muted">当前分类无日志。可切「全部」，或确认 Agent 已上报 Winlog / 持久化 / 进程事件。</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                  <aside v-if="aiLogCard" class="ai-log-detail">
                    <header class="ai-panel-hd">
                      <h4>日志详情</h4>
                      <button type="button" class="btn-text sm" @click="closeAiLogDetail">关闭</button>
                    </header>
                    <div class="ai-log-detail-body">
                      <p class="ai-log-detail-title">{{ aiLogCard.summary || aiLogCard.etype || '日志' }}</p>
                      <p class="muted sm">{{ aiLogCard.ts || '—' }} · {{ aiLogCard.etype || '—' }} · {{ aiLogCard.category || 'other' }}</p>
                      <dl class="ai-log-kv">
                        <div v-for="row in aiLogDetailRows" :key="row.k">
                          <dt>{{ row.k }}</dt>
                          <dd :class="{ mono: row.mono }" :title="row.v">{{ row.v }}</dd>
                        </div>
                      </dl>
                      <div class="ai-log-detail-acts">
                        <button type="button" class="btn sm" @click="jumpAiLogToInvestigate">到日志调查</button>
                        <button type="button" class="btn sm" @click="copyText(JSON.stringify(aiLogCard, null, 2))">复制 JSON</button>
                      </div>
                      <details class="ai-log-raw">
                        <summary>原始字段</summary>
                        <pre>{{ JSON.stringify(aiLogCard, null, 2) }}</pre>
                      </details>
                    </div>
                  </aside>
                  <div v-else class="ai-log-side">
                    <header class="ai-panel-hd">
                      <h4>日志规则命中</h4>
                      <span class="muted sm">log_rules / logrules · 实时入库也会晋升</span>
                    </header>
                    <div class="ai-log-table-wrap">
                      <table class="ai-mini-tbl">
                        <thead><tr><th>规则</th><th>来源</th><th>证据</th></tr></thead>
                        <tbody>
                          <tr
                            v-for="(h, i) in (aiResult.result?.log_rule_hits || []).slice(0, 40)"
                            :key="i"
                            class="row-click"
                            @click="openAiLogRuleHit(h)"
                          >
                            <td>{{ h.rule_title || h.title || '—' }}</td>
                            <td class="mono">{{ h.source || h.match || '—' }}</td>
                            <td :title="h.evidence">{{ h.evidence || h.etype || '—' }}</td>
                          </tr>
                          <tr v-if="!(aiResult.result?.log_rule_hits || []).length">
                            <td colspan="3" class="muted">暂无规则命中。点左侧日志可看回传详情。</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>

              <div v-show="aiTab === 'entity'" class="ai-tab-pane ai-entity-pane">
                <div class="ai-section-hd">
                  <div>
                    <label>实体研判</label>
                    <span class="muted sm">
                      共 {{ (aiResult.result?.entities || []).length }} ·
                      恶意 {{ aiEntityStats.malicious }} ·
                      可疑 {{ aiEntityStats.suspicious }} ·
                      IoC {{ (aiResult.result?.iocs || []).length }}
                    </span>
                  </div>
                  <button type="button" class="btn-text sm" @click="aiTab = 'resp'">去处置 →</button>
                </div>
                <div v-if="(aiResult.result?.entities || []).length" class="ai-entity-board">
                  <div class="ai-entity-list">
                    <button
                      v-for="(e, i) in aiResult.result.entities"
                      :key="i"
                      type="button"
                      class="ai-entity-row"
                      :class="{ on: aiEntityIdx === i }"
                      :data-risk="e.risk || ''"
                      @click="aiEntityIdx = i"
                    >
                      <span class="ai-entity-type">{{ e.type || 'obj' }}</span>
                      <span class="ai-entity-main">
                        <b :title="e.value">{{ e.value || '—' }}</b>
                        <small>{{ e.reason || e.analysis?.conclusion || '—' }}</small>
                      </span>
                      <span class="pill" :data-risk="e.risk">{{ e.risk || '—' }}</span>
                    </button>
                  </div>
                  <aside v-if="aiEntityCard" class="ai-entity-detail">
                    <div class="ai-entity-detail-top">
                      <span class="pill" :data-risk="aiEntityCard.risk">{{ aiEntityCard.risk || '—' }}</span>
                      <em>{{ aiEntityCard.type || 'entity' }}</em>
                      <span v-if="aiEntityCard.action" class="chip soft">剧本 {{ aiEntityCard.action }}</span>
                    </div>
                    <h4 class="mono">{{ aiEntityCard.value }}</h4>
                    <div class="ai-entity-grid">
                      <div class="ai-entity-box">
                        <label>基本信息</label>
                        <dl>
                          <div><dt>PID</dt><dd>{{ aiEntityCard.analysis?.basic?.pid ?? aiEntityCard.pid ?? '—' }}</dd></div>
                          <div><dt>路径</dt><dd class="mono">{{ aiEntityCard.analysis?.basic?.path || aiEntityCard.path || '—' }}</dd></div>
                          <div class="full" v-if="aiEntityCard.analysis?.basic?.command_line || aiEntityCard.command_line">
                            <dt>命令行</dt>
                            <dd class="mono">{{ aiEntityCard.analysis?.basic?.command_line || aiEntityCard.command_line }}</dd>
                          </div>
                        </dl>
                      </div>
                      <div class="ai-entity-box">
                        <label>研判过程</label>
                        <ol>
                          <li v-for="(p, pi) in (aiEntityCard.analysis?.process || ['暂无过程说明'])" :key="pi">{{ p }}</li>
                        </ol>
                      </div>
                      <div class="ai-entity-box accent">
                        <label>研判结论</label>
                        <p>{{ aiEntityCard.analysis?.conclusion || aiEntityCard.reason || '—' }}</p>
                      </div>
                      <div class="ai-entity-box advice">
                        <label>处置建议</label>
                        <p>{{ aiEntityCard.analysis?.advice || '—' }}</p>
                      </div>
                    </div>
                    <div v-if="(aiResult.result?.iocs || []).length" class="ai-ioc-strip">
                      <label>相关 IoC</label>
                      <div class="ai-ioc-chips">
                        <span v-for="(x, i) in aiResult.result.iocs.slice(0, 12)" :key="i" class="chip soft">
                          <b>{{ x.type }}</b> {{ x.value }}
                        </span>
                      </div>
                    </div>
                    <div class="ai-threat-actions">
                      <button type="button" class="btn sm" @click="aiTab = 'threats'">看 AI 研判事件</button>
                      <button type="button" class="btn sm" @click="aiTab = 'resp'">去处置</button>
                    </div>
                  </aside>
                </div>
                <div v-else class="ai-panel-empty fill">暂无实体。分析完成后会从威胁/日志抽出进程、文件、IP、注册表等。</div>
              </div>

              <div v-show="aiTab === 'report'" class="ai-tab-pane ai-report-pane">
                <div class="ai-section-hd">
                  <div>
                    <label>调查报告</label>
                    <span class="muted sm">
                      {{ aiResult.result?.verdict || '—' }} ·
                      {{ aiResult.result?.risk_level || '—' }} /
                      {{ aiResult.result?.risk_score ?? '—' }} ·
                      {{ aiResult.llm_refined || aiResult.result?.llm_refined ? '模型已精炼' : (aiResult.mode || 'Agent Team') }}
                    </span>
                  </div>
                  <div class="ai-report-actions">
                    <button type="button" class="btn-text sm" @click="aiTab = 'think'">思维链</button>
                    <button type="button" class="btn-text sm" @click="aiTab = 'resp'">处置 →</button>
                  </div>
                </div>
                <div class="ai-report-board">
                  <article class="ai-md ai-report-doc" v-html="aiMarkdownHtml" />
                  <aside class="ai-report-side">
                    <div class="ai-report-card verdict" :data-v="aiResult.result?.verdict || ''">
                      <label>AI 定性</label>
                      <b>{{ aiResult.result?.verdict || '待研判' }}</b>
                      <small>风险 {{ aiResult.result?.risk_level || '—' }} · {{ aiResult.result?.risk_score ?? '—' }}/100</small>
                    </div>
                    <div class="ai-report-card" v-if="aiResult.result?.root_cause">
                      <label>根因摘要</label>
                      <p>{{ aiResult.result.root_cause }}</p>
                    </div>
                    <div class="ai-report-card" v-if="(aiResult.result?.highlights || []).length">
                      <label>关键证据</label>
                      <ul>
                        <li v-for="(h, i) in aiResult.result.highlights.slice(0, 8)" :key="i">{{ h }}</li>
                      </ul>
                    </div>
                    <div class="ai-report-card" v-if="(aiResult.skills_used || []).length">
                      <label>使用 Skill</label>
                      <div class="ai-ioc-chips">
                        <span v-for="s in aiResult.skills_used" :key="s.id" class="chip soft" :title="(s.why || []).join('；')">
                          {{ s.name || s.id }}
                        </span>
                      </div>
                    </div>
                    <div class="ai-report-card" v-if="(aiResult.result?.iocs || []).length">
                      <label>IoC</label>
                      <ul class="ai-ioc-list">
                        <li v-for="(x, i) in aiResult.result.iocs.slice(0, 10)" :key="i">
                          <b>{{ x.type }}</b> <code>{{ x.value }}</code>
                        </li>
                      </ul>
                    </div>
                    <p v-if="aiResult.error" class="hint warn">模型回退：{{ aiResult.error }}</p>
                  </aside>
                </div>
              </div>

              <div v-show="aiTab === 'resp'" class="ai-tab-pane">
                <div v-if="(aiResult.result?.dispositions || []).length" class="ai-disp">
                  <label>推荐处置 <em class="muted">（需人工审核）</em></label>
                  <div class="ai-disp-list">
                    <div v-for="(d, i) in aiResult.result.dispositions" :key="i" class="ai-disp-row">
                      <div>
                        <b>{{ d.label }}</b>
                        <span class="mono">{{ d.target }}</span>
                        <small>{{ d.reason }}</small>
                      </div>
                      <button
                        v-if="d.action && d.action !== 'review'"
                        type="button"
                        class="btn sm danger-outline"
                        :disabled="aiDispBusy"
                        @click="runAiDisposition(d)"
                      >审核并下发</button>
                      <button v-else type="button" class="btn sm" @click="goMenu('events')">去威胁事件</button>
                    </div>
                  </div>
                </div>
                <div v-if="(aiResult.result?.hardening || []).length" class="ai-hard">
                  <label>体系化加固建议</label>
                  <ul>
                    <li v-for="(h, i) in aiResult.result.hardening" :key="i">
                      <b>{{ h.title }}</b>
                      <span>{{ h.detail }}</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>

            <div v-else class="ai-empty">
              <p>请选择左侧<strong>在线终端</strong>，点击后自动开始分析。</p>
              <p class="muted">分析内容包含：Agent 实时快照（进程/服务/任务/启动项/网络/文件等）、威胁事件，以及近 24 小时终端日志（登录/PowerShell/计划任务/服务/注册表/外联等）。</p>
            </div>
          </main>
        </div>
      </section>

<section v-if="page === 'attck'" class="page attck-page">
        <header class="page-hd">
          <div>
            <h1>ATT&CK 看板</h1>
            <p class="desc">与威胁事件同源映射 · 热力总览 · 告警下钻</p>
          </div>
          <div class="hd-right">
            <span class="live-hint" :class="{ on: liveOk }">
              <i class="live-dot" />
              {{ liveOk ? `已连接 · ${liveAgo}` : '连接中…' }}
            </span>
            <select v-model="attckAgent" class="search sev-filter" @change="loadAttckBoard">
              <option value="">全部主机</option>
              <option v-for="a in agents" :key="a.agent_id" :value="a.agent_id">{{ a.hostname || short(a.agent_id) }}</option>
            </select>
            <select v-model.number="attckDays" class="search sev-filter" @change="loadAttckBoard">
              <option :value="0">全部时间</option>
              <option :value="1">近 1 天</option>
              <option :value="7">近 7 天</option>
              <option :value="30">近 30 天</option>
            </select>
            <button type="button" class="btn ghost-btn" @click="loadAttckBoard">立即同步</button>
          </div>
        </header>

        <div class="ov-kpis ak-kpis">
          <article class="kpi click" @click="goMenu('events')">
            <span>威胁事件</span>
            <strong class="c-danger">{{ attckTotal }}</strong>
            <em>不含已加白 / 无需处置</em>
          </article>
          <article class="kpi click" @click="goMenu('events')">
            <span>未处置</span>
            <strong class="c-warn">{{ attckOpen }}</strong>
            <em>待研判处置</em>
          </article>
          <article class="kpi">
            <span>高危 / 严重</span>
            <strong class="c-danger">{{ attckHigh }}</strong>
            <em>优先响应</em>
          </article>
          <article class="kpi">
            <span>覆盖战术</span>
            <strong class="c-ink">{{ attckCovered }}<small class="kpi-den">/{{ attckHeat.length || 12 }}</small></strong>
            <em>MITRE ATT&CK 战术</em>
          </article>
          <article class="kpi">
            <span>命中技术</span>
            <strong class="c-ink">{{ attckTop.length }}</strong>
            <em>{{ attckUnmapped ? `另有 ${attckUnmapped} 条未映射` : '技术去重' }}</em>
          </article>
        </div>

        <div class="ak-board">
          <div class="panel ak-chain">
            <div class="panel-hd">
              <div>
                <h3>攻击链路</h3>
                <span class="meta">12 战术矩阵 · 点选筛选下方技术与告警</span>
              </div>
              <button v-if="attckSel.tactic || attckSel.tech" type="button" class="btn-text" @click="clearAttckSel">清除筛选</button>
            </div>
            <div class="ak-steps">
              <button
                v-for="(t, i) in attckHeat"
                :key="t.tactic"
                type="button"
                class="ak-step"
                :class="{ hit: t.count, on: attckSel.tactic === t.tactic }"
                :style="attckStepStyle(t)"
                @click="selectAttckTactic(t.tactic)"
              >
                <div class="ak-step-top">
                  <span class="ak-no">{{ String(i + 1).padStart(2, '0') }}</span>
                  <b>{{ t.name }}</b>
                </div>
                <div class="ak-step-bot">
                  <strong>{{ t.count || 0 }}</strong>
                  <em>
                    <template v-if="t.techniques.length">{{ t.techniques.length }} 项技术<template v-if="t.high"> · 高危 {{ t.high }}</template></template>
                    <template v-else>未发现</template>
                  </em>
                </div>
              </button>
            </div>
          </div>

          <div class="ak-mid">
            <div class="panel ak-tech">
              <div class="panel-hd">
                <div>
                  <h3>技术分布</h3>
                  <span class="meta">{{ attckSelTacticName ? `战术：${attckSelTacticName}` : '全部战术' }} · 点击筛选告警</span>
                </div>
              </div>
              <div v-if="attckTechList.length" class="ak-tech-list">
                <button
                  v-for="t in attckTechList"
                  :key="t.id"
                  type="button"
                  class="ak-tech-row"
                  :class="{ on: attckSel.tech === t.id }"
                  @click="selectAttckTech(t)"
                >
                  <code>{{ t.id }}</code>
                  <span class="ak-tech-name" :title="t.name">{{ t.name || '—' }}</span>
                  <span class="ak-tac">{{ t.tactic_name || attckSelTacticName || '—' }}</span>
                  <i class="rank-bar"><i :style="{ width: attckRankPct(t.count) + '%' }" /></i>
                  <strong>{{ t.count }}</strong>
                </button>
              </div>
              <p v-else class="empty sm">{{ attckSel.tactic ? '该战术下暂无命中技术' : '暂无命中技术' }}</p>
            </div>

            <div class="panel ak-hosts">
              <div class="panel-hd">
                <div>
                  <h3>告警主机</h3>
                  <span class="meta">点击只看该主机</span>
                </div>
                <button v-if="attckAgent" type="button" class="btn-text" @click="attckAgent = ''; loadAttckBoard()">全部主机</button>
              </div>
              <div v-if="attckHosts.length" class="attck-rank">
                <button
                  v-for="(h, i) in attckHosts"
                  :key="h.host || h.agent_id || i"
                  type="button"
                  class="rank-row"
                  :class="{ on: attckAgent && attckAgent === h.agent_id }"
                  @click="filterAttckByHost(h)"
                >
                  <em>{{ i + 1 }}</em>
                  <div class="rank-main">
                    <b>{{ h.host || h.hostname || short(h.agent_id) }}</b>
                    <i class="rank-bar host"><i :style="{ width: attckHostPct(h.count) + '%' }" /></i>
                  </div>
                  <strong>{{ h.count }}</strong>
                </button>
              </div>
              <p v-else class="empty sm">暂无</p>
            </div>
          </div>
        </div>

        <div class="panel attck-recent">
          <div class="panel-hd">
            <div>
              <h3>映射告警</h3>
              <span class="meta">
                <template v-if="attckSel.tactic || attckSel.tech">
                  筛选：{{ [attckSelTacticName, attckSel.tech].filter(Boolean).join(' / ') }} ·
                </template>
                共 {{ attckFiltered.length }} 条 · 点行看详情，点「威胁视图」进入处置
                <template v-if="attckFiltered.length > 60">（显示最近 60 条）</template>
              </span>
            </div>
            <div class="hd-right">
              <button type="button" class="btn sm" @click="goMenu('behaviors')">检出行为</button>
              <button type="button" class="btn sm" @click="goMenu('events')">全部威胁 →</button>
            </div>
          </div>
          <div class="table-scroll" v-if="attckFiltered.length">
            <table class="evt-table">
              <thead>
                <tr>
                  <th style="width:140px">时间</th>
                  <th style="width:72px">级别</th>
                  <th>告警</th>
                  <th style="width:220px">技术</th>
                  <th style="width:96px">战术</th>
                  <th style="width:140px">主机</th>
                  <th style="width:72px">状态</th>
                  <th style="width:96px">操作</th>
                </tr>
              </thead>
              <tbody>
                <template v-for="it in attckFiltered.slice(0, 60)" :key="it.id">
                  <tr
                    class="row-click"
                    :class="{ on: listFocusId === it.id }"
                    @click="selectListEvent({ id: it.id, title: it.title, severity: it.severity, hostname: it.hostname, agent_id: it.agent_id, status: it.status, created_at: it.ts, updated_at: it.ts, module: it.module, detail: it.detail, detail_obj: it.detail_obj })"
                  >
                    <td class="mono">{{ fmtTime(it.ts) }}</td>
                    <td><span class="sev" :data-s="it.severity">{{ sevLabel(it.severity) }}</span></td>
                    <td class="strong ak-title" :title="it.title">{{ it.title }}</td>
                    <td>
                      <span v-if="it.technique" class="ak-techcell"><code>{{ it.technique }}</code>{{ it.technique_name }}</span>
                      <span v-else class="muted">未映射</span>
                    </td>
                    <td class="muted">{{ it.tactic ? it.tactic_name : '—' }}</td>
                    <td>{{ it.hostname || short(it.agent_id) }}</td>
                    <td><span class="ak-st" :data-s="it.status">{{ statusLabel(it.status || 'open') }}</span></td>
                    <td class="ops" @click.stop>
                      <div class="op-more" @click.stop>
                        <button type="button" class="btn sm op-more-btn" :class="{ on: opMenuId === it.id }" @click="toggleOpMenu(it.id)">操作 ▾</button>
                        <div v-if="opMenuId === it.id" class="op-more-menu">
                          <button type="button" class="op-more-item primary" @click="runOpMenu(() => openEventById(it.id))">威胁视图</button>
                          <button type="button" class="op-more-item" @click="runOpMenu(() => openAllow({ id: it.id, title: it.title, agent_id: it.agent_id, hostname: it.hostname }))">加入白名单</button>
                          <button type="button" class="op-more-item danger" @click="runOpMenu(() => removeEvent({ id: it.id, title: it.title }))">删除</button>
                        </div>
                      </div>
                    </td>
                  </tr>
                  <tr v-if="listFocusId === it.id && listFocusEvent" class="evt-expand-row" :ref="(el) => scrollExpandIntoView(el)">
                    <td colspan="8">
                      <div class="evt-inline">
                        <div class="ep-hd">
                          <div class="ep-title">
                            <span class="sev" :data-s="listFocusEvent.severity">{{ sevLabel(listFocusEvent.severity) }}</span>
                            <b>{{ listFocusEvent.title }}</b>
                          </div>
                          <div class="ep-acts">
                            <button type="button" class="btn sm primary" @click.stop="openEvent(listFocusEvent)">威胁视图</button>
                            <button type="button" class="btn sm" @click.stop="openAllow(listFocusEvent)">加入白名单</button>
                            <button type="button" class="btn sm danger" @click.stop="removeEvent(listFocusEvent)">删除</button>
                            <button type="button" class="btn-text" @click.stop="clearListFocus">收起</button>
                          </div>
                        </div>
                        <div class="ep-grid">
                          <div class="ep-col">
                            <h4>对象信息</h4>
                            <dl class="td-dl">
                              <div><dt>名称</dt><dd>{{ listEvidenceName || '—' }}</dd></div>
                              <div><dt>路径 / 命令</dt><dd class="mono">{{ listEvidencePath || '—' }}</dd></div>
                              <div><dt>主机</dt><dd>{{ listFocusEvent.hostname || short(listFocusEvent.agent_id) }}</dd></div>
                              <div><dt>模块</dt><dd>{{ modLabel(listFocusEvent.module) || '—' }}</dd></div>
                            </dl>
                          </div>
                          <div class="ep-col">
                            <h4>威胁信息</h4>
                            <dl class="td-dl">
                              <div><dt>技术</dt><dd>{{ it.technique ? `${it.technique} ${it.technique_name || ''}`.trim() : '未映射' }}</dd></div>
                              <div><dt>战术</dt><dd>{{ it.tactic_name || '—' }}</dd></div>
                              <div><dt>匹配特征</dt><dd class="mono">{{ listEventEvidence.matched || '—' }}</dd></div>
                              <div><dt>判定</dt><dd>{{ judgeOf(listFocusEvent) }}</dd></div>
                            </dl>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>
          <p v-else class="empty sm">{{ (attckSel.tactic || attckSel.tech) ? '当前筛选下没有告警' : '当前时间范围内暂无威胁事件' }}</p>
        </div>
      </section>
</template>

<script>
import { forwardSetupContext } from './setupContext.js'
export default { props: { context: { type: Object, required: true } }, setup(props) { return forwardSetupContext(props.context) } }
</script>
