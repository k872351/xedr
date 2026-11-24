<template>
<section v-if="page === 'ioc'" class="page ioc-page">
        <header class="page-hd">
          <div>
            <h1>威胁情报 IOC</h1>
            <p class="desc">情报库自动匹配 · 本地自定义补充 · 命中一键下钻</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn" @click="loadIoc(); loadEvents(false)">刷新</button>
            <button type="button" class="btn primary" @click="goIocHits('')">全部 IOC 告警</button>
          </div>
        </header>

        <div class="ioc-hero panel">
          <div class="ioc-hero-main">
            <div class="ioc-hero-title">
              <span :class="iocLib?.exists === false ? 'ioc-badge bad' : 'ioc-badge ok'">
                {{ iocLib?.exists === false ? '未加载' : '情报库已就绪' }}
              </span>
              <code class="ioc-path" :title="iocLib?.path || ''">{{ iocLib?.path || 'ioc/ioc_data.db' }}</code>
            </div>
            <div class="ioc-hero-stats">
              <div class="ioc-stat">
                <em>情报条目</em>
                <b>{{ fmtNum(iocLib?.count || 0) }}</b>
              </div>
              <div class="ioc-stat">
                <em>本地 IOC</em>
                <b>{{ iocLibLocal }}</b>
              </div>
              <div class="ioc-stat">
                <em>最近命中</em>
                <b>{{ recentIocHits.length }}</b>
              </div>
            </div>
            <div v-if="iocLibTypeChips.length" class="ioc-type-chips">
              <span v-for="t in iocLibTypeChips" :key="t.key" class="ioc-type">{{ t.key }} <strong>{{ fmtNum(t.n) }}</strong></span>
            </div>
            <p v-if="iocLib?.hint" class="ioc-hint">{{ iocLib.hint }}</p>
          </div>
          <div class="ioc-hero-lookup">
            <label>试查情报库</label>
            <div class="ioc-lookup-row">
              <select v-model="iocLookupType" class="field">
                <option value="hash">hash</option>
                <option value="domain">domain</option>
                <option value="ip">ip</option>
                <option value="url">url</option>
              </select>
              <input
                v-model="iocLookupValue"
                class="field grow"
                placeholder="输入 hash / IP / 域名，回车查询"
                @keyup.enter="doIocLookup"
              />
              <button type="button" class="btn primary" :disabled="iocLookupBusy || !iocLookupValue.trim()" @click="doIocLookup">
                {{ iocLookupBusy ? '查询中…' : '查询' }}
              </button>
            </div>
            <div v-if="iocLookupResult" class="ioc-lookup-result">
              <p v-if="iocLookupResult.error" class="err-text">{{ iocLookupResult.error }}</p>
              <p v-else-if="!(iocLookupResult.hits || []).length" class="muted">未命中情报库</p>
              <ul v-else>
                <li v-for="(h, i) in iocLookupResult.hits" :key="i">
                  <span class="ioc-type">{{ h.type || iocLookupType }}</span>
                  <code>{{ h.value }}</code>
                  <em>{{ h.malware || h.source || '命中' }}</em>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <div class="ioc-body">
          <div class="panel ioc-local">
            <header class="ioc-card-hd">
              <div>
                <h3>本地自定义 IOC</h3>
                <p>批量导入后参与时间线匹配；点命中数可下钻告警</p>
              </div>
              <span class="ioc-count">{{ filteredIocItems.length }} / {{ iocItems.length }}</span>
            </header>
            <div class="ioc-card-bd">
              <div class="ioc-import">
                <div class="ioc-import-bar">
                  <select v-model="iocType" class="field">
                    <option value="hash">hash</option>
                    <option value="domain">domain</option>
                    <option value="ip">ip</option>
                    <option value="path">path</option>
                    <option value="process">process</option>
                    <option value="cmdline">cmdline</option>
                  </select>
                  <select v-model="iocSeverity" class="field">
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                  </select>
                  <button type="button" class="btn primary" :disabled="!isAdmin || !iocText.trim()" @click="doImportIoc">批量导入</button>
                </div>
                <textarea
                  v-model="iocText"
                  class="field ioc-ta"
                  rows="4"
                  placeholder="每行一个 IOC；也可写 type:value，例如 domain:evil.com"
                />
              </div>
              <div class="ioc-list-tools">
                <input v-model="iocQ" class="field grow" placeholder="筛选类型 / 值 / 备注…" />
              </div>
              <div v-if="filteredIocItems.length" class="ioc-table-wrap">
                <table>
                  <thead>
                    <tr><th>类型</th><th>值</th><th>级别</th><th>命中</th><th>备注</th><th></th></tr>
                  </thead>
                  <tbody>
                    <tr v-for="x in filteredIocItems" :key="x.id">
                      <td><span class="ioc-type">{{ x.ioc_type }}</span></td>
                      <td class="mono" :title="x.value">{{ x.value }}</td>
                      <td><span class="sev" :data-s="x.severity">{{ sevLabel(x.severity) }}</span></td>
                      <td>
                        <button type="button" class="btn-text" :disabled="!(x.hits > 0)" @click="goIocHits(x.value)">{{ x.hits || 0 }}</button>
                      </td>
                      <td class="muted">{{ x.note || '—' }}</td>
                      <td class="ops">
                        <button type="button" class="btn-text" @click="goIocHits(x.value)">下钻</button>
                        <button type="button" class="btn-text danger" :disabled="!isAdmin" @click="delIoc(x.id)">删除</button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div v-else class="ioc-empty">
                <b>还没有本地 IOC</b>
                <p>情报库仍会自动匹配哈希 / IP / 域名。需要补充自定义指标时，在上方粘贴后导入。</p>
              </div>
            </div>
          </div>

          <aside class="panel ioc-hits">
            <header class="ioc-card-hd">
              <div>
                <h3>最近命中</h3>
                <p>点击打开威胁详情</p>
              </div>
              <button type="button" class="btn-text" @click="goIocHits('')">全部 →</button>
            </header>
            <div v-if="recentIocHits.length" class="ioc-hit-list">
              <button
                v-for="e in recentIocHits"
                :key="e.id"
                type="button"
                class="ioc-hit-row"
                @click="openEvent(e)"
              >
                <span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span>
                <div class="ioc-hit-main">
                  <b>{{ iocHitValue(e) }}</b>
                  <span class="ioc-hit-meta">
                    <em v-if="iocHitKind(e)">{{ iocHitKind(e) }}</em>
                    <em>{{ e.hostname || short(e.agent_id) }}</em>
                    <em>{{ fmtTime(e.created_at || e.ts) }}</em>
                  </span>
                  <span v-if="iocHitTag(e)" class="ioc-hit-tag">{{ iocHitTag(e) }}</span>
                </div>
              </button>
            </div>
            <div v-else class="ioc-empty slim">
              <b>暂无命中</b>
              <p>终端上报含哈希 / IP / 域名的事件后，这里会显示。</p>
            </div>
          </aside>
        </div>
      </section>

<section v-if="page === 'upgrade'" class="page upgrade-page">
        <header class="page-hd">
          <div>
            <h1>灰度升级</h1>
            <p class="desc">上传 Agent 二进制 → 选择终端推送 upgrade 指令（校验 sha256 后替换）</p>
          </div>
          <button type="button" class="btn" @click="loadUpgradePage">刷新</button>
        </header>
        <div class="upgrade-summary">
          <div class="panel upgrade-metric"><span>已上传升级包</span><strong>{{ upPackages.length }}</strong><small>升级包记录</small></div>
          <div class="panel upgrade-metric"><span>终端总数</span><strong>{{ agents.length }}</strong><small>当前终端列表</small></div>
          <div class="panel upgrade-metric"><span>在线终端</span><strong>{{ agents.filter(a => a.online).length }}</strong><small>当前在线状态</small></div>
          <div class="panel upgrade-metric"><span>已选终端</span><strong>{{ upAgentIds.length }}</strong><small>当前勾选数量</small></div>
        </div>
        <div class="upgrade-form-grid">
          <article class="panel pad upgrade-form-card">
            <div class="upgrade-card-title"><span>01</span><h3>上传升级包</h3></div>
            <label class="form-lab">
              <span>版本号</span>
              <input v-model="upVer" class="field" placeholder="如 0.7.0" />
            </label>
            <label class="form-lab">
              <span>备注</span>
              <input v-model="upNote" class="field" placeholder="可选" />
            </label>
            <label class="form-lab">
              <span>forensic-agent.exe</span>
              <input type="file" accept=".exe" @change="onUpFile" />
            </label>
            <button type="button" class="btn primary" :disabled="upBusy || !upFile" @click="doUploadUpgrade">
              {{ upBusy ? '上传中…' : '上传' }}
            </button>
            <p v-if="upError" class="err-text">{{ upError }}</p>
            <p v-if="upOk" class="hint">{{ upOk }}</p>
          </article>
          <article class="panel pad upgrade-form-card">
            <div class="upgrade-card-title"><span>02</span><h3>选择终端并推送</h3></div>
            <div class="hunt-bar">
              <select v-model="upPkgId" class="search grow">
                <option value="">选择已上传的包</option>
                <option v-for="p in upPackages" :key="p.id" :value="p.id">
                  {{ p.version }} · {{ short(p.sha256) }} · {{ fmtSize(p.size) }}
                </option>
              </select>
            </div>
            <div class="up-hosts">
              <label v-for="a in agents" :key="a.agent_id" class="chk">
                <input type="checkbox" :value="a.agent_id" v-model="upAgentIds" />
                {{ a.hostname || short(a.agent_id) }}
                <em class="muted">{{ a.version || '?' }} {{ a.online ? '在线' : '离线' }}</em>
              </label>
              <p v-if="!agents.length" class="deployment-empty">暂无终端</p>
            </div>
            <div class="row" style="margin-top:12px">
              <button type="button" class="btn" @click="upAgentIds = agents.map(a => a.agent_id)">全选</button>
              <button type="button" class="btn" @click="upAgentIds = agents.filter(a => a.online).map(a => a.agent_id)">仅在线</button>
              <button type="button" class="btn primary" :disabled="upPushBusy || !upPkgId || !upAgentIds.length" @click="doPushUpgrade">
                {{ upPushBusy ? '推送中…' : `灰度推送 (${upAgentIds.length})` }}
              </button>
              <button type="button" class="btn danger-outline" :disabled="upPushBusy || !upAgentIds.length" @click="doRollbackUpgrade">
                回滚升级
              </button>
            </div>
          </article>
        </div>
        <div class="upgrade-record-grid">
        <nav class="upgrade-record-tabs" aria-label="升级记录">
          <button type="button" :class="{ on: upgradeRecordTab === 'fleet' }" :aria-pressed="upgradeRecordTab === 'fleet'" @click="upgradeRecordTab = 'fleet'">灰度状态 <span>{{ upgradeFleetRows.length }}</span></button>
          <button type="button" :class="{ on: upgradeRecordTab === 'packages' }" :aria-pressed="upgradeRecordTab === 'packages'" @click="upgradeRecordTab = 'packages'">已上传包 <span>{{ upPackages.length }}</span></button>
          <button type="button" :class="{ on: upgradeRecordTab === 'drift' }" :aria-pressed="upgradeRecordTab === 'drift'" @click="upgradeRecordTab = 'drift'">组件漂移 <span>{{ upgradeDriftRows.length }}</span></button>
          <button type="button" :class="{ on: upgradeRecordTab === 'diagnostics' }" :aria-pressed="upgradeRecordTab === 'diagnostics'" @click="upgradeRecordTab = 'diagnostics'">诊断包历史 <span>{{ diagHistoryItems.length }}</span></button>
        </nav>
        <div v-show="upgradeRecordTab === 'packages'" class="panel upgrade-record">
          <div class="panel-hd"><h3>已上传包</h3><span class="record-count">{{ upPackages.length }} 条</span></div>
          <div v-if="upPackages.length" class="table-scroll"><table>
            <thead><tr><th>版本</th><th>SHA256</th><th>大小</th><th>时间</th><th></th></tr></thead>
            <tbody>
              <tr v-for="p in upPackages" :key="p.id">
                <td>{{ p.version }}</td>
                <td class="mono muted">{{ p.sha256 }}</td>
                <td>{{ fmtSize(p.size) }}</td>
                <td>{{ fmtTime(p.created_at) }}</td>
                <td>
                  <button type="button" class="btn-text" @click="upPkgId = p.id">选用</button>
                  <button type="button" class="btn-text" style="color:var(--danger)" @click="doDelUpgrade(p.id)">删除</button>
                </td>
              </tr>
            </tbody>
          </table></div>
          <div v-else class="upgrade-empty">暂无已上传升级包</div>
        </div>
        <div v-show="upgradeRecordTab === 'drift'" class="panel upgrade-record">
          <div class="panel-hd"><h3>组件漂移</h3><span class="record-count">{{ upgradeDriftRows.length }} 条</span></div>
          <p class="upgrade-record-note">服务端集成期望与终端实际状态对比。</p>
          <div v-if="upgradeDriftRows.length" class="table-scroll"><table>
            <thead>
              <tr><th>终端</th><th>缺失</th><th>失败/降级</th><th>sync</th><th>策略</th></tr>
            </thead>
            <tbody>
              <tr v-for="row in upgradeDriftRows" :key="row.agent_id">
                <td>{{ row.hostname || short(row.agent_id) }}</td>
                <td class="mono sm">{{ (row.missing || []).join(', ') || '—' }}</td>
                <td class="mono sm">{{ [...(row.failed||[]), ...(row.degraded||[])].join(', ') || '—' }}</td>
                <td>{{ row.sync_drift ? `${row.local_sync_rev}<${row.server_sync_rev}` : 'OK' }}</td>
                <td>{{ row.policy_drift ? '未收敛' : 'OK' }}</td>
              </tr>
            </tbody>
          </table></div>
          <div v-else class="upgrade-empty">暂无组件漂移记录</div>
        </div>
        <div v-show="upgradeRecordTab === 'fleet'" class="panel upgrade-record upgrade-fleet-record">
          <div class="panel-hd"><h3>灰度状态</h3><span class="record-count">{{ upgradeFleetRows.length }} 台</span></div>
          <p class="upgrade-record-note">升级阶段、策略同步及终端最近指令状态。</p>
          <div v-if="upgradeFleetRows.length" class="table-scroll"><table>
            <thead>
              <tr>
                <th>终端</th>
                <th>版本</th>
                <th>PolicyApplied</th>
                <th>local sync / policy rev</th>
                <th>升级 Details</th>
                <th>遥测 / sync</th>
                <th>最近 upgrade 指令</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in upgradeFleetRows" :key="row.agent_id">
                <td>{{ row.hostname || short(row.agent_id) }} <em class="muted">{{ row.online ? '在线' : '离线' }}</em></td>
                <td class="mono">{{ row.version || '—' }}</td>
                <td>
                  <span class="pill" :class="{ on: row.policy_applied }">{{ row.policy_applied ? '已收敛' : '同步中' }}</span>
                </td>
                <td class="mono muted">{{ row.local_sync_rev }} / {{ row.local_policy_rev }}</td>
                <td class="mono sm">{{ row.upgrade_details || '—' }}</td>
                <td class="mono sm" :title="row.telemetry_hint">{{ row.telemetry_line || '—' }}</td>
                <td class="mono sm">{{ row.last_upgrade_cmd || '—' }}</td>
                <td>
                  <button type="button" class="btn-text" :disabled="!row.online || !row.upgrade_details" @click="cancelHostUpgrade(row)">取消升级</button>
                </td>
              </tr>
            </tbody>
          </table></div>
          <div v-else class="upgrade-empty">暂无终端数据，请先刷新或等待 Agent 心跳。</div>
        </div>
        <div v-show="upgradeRecordTab === 'diagnostics'" class="panel upgrade-record upgrade-diag-record">
          <div class="panel-hd">
            <h3>诊断包历史</h3>
            <button type="button" class="btn sm" @click="loadDiagHistory">刷新</button>
          </div>
          <div v-if="diagHistoryItems.length" class="table-scroll"><table>
            <thead><tr><th>终端</th><th>指令</th><th>文件</th><th>大小</th><th></th></tr></thead>
            <tbody>
              <tr v-for="d in diagHistoryItems" :key="d.agent_id + d.command_id">
                <td class="mono sm">{{ short(d.agent_id) }}</td>
                <td class="mono sm">{{ d.command_id }}</td>
                <td class="mono sm">{{ d.filename }}</td>
                <td>{{ Math.round((d.size || 0) / 1024) }} KB</td>
                <td><button type="button" class="btn-text" @click="downloadAgentDiagnostics(d.agent_id, d.command_id)">下载</button></td>
              </tr>
            </tbody>
          </table></div>
          <div v-else class="upgrade-empty">暂无已落盘诊断包</div>
        </div>
        </div>
      </section>

<section v-if="page === 'seq'" class="page seq-page">
        <header class="page-hd">
          <div>
            <h1>行为序列规则</h1>
            <p class="desc">
              在主机时间线的时间窗口内，按顺序命中多步行为（如「Word 创建 → PowerShell 出现」），用于发现单条特征看不出的攻击链。
            </p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn" @click="loadSeqRules">刷新</button>
            <button type="button" class="btn primary" @click="startCreateSeq">新增序列</button>
          </div>
        </header>

        <div class="seq-explain panel pad">
          <b>什么是行为序列？</b>
          <p>
            Agent 规则是「单条快照命中」；行为序列是「多条时间线事件按顺序出现」。
            例如 180 秒内先出现办公软件进程，再出现 PowerShell，就会告警——对应钓鱼宏常见攻击链。
          </p>
        </div>

        <div class="rules-layout">
          <div class="panel fill">
            <div class="panel-hd">
              <h3>序列列表 ({{ seqRules.length }})</h3>
              <span class="meta">启用 {{ seqRules.filter(r => r.enabled).length }} 条</span>
            </div>
            <div class="table-scroll">
              <table v-if="seqRules.length">
                <thead>
                  <tr>
                    <th>启用</th>
                    <th>标题</th>
                    <th>窗口</th>
                    <th>级别</th>
                    <th>步骤</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="r in seqRules"
                    :key="r.id"
                    class="row-click"
                    :class="{ active: editingSeq?.id === r.id && !seqCreating }"
                    @click="startEditSeq(r)"
                  >
                    <td @click.stop>
                      <label class="switch">
                        <input type="checkbox" :checked="!!r.enabled" @change="toggleSeq(r, $event.target.checked)" />
                        <i />
                      </label>
                    </td>
                    <td>
                      <b class="strong">{{ r.title }}</b>
                      <div class="meta">{{ r.note || r.id }}</div>
                    </td>
                    <td>{{ r.window_sec }}s</td>
                    <td><span class="sev" :data-s="r.severity">{{ sevLabel(r.severity) }}</span></td>
                    <td class="muted">{{ seqStepsPreview(r) }}</td>
                    <td class="ops" @click.stop>
                      <button type="button" class="link" @click="startEditSeq(r)">编辑</button>
                      <button type="button" class="link danger" @click="removeSeq(r)">删除</button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-else class="empty">暂无序列规则，点击右上角新增</p>
            </div>
          </div>

          <aside class="panel pad rule-editor">
            <h3>{{ seqCreating ? '新增序列' : (editingSeq ? '编辑序列' : '序列编辑') }}</h3>
            <p v-if="!seqCreating && !editingSeq" class="hint">选中左侧编辑，或点击「新增序列」。至少配置 2 步（A→B）。</p>
            <template v-if="seqCreating || editingSeq">
              <div v-if="seqCreating" class="form-lab">
                <span>快速模板</span>
                <div class="chip-row">
                  <button
                    v-for="t in SEQ_TEMPLATES"
                    :key="t.id"
                    type="button"
                    class="chip-btn"
                    @click="applySeqTemplate(t)"
                  >{{ t.label }}</button>
                </div>
              </div>
              <label class="form-lab">
                <span>标题 *</span>
                <input v-model="seqForm.title" class="field" placeholder="例如：办公进程后出现 PowerShell" />
              </label>
              <div class="form-row2">
                <label class="form-lab">
                  <span>严重级别</span>
                  <select v-model="seqForm.severity" class="field">
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                  </select>
                </label>
                <label class="form-lab">
                  <span>时间窗口（秒）</span>
                  <input v-model.number="seqForm.window_sec" type="number" min="10" max="3600" class="field" />
                </label>
              </div>
              <div class="form-lab">
                <span>步骤序列 *（按时间先后，至少 2 步）</span>
                <div v-for="(st, idx) in seqForm.steps" :key="idx" class="seq-step">
                  <header>
                    <b>第 {{ idx + 1 }} 步</b>
                    <button v-if="seqForm.steps.length > 2" type="button" class="link danger" @click="removeSeqStep(idx)">删除</button>
                  </header>
                  <label class="form-lab">
                    <span>事件类型包含</span>
                    <select v-model="st.etype_contains" class="field">
                      <option value="">不限</option>
                      <option value="process">process（进程）</option>
                      <option value="network">network（网络）</option>
                      <option value="file">file（文件）</option>
                      <option value="driver">driver（驱动）</option>
                      <option value="service">service（服务）</option>
                      <option value="registry">registry（注册表）</option>
                    </select>
                  </label>
                  <label class="form-lab">
                    <span>摘要包含</span>
                    <input v-model="st.summary_contains" class="field" placeholder="可选，如：临时" />
                  </label>
                  <label class="form-lab">
                    <span>进程名正则</span>
                    <input v-model="st.name_regex" class="field" placeholder="可选，如 (?i)powershell\.exe" />
                  </label>
                </div>
                <button type="button" class="btn" style="margin-top:8px" @click="addSeqStep" :disabled="seqForm.steps.length >= 6">
                  + 添加步骤
                </button>
              </div>
              <label class="form-lab">
                <span>备注</span>
                <input v-model="seqForm.note" class="field" placeholder="可选，如 ATT&CK 技术链说明" />
              </label>
              <label class="chk">
                <input type="checkbox" v-model="seqForm.enabled" />
                启用此序列
              </label>
              <p v-if="seqFormError" class="err-text">{{ seqFormError }}</p>
              <div class="row" style="margin-top:14px">
                <button type="button" class="btn primary" :disabled="seqSaving" @click="saveSeqForm">
                  {{ seqSaving ? '保存中…' : '保存' }}
                </button>
                <button type="button" class="btn" @click="cancelSeqForm">取消</button>
              </div>
            </template>
          </aside>
        </div>
      </section>

<section v-if="page === 'groups'" class="page groups-page">
        <header class="page-hd">
          <div>
            <h1>终端分组</h1>
            <p class="desc">先起组名再勾选主机；也可在「终端列表」分组列直接改。在线 / 离线均可加入分组</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn" @click="refresh(); loadGroups()">刷新主机</button>
            <button type="button" class="btn" @click="goMenu('hosts')">回终端列表</button>
          </div>
        </header>

        <div class="groups-layout">
          <div class="panel pad groups-editor">
            <div class="groups-editor-hd">
              <h3>{{ groupEditId ? '编辑分组' : '新建分组' }}</h3>
              <button v-if="groupEditId" type="button" class="btn-text" @click="resetGroupForm">改为新建</button>
            </div>
            <label class="form-lab">
              <span>分组名称</span>
              <input v-model="groupName" class="field" placeholder="例如：财务 / 研发 / 测试机" />
            </label>
            <label class="form-lab">
              <span>备注（可选）</span>
              <input v-model="groupNote" class="field" placeholder="用途说明，如：财务部办公机" />
            </label>
            <div class="groups-pick-hd">
              <b>选择主机</b>
              <label class="chk">
                <input type="checkbox" v-model="groupPickOnlineOnly" />
                仅显示在线
              </label>
              <button type="button" class="btn-text" @click="selectAllGroupHosts(true)">全选</button>
              <button type="button" class="btn-text" @click="selectAllGroupHosts(false)">清空</button>
            </div>
            <div class="groups-pick-list">
              <label
                v-for="a in groupPickAgents"
                :key="a.agent_id"
                class="groups-pick-row"
                :class="{ on: isGroupHostPicked(a.agent_id) }"
              >
                <input type="checkbox" :checked="isGroupHostPicked(a.agent_id)" @change="toggleGroupHost(a.agent_id, $event.target.checked)" />
                <i :class="['dot', a.online ? 'on' : '']" />
                <span class="gph-name">{{ a.hostname || short(a.agent_id) }}</span>
                <span class="mono muted">{{ a.ip || '—' }}</span>
                <span v-if="groupsOfAgent(a.agent_id).length" class="gph-groups" :title="agentGroupLabel(a.agent_id)">
                  {{ agentGroupLabel(a.agent_id) }}
                </span>
                <em class="pill" :class="{ on: a.online }">{{ a.online ? '在线' : '离线' }}</em>
              </label>
              <p v-if="!groupPickAgents.length" class="empty sm">
                {{ groupPickOnlineOnly ? '当前没有在线主机。可取消「仅显示在线」，或先部署并确认终端心跳。' : '暂无终端，请先部署安装包。' }}
              </p>
            </div>
            <p class="hint sm" style="margin:8px 0 0">已在其它组的主机仍可勾选；保存后会加入本组（可多组并存）。若要「换组」，请到终端列表分组列直接改。</p>
            <div class="groups-editor-acts">
              <button type="button" class="btn primary" :disabled="!groupName.trim() || groupBusy" @click="saveGroup">
                {{ groupBusy ? '保存中…' : (groupEditId ? '保存修改' : '保存分组') }}
              </button>
              <button v-if="groupEditId" type="button" class="btn" :disabled="groupBusy" @click="resetGroupForm">取消</button>
              <button
                v-if="groupEditId"
                type="button"
                class="btn danger"
                :disabled="groupBusy"
                @click="removeGroup({ id: groupEditId, name: groupName })"
              >删除此分组</button>
              <span class="muted sm">已选 {{ groupPickedIds.length }} 台</span>
            </div>
          </div>

          <div class="panel pad groups-list">
            <h3>已有分组 <em>{{ groupItems.length }}</em></h3>
            <div v-if="groupItems.length" class="groups-cards">
              <article
                v-for="g in groupItems"
                :key="g.id"
                class="groups-card"
                :class="{ editing: String(groupEditId) === String(g.id) }"
              >
                <header>
                  <div>
                    <b>{{ g.name }}</b>
                    <small v-if="g.note" class="muted">{{ g.note }}</small>
                  </div>
                  <span class="pill">{{ (g.agent_ids || []).length }} 台</span>
                </header>
                <ul>
                  <li v-for="aid in (g.agent_ids || [])" :key="aid">
                    <i :class="['dot', agentOnline(aid) ? 'on' : '']" />
                    <span>{{ agentHostLabel(aid) }}</span>
                    <button type="button" class="btn-text danger" title="从本组移除" @click="removeHostFromGroup(g, aid)">移除</button>
                  </li>
                  <li v-if="!(g.agent_ids || []).length" class="groups-empty-hint">尚未加入主机 · 左侧勾选主机后点「保存修改」</li>
                </ul>
                <div class="ops">
                  <button type="button" class="btn sm" @click="editGroup(g)">更改</button>
                  <button type="button" class="btn sm" @click="hostGroupFilter = String(g.id); goMenu('hosts')">在列表中查看</button>
                  <button type="button" class="btn sm danger" :disabled="groupBusy" @click="removeGroup(g)">删除</button>
                </div>
              </article>
            </div>
            <p v-else class="empty sm">还没有分组。左侧填写名称并勾选主机后点「保存分组」。</p>
          </div>
        </div>
      </section>

<section v-if="page === 'audit'" class="page">
        <header class="page-hd">
          <div>
            <h1>处置审计</h1>
            <p class="desc">谁在何时对哪台终端下发了什么动作</p>
          </div>
          <button type="button" class="btn" @click="loadAudit">刷新</button>
        </header>
        <div class="panel record-panel">
          <div class="panel-hd"><h3>审计记录</h3><span class="record-count">{{ auditItems.length }} 条记录</span></div>
          <div v-if="auditItems.length" class="table-scroll record-table"><table>
            <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>终端</th><th>详情</th></tr></thead>
            <tbody>
              <tr v-for="a in auditItems" :key="a.id">
                <td>{{ fmtTime(a.created_at) }}</td>
                <td>{{ a.actor || '—' }}</td>
                <td>{{ a.action }}</td>
                <td>{{ short(a.agent_id) }}</td>
                <td class="muted" :title="a.detail">{{ (a.detail || '').slice(0, 100) }}</td>
              </tr>
            </tbody>
          </table></div>
          <div v-else class="record-empty"><span class="record-empty-mark" aria-hidden="true">—</span><strong>暂无审计记录</strong><p>产生审计记录后将在此展示。</p></div>
        </div>
      </section>

<section v-if="page === 'settings'" class="page settings-page">
        <header class="page-hd">
          <div>
            <h1>平台配置</h1>
            <p class="desc">接入地址 · 大模型（本地/在线）· 实时规则启停</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn sm" @click="goMenu('deploy')">部署下载</button>
            <button type="button" class="btn sm" @click="goMenu('upgrade')">灰度升级</button>
            <button type="button" class="btn sm" @click="setSection('rules')">规则管理</button>
          </div>
        </header>

        <div class="settings-stack">
          <div class="panel pad settings-addr">
            <div class="settings-addr-row">
              <label class="grow">
                <span>EDR 平台地址</span>
                <input v-model="agentServerUrl" class="field" :disabled="!isAdmin" placeholder="http://192.168.31.94:8100" />
              </label>
              <div v-if="isAdmin" class="settings-addr-acts">
                <button type="button" class="btn primary" :disabled="saving" @click="saveSettings">{{ saving ? '保存中…' : '保存' }}</button>
                <button type="button" class="btn" @click="rotateKey">轮换接入密钥</button>
              </div>
            </div>
            <p class="hint">填终端能访问到的 xedr 后台地址（勿用 127.0.0.1）。留空则按当前浏览器地址生成安装包。轮换密钥后需重新下载安装包。</p>
          </div>

          <div class="panel pad settings-ai-panel">
            <div class="settings-ai-hd">
              <div>
                <h3 style="margin:0 0 4px;font-size:15px">模型配置</h3>
                <p class="hint sm" style="margin:0">可保存多套本地/在线模型，切换「使用」；保存后可「测试连接」确认可用性。</p>
              </div>
              <span class="pill" :class="aiModelForm.has_key || aiStatusInfo.configured ? 'ok' : 'warn'">
                {{ aiProfiles.length ? `${aiProfiles.length} 套` : (aiModelForm.has_key || aiStatusInfo.configured ? '已配置' : '未配置') }}
              </span>
            </div>

            <div v-if="aiProfiles.length" class="settings-ai-profiles">
              <button
                v-for="p in aiProfiles"
                :key="p.id"
                type="button"
                class="settings-ai-profile"
                :class="{ on: p.id === aiModelForm.id, active: p.active }"
                @click="selectAiProfile(p)"
              >
                <b>{{ p.name || p.model || '未命名' }}</b>
                <small class="mono">{{ p.provider_mode === 'local' ? '本地' : '在线' }} · {{ p.model || '—' }}</small>
                <em v-if="p.active" class="pill ok sm">使用中</em>
              </button>
              <button
                v-if="isAdmin"
                type="button"
                class="settings-ai-profile add"
                @click="startNewAiProfile"
              >+ 新增模型</button>
            </div>

            <div class="settings-ai-modes">
              <button
                type="button"
                class="chip-btn"
                :class="{ on: aiModelForm.provider_mode === 'local' }"
                :disabled="!isAdmin"
                @click="applyAiModelPreset('local')"
              >本地模型</button>
              <button
                type="button"
                class="chip-btn"
                :class="{ on: aiModelForm.provider_mode === 'online' }"
                :disabled="!isAdmin"
                @click="applyAiModelPreset('online')"
              >在线模型</button>
              <button
                v-for="p in AI_ONLINE_PRESETS"
                :key="p.id"
                type="button"
                class="chip-btn ghost"
                :disabled="!isAdmin || aiModelForm.provider_mode !== 'online'"
                @click="applyAiOnlineVendor(p)"
              >{{ p.label }}</button>
            </div>
            <div class="settings-ai-grid">
              <label>
                <span>显示名称</span>
                <input
                  v-model="aiModelForm.name"
                  class="field"
                  :disabled="!isAdmin"
                  :placeholder="aiModelForm.provider_mode === 'local' ? '如：内网 Qwen' : '如：DeepSeek 生产'"
                />
              </label>
              <label>
                <span>超时（秒）</span>
                <input v-model.number="aiModelForm.timeout" class="field" type="number" min="30" max="600" :disabled="!isAdmin" />
              </label>
              <label>
                <span>Base URL</span>
                <input
                  v-model="aiModelForm.base_url"
                  class="field mono"
                  :disabled="!isAdmin"
                  :placeholder="aiModelForm.provider_mode === 'local' ? 'http://192.168.x.x:8085/v1' : 'https://api.openai.com/v1'"
                />
              </label>
              <label>
                <span>模型名</span>
                <input
                  v-model="aiModelForm.model"
                  class="field mono"
                  :disabled="!isAdmin"
                  :placeholder="aiModelForm.provider_mode === 'local' ? 'qwen3… / llama…' : 'gpt-4o-mini / deepseek-chat'"
                />
              </label>
              <label class="span-2">
                <span>API Key {{ aiModelForm.has_key ? `（当前 ${aiModelForm.api_key_masked || '已保存'}）` : '' }}</span>
                <input
                  v-model="aiModelForm.api_key"
                  class="field mono"
                  type="password"
                  autocomplete="new-password"
                  :disabled="!isAdmin"
                  :placeholder="aiModelForm.has_key ? '留空则保持原密钥' : (aiModelForm.provider_mode === 'local' ? '本地网关可随意填写' : 'sk-…')"
                />
              </label>
            </div>
            <div v-if="isAdmin" class="settings-ai-acts">
              <button type="button" class="btn primary" :disabled="aiModelSaving || aiModelTesting" @click="saveAiModelConfig">
                {{ aiModelSaving ? '保存中…' : (aiModelForm.is_new ? '新增并启用' : '保存') }}
              </button>
              <button
                v-if="aiModelForm.id && !aiModelForm.is_new && !aiModelForm.active"
                type="button"
                class="btn sm"
                :disabled="aiModelSaving || aiModelTesting"
                @click="activateAiModelProfile(aiModelForm.id)"
              >设为使用</button>
              <button type="button" class="btn sm" :disabled="aiModelSaving || aiModelTesting" @click="testAiModelConfig">
                {{ aiModelTesting ? '测试中…' : '测试连接' }}
              </button>
              <button
                v-if="aiModelForm.id && !aiModelForm.is_new && aiProfiles.length > 1"
                type="button"
                class="btn sm danger-ghost"
                :disabled="aiModelSaving || aiModelTesting"
                @click="deleteAiModelProfile(aiModelForm.id)"
              >删除</button>
              <button type="button" class="btn sm" :disabled="aiModelSaving || aiModelTesting" @click="loadAiModelConfig">刷新</button>
              <span v-if="aiModelTestMsg" class="muted sm" :class="{ ok: aiModelTestOk, err: aiModelTestOk === false }">{{ aiModelTestMsg }}</span>
              <span v-else class="muted sm">密钥加密存储；测试会向模型发一条极短请求。</span>
            </div>
            <p v-else class="hint sm">仅管理员可修改模型配置。</p>
          </div>

          <div v-if="isAdmin" class="panel pad">
            <h3 style="margin:0 0 8px;font-size:15px">运维</h3>
            <label class="chk">
              <input type="checkbox" :checked="autoEnrichOnLoad" @change="setAutoEnrichOnLoad($event.target.checked)" />
              刷新威胁列表时自动 enrich 详情（最多 120 条，仅管理员）
            </label>
            <p class="hint sm">补全历史告警命令行/PTM 链；大库时可能增加 SQLite 写入，按需开启。</p>
          </div>

          <div class="panel settings-rules-panel">
            <div class="panel-hd">
              <div>
                <h3>实时匹配规则</h3>
                <span class="meta">
                  {{ ruleStats?.source || 'Agent 独立规则库' }}
                  · {{ (ruleStatsItems.length || ruleStats?.count || 0) }} 条
                  · 启用 {{ ruleStatsItems.filter(r => r.enabled !== false).length || ruleStats?.enabled || 0 }}
                </span>
              </div>
              <div class="chip-row">
                <button type="button" class="chip-btn" :class="{ on: settingsRulesFilter === 'all' }" @click="settingsRulesFilter = 'all'">全部</button>
                <button type="button" class="chip-btn" :class="{ on: settingsRulesFilter === 'sensor' }" @click="settingsRulesFilter = 'sensor'">内置传感器</button>
                <button type="button" class="chip-btn" :class="{ on: settingsRulesFilter === 'custom' }" @click="settingsRulesFilter = 'custom'">快照规则</button>
                <button type="button" class="chip-btn" @click="loadSettings(); loadRules()">刷新</button>
              </div>
            </div>
            <div v-if="ruleStats?.coverage?.states?.length" class="chip-row" style="padding:0 12px 10px;gap:6px;flex-wrap:wrap">
              <span class="meta" style="margin-right:4px">覆盖率</span>
              <span
                v-for="s in ruleStats.coverage.states"
                :key="s.key"
                class="chip"
                :title="s.label"
              >{{ s.label }} {{ s.count }}</span>
            </div>
            <div class="table-scroll settings-rules-table">
              <table>
                <thead>
                  <tr>
                    <th>启用</th>
                    <th>标题</th>
                    <th>来源</th>
                    <th>级别</th>
                    <th>类型 / 关键字</th>
                    <th>说明</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="r in filteredSettingsRules" :key="r.id">
                    <td>
                      <label class="switch">
                        <input type="checkbox" :checked="r.enabled !== false" @change="toggleRule(r, $event.target.checked)" />
                        <i />
                      </label>
                    </td>
                    <td>
                      <b class="strong">{{ r.title }}</b>
                      <div class="meta">{{ r.id }}</div>
                    </td>
                    <td>
                      <span class="pill" :class="{ on: r.builtin || r.source === 'sensor' }">
                        {{ (r.builtin || r.source === 'sensor') ? '内置传感器' : '快照规则' }}
                      </span>
                    </td>
                    <td><span class="sev" :data-s="r.severity">{{ sevLabel(r.severity) }}</span></td>
                    <td class="muted">
                      <template v-if="r.builtin || r.source === 'sensor'">
                        {{ r.etype || '—' }}
                        <span v-if="r.summary_contains"> · {{ r.summary_contains }}</span>
                      </template>
                      <template v-else>
                        {{ (r.modules || []).map(modLabel).join('、') || '—' }}
                        <span v-if="(r.patterns || []).length"> · {{ (r.patterns || []).length }} 特征</span>
                      </template>
                    </td>
                    <td class="muted" :title="r.note">{{ r.note || '—' }}</td>
                  </tr>
                </tbody>
              </table>
              <p v-if="!filteredSettingsRules.length" class="empty settings-rules-empty">暂无规则数据，请点右上角「刷新」或前往规则管理</p>
            </div>
          </div>
        </div>
      </section>

<section v-if="page === 'accounts'" class="page">
        <header class="page-hd">
          <div>
            <h1>账号管理</h1>
            <p class="desc">xedr 后台独立账号，与分析平台账号互不相通</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn primary" @click="openUserForm()">新建账号</button>
          </div>
        </header>
        <div class="panel record-panel">
          <div class="panel-hd"><h3>账号列表</h3><span class="record-count">{{ edrUsers.length }} 个账号</span></div>
          <div v-if="edrUsers.length" class="table-scroll record-table">
          <table class="acct-table">
            <thead>
              <tr><th>账号</th><th>角色</th><th>状态</th><th>最近登录</th><th>操作</th></tr>
            </thead>
            <tbody>
              <tr v-for="u in edrUsers" :key="u.id">
                <td>
                  <div class="acct-name">
                    <span class="ru-avatar sm">{{ (u.display_name || u.username || '?').slice(0, 1).toUpperCase() }}</span>
                    <div>
                      <strong>{{ u.display_name || u.username }}</strong>
                      <small>{{ u.username }}<i v-if="u.id === user?.id" class="acct-me">我</i></small>
                    </div>
                  </div>
                </td>
                <td>
                  <select class="field sm" :value="u.role" :disabled="u.id === user?.id" @change="changeUserRole(u, $event.target.value)">
                    <option v-for="(lb, k) in roleLabels" :key="k" :value="k">{{ lb }}</option>
                  </select>
                </td>
                <td>
                  <span class="pill" :class="{ on: u.enabled }">{{ u.enabled ? '启用' : '已禁用' }}</span>
                  <span v-if="u.must_change" class="pill warn">待改密</span>
                </td>
                <td class="muted">
                  {{ u.last_login_at ? fmtEpoch(u.last_login_at) : '从未登录' }}
                  <small v-if="u.last_login_ip" class="acct-ip">{{ u.last_login_ip }}</small>
                </td>
                <td class="ops">
                  <template v-if="u.id !== user?.id">
                    <button type="button" class="btn-text" @click="toggleUserEnabled(u)">{{ u.enabled ? '禁用' : '启用' }}</button>
                    <button type="button" class="btn-text" @click="openResetPw(u)">重置密码</button>
                    <button type="button" class="btn-text" style="color:var(--danger)" @click="removeUser(u)">删除</button>
                  </template>
                  <button v-else type="button" class="btn-text" @click="openPwDialog">修改密码</button>
                </td>
              </tr>
            </tbody>
          </table>
          </div>
          <div v-else class="record-empty"><span class="record-empty-mark" aria-hidden="true">—</span><strong>暂无账号</strong></div>
          <p class="hint record-footer">角色说明：管理员可处置终端、改规则与配置、管理账号；分析员与只读账号仅可查看。</p>
        </div>
      </section>

<section v-if="page === 'notify'" class="page">
        <header class="page-hd">
          <div>
            <h1>通知渠道</h1>
            <p class="desc">新威胁事件达到级别阈值时推送（同主机同标题 10 分钟内只推一次）</p>
          </div>
        </header>
        <div class="panel pad settings notify-settings">
          <div class="notify-form-heading"><h3>通知设置</h3><p class="hint">设置通知阈值和接收渠道。</p></div>
          <label class="chk"><input type="checkbox" v-model="notifyForm.enabled" /> 启用通知</label>
          <label>
            <span>最低级别</span>
            <select v-model="notifyForm.min_severity" class="field">
              <option value="medium">中及以上</option>
              <option value="high">高及以上</option>
              <option value="critical">仅严重</option>
            </select>
          </label>
          <label>
            <span>通用 Webhook（POST JSON）</span>
            <input v-model="notifyForm.webhook_url" class="field" placeholder="https://example.com/edr-hook" />
          </label>
          <label>
            <span>飞书机器人 Webhook</span>
            <input v-model="notifyForm.feishu_webhook" class="field" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." />
          </label>
          <label>
            <span>钉钉机器人 Webhook</span>
            <input v-model="notifyForm.dingtalk_webhook" class="field" placeholder="https://oapi.dingtalk.com/robot/send?access_token=..." />
          </label>
          <label>
            <span>钉钉加签密钥（可选）</span>
            <input v-model="notifyForm.dingtalk_secret" class="field" type="password" placeholder="SEC..." />
          </label>
          <div class="row">
            <button type="button" class="btn primary" :disabled="saving" @click="saveNotify">保存</button>
            <button type="button" class="btn" @click="doTestNotify">发送测试消息</button>
          </div>
          <div v-if="notifyTestResult" class="notify-results">
            <p v-if="notifyTestResult.error" class="err-text">{{ notifyTestResult.error }}</p>
            <p v-for="r in notifyTestResult.results || []" :key="r.channel" :class="r.ok ? 'hint' : 'err-text'">
              {{ ({ webhook: 'Webhook', feishu: '飞书', dingtalk: '钉钉' })[r.channel] || r.channel }}：
              {{ r.ok ? `成功（HTTP ${r.status}）` : `失败：${r.error}` }}
            </p>
          </div>
        </div>
      </section>

<section v-if="page === 'storage'" class="page">
        <header class="page-hd">
          <div>
            <h1>存储与保留</h1>
            <p class="desc">SQLite 存近期热数据；MySQL 双写保留 4 倍时长作历史检索层；保留期在「EDR 策略」中设置</p>
          </div>
          <button type="button" class="btn" @click="loadStorage">刷新</button>
        </header>
        <div class="host-summary" v-if="storeInfo">
          <div class="hs"><span>SQLite 时间线</span><b>{{ fmtNum(storeInfo.sqlite_timeline) }}</b></div>
          <div class="hs"><span>SQLite 事件</span><b>{{ fmtNum(storeInfo.sqlite_events) }}</b></div>
          <div class="hs on"><span>MySQL 时间线</span><b>{{ storeInfo.mysql?.available ? fmtNum(storeInfo.mysql.timeline) : '不可用' }}</b></div>
          <div class="hs on"><span>MySQL 事件</span><b>{{ storeInfo.mysql?.available ? fmtNum(storeInfo.mysql.events) : '不可用' }}</b></div>
        </div>
        <div class="panel pad" v-if="storeInfo">
          <p>
            时间线保留 <b>{{ storeInfo.retention?.timeline_days }}</b> 天 ·
            已关闭事件保留 <b>{{ storeInfo.retention?.events_days }}</b> 天 ·
            MySQL 双写 <b>{{ storeInfo.retention?.mysql_dual_write ? '开' : '关' }}</b>
          </p>
          <p class="hint">后台每小时自动清理一次；未关闭的威胁事件永不清理。</p>
          <button type="button" class="btn danger-outline" @click="doPurge">立即按保留期清理</button>
        </div>
        <div class="panel pad storage-results" style="margin-top:14px">
          <h3>历史时间线检索（MySQL）</h3>
          <div class="hunt-bar">
            <input v-model="storeQ" class="search grow" placeholder="关键字：进程名 / IP / 路径…" @keyup.enter="doStoreSearch" />
            <button type="button" class="btn primary" @click="doStoreSearch">检索</button>
          </div>
          <div v-if="storeHits.length" class="table-scroll record-table"><table>
            <thead><tr><th>时间</th><th>主机</th><th>类型</th><th>摘要</th></tr></thead>
            <tbody>
              <tr v-for="(h, i) in storeHits" :key="i">
                <td>{{ fmtTime(h.ts) }}</td>
                <td>{{ h.hostname || short(h.agent_id) }}</td>
                <td class="mono">{{ h.etype }}</td>
                <td>{{ h.summary }}</td>
              </tr>
            </tbody>
          </table></div>
          <div v-else class="record-empty"><span class="record-empty-mark" aria-hidden="true">—</span><strong>暂无检索结果</strong><p>输入关键词检索历史记录。</p></div>
        </div>
      </section>

<section v-if="page === 'policy'" class="page policy-page">
        <header class="page-hd">
          <div>
            <h1>EDR 策略</h1>
            <p class="desc">采集开关、周期保留、远程运维；告警加白降低误报 · rev {{ policyRev }}</p>
          </div>
          <button type="button" class="btn primary" :disabled="saving" @click="savePolicy">保存策略</button>
        </header>

        <div class="pol-body">
          <div class="pol-main">
            <div class="panel pol-card">
              <header class="pol-card-hd">
                <div>
                  <h3>全局策略</h3>
                  <p>修改后点「保存策略」下发；终端校验通过后生效</p>
                </div>
              </header>

              <section class="pol-sec">
                <h4>采集与防护</h4>
                <div class="pol-checks">
                  <label class="chk"><input type="checkbox" v-model="policyForm.response_enabled" /> 允许远程处置</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.self_protect" /> 自保护</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.timeline_process" /> 上报进程时间线</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.timeline_file" /> 上报文件时间线</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.timeline_network" /> 上报网络外联</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.fim_enabled" /> 文件完整性监控（FIM）</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.sysmon_managed" /> 托管安装 Sysmon</label>
                </div>
                <p class="pol-hint">远程处置：威胁页结束进程 / 隔离文件 / 网络隔离。自保护：忽略普通 net stop 并收紧状态目录。Sysmon：随 Agent 安装并订阅 Operational 通道（需平台 Sysmon/Sysmon64.exe）。</p>
              </section>

              <section class="pol-sec">
                <h4>路径与通道</h4>
                <div class="pol-fields">
                  <label v-if="policyForm.fim_enabled" class="span-2">
                    <span>FIM 自定义目录 <em>每行一个，末尾加 |r 表示递归</em></span>
                    <textarea v-model="policyForm.fim_paths_text" class="field mono" rows="3" placeholder="D:\app\bin&#10;D:\web\wwwroot|r" />
                  </label>
                  <label class="span-2">
                    <span>定向日志 tail <em>每行一个文件绝对路径，最多 20 条</em></span>
                    <textarea v-model="policyForm.log_tail_paths_text" class="field mono" rows="2" placeholder="C:\ProgramData\YourApp\app.log" />
                  </label>
                  <label>
                    <span>Winlog 通道模式</span>
                    <select v-model="policyForm.winevent_channel_mode" class="field">
                      <option value="all">全部通道</option>
                      <option value="critical">critical 默认集</option>
                      <option value="high_sens">高敏（critical + BITS/AppLocker/…）</option>
                      <option value="custom">自定义列表</option>
                    </select>
                  </label>
                  <label
                    v-if="policyForm.winevent_channel_mode === 'custom' || policyForm.winevent_channel_mode === 'critical' || policyForm.winevent_channel_mode === 'high_sens'"
                    class="span-2"
                  >
                    <span>Winlog 通道 ID <em>每行一个；critical/high_sens 下为追加</em></span>
                    <textarea v-model="policyForm.winevent_channels_text" class="field mono" rows="2" placeholder="firewall&#10;bits&#10;applocker" />
                  </label>
                </div>
              </section>

              <section class="pol-sec">
                <h4>周期与保留</h4>
                <div class="pol-num-grid">
                  <label>
                    <span>心跳间隔（秒）</span>
                    <input v-model.number="policyForm.heartbeat_sec" type="number" min="3" max="120" class="field" />
                  </label>
                  <label>
                    <span>进程采集（秒）</span>
                    <input v-model.number="policyForm.intervals_sec.process" type="number" min="3" max="300" class="field" />
                  </label>
                  <label>
                    <span>网络采集（秒）</span>
                    <input v-model.number="policyForm.intervals_sec.network" type="number" min="3" max="300" class="field" />
                  </label>
                  <label>
                    <span>文件采集（秒）</span>
                    <input v-model.number="policyForm.intervals_sec.file" type="number" min="5" max="600" class="field" />
                  </label>
                  <label>
                    <span>时间线保留（天）</span>
                    <input v-model.number="policyForm.timeline_retain_days" type="number" min="1" max="365" class="field" />
                  </label>
                  <label>
                    <span>已关闭事件保留（天）</span>
                    <input v-model.number="policyForm.events_retain_days" type="number" min="7" max="730" class="field" />
                  </label>
                </div>
              </section>

              <section class="pol-sec">
                <h4>存储与远程运维</h4>
                <div class="pol-checks">
                  <label class="chk"><input type="checkbox" v-model="policyForm.mysql_dual_write" /> MySQL 双写（历史检索层）</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.remote_ops_enabled" /> 开启远程运维</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.remote_ops_read_only" :disabled="!policyForm.remote_ops_enabled" /> 远程运维只读</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.remote_ops_run_cmd" :disabled="!policyForm.remote_ops_enabled || policyForm.remote_ops_read_only" /> 允许白名单 run_cmd</label>
                  <label class="chk"><input type="checkbox" v-model="policyForm.remote_ops_shell" :disabled="!policyForm.remote_ops_enabled" /> 允许交互 Shell</label>
                </div>
              </section>
            </div>

            <div class="panel pol-card pol-wl">
              <header class="pol-card-hd">
                <div>
                  <h3>告警加白</h3>
                  <p>命中后不再产生告警；值支持 * 通配，路径/注册表以 \ 结尾表示整目录。也可在威胁事件中直接加白。</p>
                </div>
                <span class="pol-count">{{ whitelist.length }} 条</span>
              </header>
              <div class="pol-wl-add">
                <select v-model="wlKind" class="field">
                  <option v-for="(lb, k) in ALLOW_KIND_LABELS" :key="k" :value="k">{{ lb }}</option>
                </select>
                <input v-model="wlValue" class="field mono grow" placeholder="匹配值，如 C:\Tools\*.exe" />
                <input v-model="wlRule" class="field" placeholder="限定告警标题（可选）" />
                <input v-model="wlNote" class="field" placeholder="备注" />
                <button type="button" class="btn primary" @click="addWl">添加</button>
              </div>
              <div v-if="whitelist.length" class="pol-table-wrap">
                <table class="pol-table">
                  <thead>
                    <tr>
                      <th>类型</th>
                      <th>值</th>
                      <th>限定告警</th>
                      <th>范围</th>
                      <th>命中</th>
                      <th>最近命中</th>
                      <th>备注</th>
                      <th>状态</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="w in whitelist" :key="w.id" :class="{ 'wl-off': !w.enabled }">
                      <td><span class="pol-kind">{{ ALLOW_KIND_LABELS[w.kind] || w.kind }}</span></td>
                      <td class="mono wl-val" :title="w.value">{{ w.value }}</td>
                      <td class="wl-val" :title="w.rule">{{ w.rule || '全部' }}</td>
                      <td>{{ w.agent_id ? agentLabel(w.agent_id) : '全部终端' }}</td>
                      <td class="num">{{ w.hits || 0 }}</td>
                      <td class="muted">{{ w.last_hit_at ? fmtTime(w.last_hit_at) : '—' }}</td>
                      <td class="wl-val" :title="w.note">{{ w.note || '—' }}</td>
                      <td>
                        <button type="button" class="btn-text" :class="{ on: w.enabled }" @click="toggleWl(w)">
                          {{ w.enabled ? '启用中' : '已停用' }}
                        </button>
                      </td>
                      <td><button type="button" class="btn-text danger" @click="delWl(w.id)">删除</button></td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p v-else class="empty sm">暂无加白条目</p>
            </div>
          </div>

          <aside class="pol-side">
            <div class="panel pol-card">
              <header class="pol-card-hd">
                <div>
                  <h3>终端生效</h3>
                  <p>rev {{ policyRollout?.rev ?? policyRev }} · 当前 Agent 最短试用 20 秒且至少 3 次成功心跳后记为 LKG</p>
                </div>
              </header>
              <div v-if="policyRollout" class="pol-chips">
                <span class="pol-chip ok">已生效 <b>{{ policyRollout.summary.applied }}</b></span>
                <span class="pol-chip">试用中 <b>{{ policyRollout.summary.probation }}</b></span>
                <span class="pol-chip">待生效 <b>{{ policyRollout.summary.pending }}</b></span>
                <span class="pol-chip" :class="{ warn: policyRollout.summary.rejected }">已拒绝 <b>{{ policyRollout.summary.rejected }}</b></span>
                <span class="pol-chip" :class="{ warn: policyRollout.summary.rolled_back }">已回滚 <b>{{ policyRollout.summary.rolled_back }}</b></span>
                <span class="pol-chip">旧版 <b>{{ policyRollout.summary.legacy }}</b></span>
              </div>
              <div v-if="policyRollout?.problems?.length" class="pol-table-wrap tight">
                <table class="pol-table sm">
                  <thead><tr><th>主机</th><th>状态</th><th>生效</th></tr></thead>
                  <tbody>
                    <tr v-for="p in policyRollout.problems" :key="p.agent_id">
                      <td :title="p.error || ''">{{ p.hostname || short(p.agent_id) }}</td>
                      <td>{{ POLICY_STATUS_LABELS[p.status] || p.status }}</td>
                      <td class="muted">rev {{ p.applied_rev || '默认' }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p v-else class="pol-hint">当前无拒绝/回滚问题终端</p>
            </div>

            <div class="panel pol-card pol-hist">
              <header class="pol-card-hd">
                <div>
                  <h3>版本历史</h3>
                  <p>可回滚到任一历史版本</p>
                </div>
              </header>
              <ul v-if="policyHistory.length" class="pol-hist-list">
                <li v-for="h in policyHistory" :key="h.rev" :class="{ cur: h.rev === policyRev }">
                  <div class="pol-hist-top">
                    <b class="mono">rev {{ h.rev }}</b>
                    <em v-if="h.rev === policyRev" class="pill on">当前</em>
                    <button
                      v-if="isAdmin && h.rev !== policyRev"
                      type="button"
                      class="btn-text"
                      @click="doPolicyRollback(h.rev)"
                    >回滚</button>
                  </div>
                  <p>{{ h.note || '—' }}</p>
                  <small>{{ fmtTime(h.created_at) }} · {{ h.actor || '—' }}</small>
                </li>
              </ul>
              <p v-else class="empty sm">暂无历史版本</p>
            </div>
          </aside>
        </div>
      </section>
</template>

<script>
import { forwardSetupContext } from './setupContext.js'
export default { props: { context: { type: Object, required: true } }, setup(props) { return forwardSetupContext(props.context) } }
</script>
