<template>
<section v-if="page === 'overview'" class="page overview">
        <header class="page-hd">
          <div>
            <span class="overview-eyebrow">安全运营 · SECURITY OVERVIEW</span>
            <h1>数据概览</h1>
            <p class="desc">威胁优先 · 终端态势 · 一键下钻</p>
          </div>
          <div class="hd-right">
            <span class="live-hint" :class="{ on: liveOk }">
              <i class="live-dot" />
              {{ liveOk ? `已连接 · ${liveAgo}` : '连接中…' }}
            </span>
            <button type="button" class="btn ghost-btn" :disabled="loading" @click="refresh">立即同步</button>
          </div>
        </header>

        <div class="overview-section-label"><strong>终端与遥测态势</strong><span>资产接入及运行情况</span></div>
        <OverviewFleetStrip
          :ov-agent-total="ovAgentTotal"
          :online-count="onlineCount"
          :overview-stats="overviewStats"
          :overview-spark-tl="overviewSparkTl"
          :overview-spark-dns="overviewSparkDns"
          :ov-fleet-collapsed="ovFleetCollapsed"
          @navigate="goPage"
          @network="openOverviewNetworkView"
          @toggle="ovFleetCollapsed = !ovFleetCollapsed"
        />

        <div class="overview-section-label"><strong>威胁态势</strong><span>告警与检测统计</span></div>
        <OverviewThreatCards :overview-stats="overviewStats" :online-count="onlineCount" @navigate="goPage" @events="goEventsWith" />

        <div class="ov-body">
          <div class="panel ov-threats">
            <div class="panel-hd">
              <div>
                <h3>最近威胁</h3>
                <span class="meta">点击进入威胁视图处置</span>
              </div>
              <div class="hd-right">
                <button type="button" class="btn-text" @click="goMenu('behaviors')">检出行为</button>
                <button type="button" class="btn-text" @click="goPage('events')">全部 →</button>
              </div>
            </div>
            <div v-if="recentThreats.length" class="table-scroll ov-threat-scroll">
              <table class="evt-table">
                <thead>
                  <tr>
                    <th>级别</th>
                    <th>事件</th>
                    <th>主机</th>
                    <th>模块</th>
                    <th>时间</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="e in recentThreats"
                    :key="e.id"
                    class="row-click"
                    @click="openEvent(e)"
                  >
                    <td><span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span></td>
                    <td class="strong">{{ e.title }}</td>
                    <td>{{ e.hostname || short(e.agent_id) }}</td>
                    <td class="muted">{{ modLabel(e.module) || '—' }}</td>
                    <td class="mono">{{ fmtTime(e.updated_at || e.created_at) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-else-if="recentRiskTimeline.length" class="table-scroll ov-threat-scroll">
              <p class="hint" style="margin:8px 14px">暂无正式威胁事件，以下为近期中高危时间线</p>
              <table class="evt-table">
                <thead>
                  <tr><th>级别</th><th>摘要</th><th>主机</th><th>类型</th><th>时间</th></tr>
                </thead>
                <tbody>
                  <tr
                    v-for="t in recentRiskTimeline"
                    :key="t.id || (t.ts + t.summary)"
                    class="row-click"
                    @click="openTimelineFor(t.agent_id)"
                  >
                    <td><span class="sev" :data-s="t.severity">{{ sevLabel(t.severity) }}</span></td>
                    <td class="strong">{{ cleanSummary(t.summary) }}</td>
                    <td>{{ t.hostname || short(t.agent_id) }}</td>
                    <td class="muted">{{ etypeLabel(t.etype) }}</td>
                    <td class="mono">{{ fmtTime(t.ts) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-else class="empty sm ov-empty">
              <p>暂无威胁事件</p>
              <p v-if="!agents.length" class="hint sm">尚未接入终端，可前往 <button type="button" class="btn-text" @click="goMenu('deploy')">部署安装</button> 纳管第一台主机。</p>
              <button type="button" class="btn sm" @click="goMenu('timeline')">查看时间线</button>
            </div>
          </div>

          <aside class="panel ov-side">
            <div class="panel-hd">
              <h3>终端</h3>
              <button type="button" class="btn-text" @click="goPage('hosts')">管理 →</button>
            </div>
            <div class="ov-host-summary">
              <div><b>{{ onlineCount }}</b><span>在线</span></div>
              <div><b>{{ agents.length - onlineCount }}</b><span>离线</span></div>
              <div><b>{{ agents.reduce((n, a) => n + (alertCount(a.agent_id) || 0), 0) }}</b><span>告警</span></div>
            </div>
            <div class="ov-host-list">
              <button
                v-for="a in agents"
                :key="a.agent_id"
                type="button"
                class="ov-host-row"
                @click="openHost(a, 'hosts')"
              >
                <i :class="['dot', a.online ? 'on' : '']" />
                <div class="ov-host-main">
                  <b>{{ a.hostname || short(a.agent_id) }}</b>
                  <small>{{ a.ip || '—' }} · v{{ a.version || '—' }} · {{ a.online ? '在线' : '离线' }}</small>
                </div>
                <span v-if="alertCount(a.agent_id)" class="alert-n badge">{{ alertCount(a.agent_id) }}</span>
                <span v-else class="ov-host-ok">正常</span>
              </button>
              <p v-if="!agents.length" class="empty sm">暂无终端</p>
            </div>
            <div class="ov-side-links">
              <button type="button" class="btn sm" @click="goMenu('deploy')">部署安装</button>
              <button type="button" class="btn sm" @click="goMenu('hunt')">威胁狩猎</button>
              <button type="button" class="btn sm" @click="goMenu('policy')">EDR 策略</button>
              <button type="button" class="btn sm" @click="goMenu('attck')">ATT&CK</button>
            </div>
          </aside>
        </div>

        <div class="overview-section-label overview-breakdown-label"><strong>趋势与分布</strong><span>按类型、等级及终端汇总</span></div>
        <div class="ov-bottom-grid">
          <div class="panel ov-panel">
            <div class="panel-hd"><h3>威胁分类</h3><button type="button" class="btn-text" @click="goPage('events')">威胁事件 →</button></div>
            <div class="ov-cats ov-cats-compact">
              <button v-for="c in focusCats" :key="c.key" type="button" class="ov-cat" @click="goEventsWith({ focus: c.key })">
                <span class="focus-ico" :style="{ background: c.color }">{{ c.short }}</span>
                <b>{{ c.label }}</b>
                <em>{{ c.count }}</em>
              </button>
            </div>
          </div>

          <div class="panel ov-panel">
            <div class="panel-hd"><h3>告警级别</h3><span class="meta">未处置 {{ ovStatus.open }} · 已处置 {{ ovStatus.closed }}</span></div>
            <div class="ov-bars">
              <div v-for="s in ovSevDist" :key="s.key" class="ov-bar-row">
                <span class="sev" :data-s="s.key">{{ s.label }}</span>
                <div class="ov-bar"><i :style="{ width: s.pct + '%' }" :data-s="s.key" /></div>
                <b>{{ s.count }}</b>
              </div>
            </div>
          </div>

          <div class="panel ov-panel">
            <div class="panel-hd"><h3>近 7 天告警趋势</h3><span class="meta">共 {{ ovTrend.total }} 条</span></div>
            <div class="ov-trend">
              <div v-for="d in ovTrend.days" :key="d.day" class="ov-trend-col" :title="`${d.day}：${d.count} 条（高危 ${d.high}）`">
                <em>{{ d.count || '' }}</em>
                <div class="ov-trend-bar"><i :style="{ height: d.pct + '%' }" /><i class="hi" :style="{ height: d.hpct + '%' }" /></div>
                <small>{{ d.label }}</small>
              </div>
            </div>
          </div>

          <div class="panel ov-panel">
            <div class="panel-hd">
              <h3>{{ overviewTopMalware.length ? 'TOP5 恶意文件' : '风险终端 Top 5' }}</h3>
              <button type="button" class="btn-text" @click="overviewTopMalware.length ? goPage('malware') : goPage('hosts')">{{ overviewTopMalware.length ? '全部 →' : '终端列表 →' }}</button>
            </div>
            <ul v-if="overviewTopMalware.length" class="ov-mal-list compact">
              <li v-for="(m, i) in overviewTopMalware" :key="i">
                <i>{{ i + 1 }}</i><span class="mono" :title="m.title">{{ m.title }}</span><em>{{ m.count }}</em>
              </li>
            </ul>
            <div v-else class="ov-rank">
              <button v-for="(h, i) in ovTopHosts" :key="h.agent_id" type="button" class="ov-rank-row" @click="goEventsWith({ agent: h.agent_id })">
                <i>{{ i + 1 }}</i>
                <b>{{ h.hostname }}</b>
                <span v-if="h.high" class="sev" data-s="high">高危 {{ h.high }}</span>
                <em>{{ h.count }} 条</em>
              </button>
              <p v-if="!ovTopHosts.length" class="empty sm">暂无数据</p>
            </div>
          </div>
        </div>
      </section>

<section v-if="page === 'timeline'" class="page timeline-page">
        <header class="page-hd">
          <div>
            <h1>主机时间线</h1>
            <p class="desc">进程创建 / 退出、文件落地等近实时事件 · 共 {{ filteredTimeline.length }} 条</p>
          </div>
          <div class="hd-right">
            <select v-model="tlAgentId" class="search" @change="loadTimeline">
              <option value="">全部终端</option>
              <option v-for="a in agents" :key="a.agent_id" :value="a.agent_id">{{ a.hostname || short(a.agent_id) }}</option>
            </select>
            <input v-model="tlQ" class="search" placeholder="搜索摘要 / 路径 / PID…" @keyup.enter="loadTimeline" />
            <button type="button" class="btn" :disabled="logRuleDiagBusy" @click="runTimelineLogRuleDiagnose">命中诊断</button>
            <button type="button" class="btn primary" @click="loadTimeline">查询</button>
          </div>
        </header>

        <div v-if="tlLogRuleDiag?.ok" class="tl-diag panel pad">
          <div class="tl-diag-hd">
            <b>日志规则命中诊断</b>
            <button type="button" class="btn-text" @click="tlLogRuleDiag = null">关闭</button>
          </div>
          <div class="lr-diag-kpis compact">
            <div><em>样本</em><b>{{ tlLogRuleDiag.sample_size || 0 }}</b></div>
            <div><em>EventID</em><b>{{ tlLogRuleDiag.with_event_id || 0 }}</b></div>
            <div><em>命中</em><b>{{ tlLogRuleDiag.match_hits || 0 }}</b></div>
            <div><em>可晋升</em><b>{{ tlLogRuleDiag.promoteable || 0 }}</b></div>
            <div><em>级别低</em><b>{{ tlLogRuleDiag.low_only || 0 }}</b></div>
            <div><em>加白</em><b>{{ tlLogRuleDiag.suppressed || 0 }}</b></div>
          </div>
          <ul class="lr-diag-reasons">
            <li v-for="(r, i) in (tlLogRuleDiag.reasons || [])" :key="i" :data-l="r.level">{{ r.text }}</li>
          </ul>
          <button type="button" class="btn-text" @click="goMenu('rules'); rulesSection = 'logrules'; logRuleDiagAgent = tlAgentId; runLogRuleDiagnose()">到规则页看完整诊断 →</button>
        </div>

        <div class="tl-filters">
          <button
            type="button"
            class="tl-fchip"
            :class="{ on: !tlTypeFilter }"
            @click="tlTypeFilter = ''"
          >全部 <em>{{ timelineTotal }}</em></button>
          <button
            v-for="f in tlTypeOptions"
            :key="f.key"
            type="button"
            class="tl-fchip"
            :class="{ on: tlTypeFilter === f.key }"
            :data-k="f.key"
            @click="tlTypeFilter = tlTypeFilter === f.key ? '' : f.key"
          >{{ f.label }} <em>{{ f.count }}</em></button>
          <button
            type="button"
            class="tl-fchip"
            :class="{ on: tlSourceFilter === 'sysmon' }"
            @click="tlSourceFilter = tlSourceFilter === 'sysmon' ? '' : 'sysmon'; loadTimeline()"
          >Sysmon</button>
          <label class="tl-eid-filter">
            <span>EventID</span>
            <input
              v-model="tlEventIdFilter"
              class="field mono"
              placeholder="如 10"
              @keyup.enter="loadTimeline"
              @change="loadTimeline"
            />
          </label>
        </div>
        <p class="tl-hint">已过滤 Agent 自身采集命令及同一进程的重复记录；可按 Sysmon 来源或 EventID 筛；分类计数为全部数据，列表显示最近 300 条。点卡片「详情」查看完整字段。</p>

        <div class="tl-board" v-if="filteredTimeline.length">
          <div class="tl-rail">
            <article
              v-for="t in pagedTimeline"
              :key="t.id"
              class="tl-card"
              :data-s="t.severity"
              :data-k="etypeKind(t.etype)"
              :class="{ open: tlOpenId === t.id }"
            >
              <div class="tl-axis">
                <i class="tl-dot" />
                <span class="tl-line" />
              </div>
              <div class="tl-main" @click="tlOpenId = tlOpenId === t.id ? null : t.id">
                <header class="tl-card-hd">
                  <time>{{ fmtTime(t.ts || t.created_at) }}</time>
                  <span class="tl-etype" :data-k="etypeKind(t.etype)">{{ etypeLabel(t.etype) }}</span>
                  <span class="sev" :data-s="t.severity">{{ sevLabel(t.severity) }}</span>
                  <span class="tl-host">{{ t.hostname || short(t.agent_id) }}</span>
                  <button type="button" class="tl-expand" :aria-expanded="tlOpenId === t.id">
                    {{ tlOpenId === t.id ? '收起' : '详情' }}
                  </button>
                </header>
                <h3 class="tl-title">{{ t.summary }}</h3>
                <div class="tl-preview" v-if="detailPreview(t).length">
                  <span v-for="p in detailPreview(t)" :key="p.k" class="tl-chip">
                    <em>{{ p.k }}</em>{{ p.v }}
                  </span>
                </div>
                <div class="tl-fields" v-if="tlOpenId === t.id" @click.stop>
                  <template v-if="detailGroupsTl(t).length">
                    <section v-for="g in detailGroupsTl(t)" :key="g.title" class="tl-g">
                      <h5>{{ g.title }}<em>{{ g.items.length }}</em></h5>
                      <div class="tl-g-grid">
                        <div v-for="row in g.items" :key="row.key || row.k" class="tl-field" :class="{ wide: row.wide }">
                          <label>{{ row.k }}</label>
                          <div class="tl-fv">
                            <span :title="row.v" :class="{ mono: row.mono }">{{ row.v }}</span>
                            <button v-if="row.wide || row.mono" type="button" class="ev-copy" @click="copyText(row.v)">复制</button>
                          </div>
                        </div>
                      </div>
                    </section>
                  </template>
                  <p v-else class="tl-empty">该事件未携带明细字段（来源 {{ etypeLabel(t.etype) }}）</p>
                  <details v-if="parseTlDetail(t)" class="tl-raw">
                    <summary>原始明细 JSON</summary>
                    <pre>{{ JSON.stringify(parseTlDetail(t), null, 2) }}</pre>
                  </details>
                  <div class="tl-acts">
                    <button type="button" class="btn sm" @click="openTimelineHost(t)">打开主机快照</button>
                    <button v-if="tlPid(t)" type="button" class="btn sm" @click="openTimelineHostPid(t)">定位进程 PID {{ tlPid(t) }}</button>
                    <button v-if="t.agent_id" type="button" class="btn sm" @click="openTimelineThreats(t)">相关威胁</button>
                  </div>
                </div>
              </div>
            </article>
          </div>
          <div class="list-pager tl-pager">
            <span class="pg-info">第 {{ tlPage }} / {{ tlPageCount }} 页 · 共 {{ filteredTimeline.length }} 条</span>
            <div class="pg-acts">
              <select v-model.number="tlPageSize" class="pg-size" @change="tlPage = 1">
                <option :value="10">10 条/页</option>
                <option :value="20">20 条/页</option>
                <option :value="50">50 条/页</option>
              </select>
              <button type="button" class="btn sm" :disabled="tlPage <= 1" @click="tlPage--">上一页</button>
              <button type="button" class="btn sm" :disabled="tlPage >= tlPageCount" @click="tlPage++">下一页</button>
            </div>
          </div>
        </div>
        <div v-else class="panel record-panel">
          <div class="panel-hd"><h3>时间线事件</h3><span class="record-count">0 条记录</span></div>
          <div class="record-empty"><span class="record-empty-mark" aria-hidden="true">—</span><strong>暂无时间线事件</strong><p>请确认终端已安装 Agent 且在线上报。</p></div>
        </div>
      </section>

<section v-if="page === 'investigate'" class="page inv-page">
        <header class="inv-top">
          <div class="inv-tabs">
            <button type="button" class="inv-tab brand">日志调查</button>
            <button type="button" class="inv-tab on">新建查询</button>
          </div>
          <div class="inv-top-acts">
            <button type="button" class="btn sm" @click="saveInvQuery" :disabled="!invQ && !invFilters.hostname">保存</button>
            <button type="button" class="btn sm" @click="invShowSaved = !invShowSaved">已保存查询列表</button>
            <button type="button" class="btn sm" @click="invShowHist = !invShowHist">历史查询列表</button>
            <span class="inv-range-lab">时间范围：</span>
            <select v-model="invRange" class="search" @change="runInvestigate">
              <option value="1h">近 1 小时</option>
              <option value="today">今天</option>
              <option value="7d">近 7 天</option>
              <option value="30d">近 30 天</option>
              <option value="all">全部</option>
            </select>
            <span class="muted">刷新频率：关闭</span>
          </div>
        </header>

        <div v-if="invShowSaved || invShowHist" class="inv-saved panel pad">
          <template v-if="invShowSaved">
            <h4>已保存查询</h4>
            <button v-for="(s, i) in invSaved" :key="'s'+i" type="button" class="inv-saved-row" @click="applyInvSaved(s)">
              <b>{{ s.name }}</b><small>{{ s.q || '（仅筛选）' }}</small>
            </button>
            <p v-if="!invSaved.length" class="empty sm">暂无保存</p>
          </template>
          <template v-if="invShowHist">
            <h4>历史查询</h4>
            <button v-for="(s, i) in invHistory" :key="'h'+i" type="button" class="inv-saved-row" @click="applyInvSaved(s)">
              <b>{{ s.at }}</b><small>{{ s.q || s.hostname || '全部' }}</small>
            </button>
            <p v-if="!invHistory.length" class="empty sm">暂无历史</p>
          </template>
        </div>

        <div class="inv-filters panel">
          <div class="inv-fg inv-fg-2">
            <label>事件性质
              <select v-model="invFilters.nature">
                <option value="">全部</option>
                <option value="threat">威胁行为</option>
                <option value="risk">风险行为</option>
                <option value="minor">细微行为</option>
                <option value="surface">攻击面</option>
              </select>
            </label>
            <label>动作类型
              <select v-model="invFilters.etype">
                <option value="">全部</option>
                <option v-for="e in (invFacets.etype || [])" :key="e.id" :value="e.id">{{ etypeLabel(e.id) }} ({{ e.count }})</option>
              </select>
            </label>
            <label>终端名称
              <select v-model="invFilters.hostname">
                <option value="">全部</option>
                <option v-for="h in (invFacets.hostname || [])" :key="h.id" :value="h.id">{{ h.id }} ({{ h.count }})</option>
              </select>
            </label>
            <label>操作系统类型
              <select v-model="invFilters.os">
                <option value="">全部</option>
                <option v-for="os in bhOsOptions" :key="'inv-'+os" :value="os">{{ os }}</option>
              </select>
            </label>
          </div>
          <div v-show="invMoreFilters" class="inv-fg inv-fg-2 inv-more-panel">
            <label>目标实体
              <input v-model="invFilters.entity" class="field" placeholder="全部" />
            </label>
            <label>进程 / 文件路径
              <input v-model="invFilters.path" class="field" placeholder="全部" />
            </label>
            <label>SHA256 / MD5
              <input v-model="invFilters.hash_q" class="field" placeholder="全部" />
            </label>
            <label>威胁阶段
              <select v-model="invFilters.tactic">
                <option value="">全部</option>
                <option v-for="(lab, key) in TACTIC_CN" :key="key" :value="key">{{ lab }}</option>
              </select>
            </label>
            <label>采集来源
              <select v-model="invFilters.source">
                <option value="">全部</option>
                <option value="sysmon">Sysmon</option>
                <option value="etw">ETW</option>
                <option value="security">Security</option>
                <option value="powershell">PowerShell</option>
              </select>
            </label>
            <label>EventID
              <input v-model="invFilters.event_id" class="field mono" placeholder="如 10 / 22" />
            </label>
          </div>
          <div class="inv-search-row">
            <input
              v-model="invQ"
              class="search grow"
              placeholder="请输入终端名 / 命令行路径 / SHA256 / IP / 域名等常见字段检索"
              @keyup.enter="runInvestigate"
            />
            <button type="button" class="btn" :class="{ on: invMoreFilters }" @click="invMoreFilters = !invMoreFilters">{{ invMoreFilters ? '− 收起筛选' : '+ 更多筛选条件' }}</button>
            <label class="inv-check inv-hide-noise">
              <input v-model="invHideProcNoise" type="checkbox" @change="runInvestigate" />
              <em>隐藏普通进程创建</em>
            </label>
            <button
              type="button"
              class="chip"
              :class="{ on: invFilters.source === 'sysmon' }"
              @click="invFilters.source = invFilters.source === 'sysmon' ? '' : 'sysmon'; invMoreFilters = true; runInvestigate()"
            >Sysmon</button>
            <button type="button" class="btn primary" :disabled="invBusy" @click="runInvestigate">{{ invBusy ? '查询中…' : '查询' }}</button>
            <button type="button" class="btn" @click="resetInvestigate">重置</button>
          </div>
        </div>

        <div class="inv-chart panel">
          <div class="inv-chart-hd">
            <span>行为趋势</span>
            <div class="inv-legend">
              <i data-n="threat" />威胁行为
              <i data-n="risk" />风险行为
              <i data-n="minor" />终端行为
            </div>
          </div>
          <div class="inv-bars" v-if="invHist.length">
            <div v-for="b in invHist" :key="b.ts" class="inv-bar-col" :title="`${b.ts} · 共 ${b.total}`">
              <div class="inv-bar-stack">
                <span class="seg threat" :style="{ height: histSegH(b, 'threat') }" />
                <span class="seg risk" :style="{ height: histSegH(b, 'risk') }" />
                <span class="seg minor" :style="{ height: histSegH(b, 'minor') }" />
              </div>
              <em>{{ histTick(b.ts) }}</em>
            </div>
          </div>
          <p v-else class="empty sm inv-chart-empty">查询后显示时间分布</p>
        </div>

        <div class="inv-body panel">
          <div class="inv-cats">
            <button type="button" :class="{ on: !invNatureTab }" @click="setInvNature('')">全部 <em>{{ invCounts.all || 0 }}</em></button>
            <button type="button" :class="{ on: invNatureTab === 'threat' }" @click="setInvNature('threat')">威胁 <em>{{ invCounts.threat || 0 }}</em></button>
            <button type="button" :class="{ on: invNatureTab === 'risk' }" @click="setInvNature('risk')">风险 <em>{{ invCounts.risk || 0 }}</em></button>
            <button type="button" :class="{ on: invNatureTab === 'surface' }" @click="setInvNature('surface')">攻击面收敛 <em>{{ invCounts.surface || 0 }}</em></button>
            <button type="button" :class="{ on: invNatureTab === 'minor' }" @click="setInvNature('minor')">细微 <em>{{ invCounts.minor || 0 }}</em></button>
          </div>
          <div class="inv-topics">
            <span class="inv-topics-lab">关注</span>
            <button
              v-for="t in INV_TOPIC_CHIPS"
              :key="t.id"
              type="button"
              class="chip"
              :class="{ on: invFilters.topic === t.id }"
              @click="setInvTopic(t.id)"
            >{{ t.label }}</button>
          </div>

          <div class="inv-layout" :class="{ open: !!invDetail }">
            <div class="inv-list">
              <p v-if="invBusy" class="hint sm inv-busy-hint">{{ invItems.length ? '刷新中…' : '加载中…' }}</p>
              <template v-if="invItems.length">
                <div class="inv-list-scroll" :class="{ dim: invBusy }">
                  <table>
                    <thead>
                      <tr>
                        <th>时间</th>
                        <th>性质</th>
                        <th>类型</th>
                        <th>摘要</th>
                        <th>主机</th>
                        <th>进程</th>
                        <th>路径 / 命令</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr
                        v-for="it in pagedInvItems"
                        :key="it.id"
                        class="row-click"
                        :class="{ active: invDetailId === it.id }"
                        @click="openInvDetail(it.id)"
                      >
                        <td class="mono">{{ fmtTime(it.ts) }}</td>
                        <td><span class="nat" :data-n="it.nature">{{ natureLabel(it.nature) }}</span></td>
                        <td class="inv-etype-td">
                          <span class="inv-etype">{{ etypeLabel(it.etype) }}</span>
                          <em
                            v-for="tp in (it.topics || [])"
                            :key="tp"
                            class="src-chip topic"
                            :data-t="tp"
                          >{{ invTopicLabel(tp) }}</em>
                          <em v-if="invRowIsSysmon(it)" class="src-chip sysmon" title="来源含 Sysmon">Sysmon</em>
                          <em
                            v-if="it.source_etype && it.source_etype !== it.etype"
                            class="src-chip muted"
                            :title="it.source_etype"
                          >{{ etypeLabel(it.source_etype) }}</em>
                          <em v-if="it.event_id != null && it.event_id !== ''" class="src-eid" title="EventID">E{{ it.event_id }}</em>
                        </td>
                        <td class="strong" :title="cleanSummary(it.summary)">{{ cleanSummary(it.summary) }}</td>
                        <td>{{ it.hostname || short(it.agent_id) }}</td>
                        <td>{{ it.name || '—' }} <em v-if="it.pid" class="muted">#{{ it.pid }}</em></td>
                        <td class="muted mono" :title="it.command_line || it.path">{{ (it.command_line || it.path || '—').slice(0, 64) }}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <div class="list-pager">
                  <span class="pg-info">第 {{ invPage }} / {{ invPageCount }} 页 · 共 {{ invItems.length }} 条</span>
                  <div class="pg-acts">
                    <select v-model.number="invPageSize" class="pg-size" @change="invPage = 1">
                      <option :value="10">10 条/页</option>
                      <option :value="20">20 条/页</option>
                      <option :value="50">50 条/页</option>
                    </select>
                    <button type="button" class="btn sm" :disabled="invPage <= 1" @click="invPage--">上一页</button>
                    <button type="button" class="btn sm" :disabled="invPage >= invPageCount" @click="invPage++">下一页</button>
                  </div>
                </div>
              </template>
              <p v-else-if="!invBusy" class="empty ov-empty">暂无日志。确认 Agent 在线上报时间线后会自动加载；也可点「查询」。</p>
              <p v-else class="empty ov-empty">正在拉取时间线…</p>
            </div>

            <aside v-if="invDetail" class="inv-detail">
              <div class="inv-dh">
                <div>
                  <b>{{ cleanSummary(invDetail.item?.summary) || '日志详情' }}</b>
                  <small>{{ fmtTime(invDetail.item?.ts) }} · {{ invDetail.item?.hostname || short(invDetail.item?.agent_id) }}</small>
                </div>
                <button type="button" class="icon-x" @click="closeInvDetail">×</button>
              </div>
              <div class="inv-dtabs">
                <button type="button" :class="{ on: invDetailTab === 'info' }" @click="invDetailTab = 'info'">详细信息</button>
                <button type="button" :class="{ on: invDetailTab === 'chain' }" @click="invDetailTab = 'chain'">进程链</button>
                <button v-if="invEntityId" type="button" :class="{ on: invDetailTab === 'entity' }" @click="openEntityTab">进程实体</button>
                <button type="button" :class="{ on: invDetailTab === 'raw' }" @click="invDetailTab = 'raw'">原始日志</button>
              </div>

              <div v-if="invDetailTab === 'entity'" class="inv-dbody">
                <p v-if="entityBusy" class="muted">加载中…</p>
                <p v-else-if="entityErr" class="empty sm">{{ entityErr }}</p>
                <template v-else-if="entityView">
                  <section class="inv-g">
                    <h5>
                      {{ entityView.entity?.name || '进程' }}
                      <em class="pill" :class="{ on: entityView.entity && !entityView.entity.exit_time }" style="margin-left:6px">
                        {{ entityView.entity?.exit_time ? '已退出（墓碑）' : '运行中/未见退出' }}
                      </em>
                    </h5>
                    <div class="inv-kv">
                      <div v-for="f in entityFieldsOf(entityView.entity)" :key="f.k" class="inv-kv-row" :class="{ wide: String(f.v).length > 48 }">
                        <span>{{ f.k }}</span><strong class="mono">{{ f.v }}</strong>
                      </div>
                    </div>
                  </section>
                  <section class="inv-g">
                    <h5>祖先链</h5>
                    <div class="inv-chain">
                      <div v-for="a in [...(entityView.ancestors || [])].reverse()" :key="a.entity_id" class="inv-cnode" :class="{ miss: a.missing }">
                        <i class="dot" />
                        <div>
                          <b class="ent-link" @click="loadEntity(a.entity_id)">{{ a.missing ? '（未记录的祖先）' : (a.name || ('PID ' + a.pid)) }}</b>
                          <span v-if="!a.missing">PID {{ a.pid }} · {{ fmtTime(a.create_time) }}</span>
                          <small v-if="a.command_line" class="mono">{{ a.command_line }}</small>
                        </div>
                      </div>
                      <div class="inv-cnode on">
                        <i class="dot" />
                        <div><b>{{ entityView.entity?.name || '当前进程' }}</b><span>PID {{ entityView.entity?.pid }}</span></div>
                      </div>
                      <div v-for="c in (entityView.children || [])" :key="c.entity_id" class="inv-cnode child">
                        <i class="dot" />
                        <div>
                          <b class="ent-link" @click="loadEntity(c.entity_id)">{{ c.name || ('PID ' + c.pid) }}</b>
                          <span>PID {{ c.pid }} · {{ fmtTime(c.create_time) }}{{ c.exit_time ? ' · 已退出' : '' }}</span>
                        </div>
                      </div>
                    </div>
                  </section>
                  <section class="inv-g">
                    <h5>归属事件（{{ (entityView.events || []).length }}）</h5>
                    <div class="health-chips" style="margin-bottom:6px">
                      <span v-for="(n, k) in (entityView.event_counts || {})" :key="k" class="hchip">{{ etypeLabel(k) }} {{ n }}</span>
                    </div>
                    <div v-for="ev in (entityView.events || []).slice(0, 120)" :key="ev.id" class="ent-ev">
                      <span class="muted">{{ fmtTime(ev.ts) }}</span>
                      <em class="pill" :class="'sev-' + ev.severity">{{ etypeLabel(ev.etype) }}</em>
                      <span>{{ cleanSummary(ev.summary) }}</span>
                    </div>
                    <p v-if="!(entityView.events || []).length" class="empty sm">该实体暂无其他归属事件</p>
                  </section>
                </template>
              </div>

              <div v-else-if="invDetailTab === 'info'" class="inv-dbody">
                <section class="inv-g">
                  <h5>日志信息</h5>
                  <div class="inv-kv">
                    <div v-for="f in (invDetail.info || [])" :key="f.k" class="inv-kv-row">
                      <span>{{ f.k }}</span>
                      <strong>{{ f.k === '摘要' ? cleanSummary(f.v) : (f.v == null || f.v === '' ? '—' : f.v) }}</strong>
                    </div>
                  </div>
                </section>
                <section v-for="g in (invDetail.groups || [])" :key="g.title" class="inv-g">
                  <h5>{{ g.title }}</h5>
                  <div class="inv-kv">
                    <div v-for="f in g.fields" :key="f.k" class="inv-kv-row" :class="{ wide: String(f.v).length > 48 }">
                      <span>{{ DETAIL_LABELS[f.k] || colLabel(f.k) || f.k }}</span>
                      <strong class="mono">
                        {{ f.v }}
                        <button v-if="String(f.v).length > 24" type="button" class="ev-copy" @click="copyText(String(f.v))">复制</button>
                      </strong>
                    </div>
                  </div>
                </section>
                <div class="inv-dacts">
                  <button type="button" class="btn sm" @click="jumpInvTimeline">完整时间线</button>
                  <button type="button" class="btn sm" @click="jumpInvHost">打开主机</button>
                </div>
              </div>

              <div v-else-if="invDetailTab === 'chain'" class="inv-dbody">
                <div v-if="(invDetail.chain || []).length" class="inv-chain">
                  <div
                    v-for="(n, i) in invDetail.chain"
                    :key="i"
                    class="inv-cnode"
                    :class="{ on: n.current, miss: n.missing, child: n.child }"
                  >
                    <i class="dot" />
                    <div>
                      <b>{{ n.name || ('PID ' + n.pid) }}</b>
                      <span>PID {{ n.pid }}<template v-if="n.ppid != null"> · PPID {{ n.ppid }}</template></span>
                      <small v-if="n.path" class="mono">{{ n.path }}</small>
                      <small v-if="n.command_line" class="mono">{{ n.command_line }}</small>
                    </div>
                  </div>
                </div>
                <p v-else class="empty sm">该日志无进程 PID，或同主机时间线不足以还原父子链。</p>
              </div>

              <div v-else class="inv-dbody">
                <pre class="inv-raw">{{ JSON.stringify(invDetail.raw || invDetail.item, null, 2) }}</pre>
                <button type="button" class="btn sm" @click="copyText(JSON.stringify(invDetail.raw || invDetail.item, null, 2))">复制 JSON</button>
              </div>
            </aside>
          </div>
        </div>
      </section>

<section v-if="page === 'dns'" class="page dns-page">
        <header class="page-hd">
          <div>
            <h1>DNS 狩猎</h1>
            <p class="desc">按域名聚合：默认近 24 小时 · 仅在线终端；可选「全部终端」或指定主机，取消勾选可看离线/历史</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn sm" :disabled="dnsBusy" @click="loadDns">{{ dnsBusy ? '刷新中…' : '刷新' }}</button>
            <button type="button" class="btn sm" @click="goMenu('events')">威胁事件 →</button>
          </div>
        </header>

        <div class="evt-filter-bar panel pad">
          <label class="evt-fl">
            <span>域名</span>
            <input v-model="dnsDomainQ" class="field mono" placeholder="example.com" @keyup.enter="applyDnsFilters" />
          </label>
          <label class="evt-fl">
            <span>应答 IP</span>
            <input v-model="dnsIpQ" class="field mono" placeholder="1.2.3.4" @keyup.enter="applyDnsFilters" />
          </label>
          <label class="evt-fl">
            <span>进程</span>
            <input v-model="dnsProcQ" class="field" placeholder="powershell" @keyup.enter="applyDnsFilters" />
          </label>
          <label class="evt-fl">
            <span>时间</span>
            <select v-model="dnsRange" class="field" @change="applyDnsFilters">
              <option value="1h">近 1 小时</option>
              <option value="24h">近 24 小时</option>
              <option value="today">今天</option>
              <option value="7d">近 7 天</option>
              <option value="30d">近 30 天</option>
              <option value="all">全部历史</option>
            </select>
          </label>
          <label class="evt-fl">
            <span>终端</span>
            <select v-model="dnsAgent" class="field" @change="applyDnsFilters">
              <option value="">全部终端</option>
              <option v-for="a in agents" :key="a.agent_id" :value="a.agent_id">{{ a.hostname || short(a.agent_id) }}</option>
            </select>
          </label>
          <label class="evt-fl">
            <span>职场 / 分组</span>
            <select v-model="dnsGroupId" class="field" @change="applyDnsFilters">
              <option value="">全部</option>
              <option v-for="g in groupItems" :key="g.id" :value="g.id">{{ g.name }}</option>
            </select>
          </label>
          <label class="evt-fl chk-inline">
            <span>条件</span>
            <div class="dns-checks">
              <label class="chk"><input v-model="dnsOnlineOnly" type="checkbox" @change="applyDnsFilters" /> 仅在线终端</label>
              <label class="chk"><input v-model="dnsNx" type="checkbox" /> 仅解析失败</label>
              <label class="chk"><input v-model="dnsDgaOnly" type="checkbox" /> 高 DGA</label>
              <label class="chk"><input v-model="dnsIntelOnly" type="checkbox" /> 情报命中</label>
            </div>
          </label>
          <div class="evt-fl-acts">
            <button type="button" class="btn primary" :disabled="dnsBusy" @click="applyDnsFilters">{{ dnsBusy ? '查询中…' : '查询' }}</button>
            <button type="button" class="btn" @click="resetDnsFilters">重置</button>
          </div>
        </div>

        <div class="dns-summary panel pad">
          <div class="mal-stat"><b>{{ dnsStats.total }}</b><span>域名聚合</span></div>
          <div class="mal-stat"><b>{{ dnsStats.hits }}</b><span>解析次数</span></div>
          <div class="mal-stat"><b>{{ dnsStats.nx }}</b><span>解析失败</span></div>
          <div class="mal-stat"><b>{{ dnsStats.intel }}</b><span>情报命中</span></div>
          <p class="hint sm">
            情报源：<code class="mono">{{ dnsIocMeta.path || 'ioc_data.db' }}</code>
            <template v-if="dnsIocMeta.ok === false">
              · <span class="off">{{ dnsIocMeta.hint || '未加载' }}</span>
            </template>
            <template v-else>
              · 精确匹配域名 / ip_only
              <template v-if="dnsIocMeta.ms != null">（{{ dnsIocMeta.ms }}ms）</template>
            </template>
            ；点「次数」下钻日志，点域名筛威胁事件
          </p>
        </div>

        <div class="panel pad dns-table-panel">
          <p v-if="dnsBusy && !filteredDnsItems.length" class="hint sm" style="margin:0 0 8px">加载中…</p>
          <template v-if="filteredDnsItems.length">
            <div class="table-scroll dns-table-scroll">
              <table class="evt-table">
                <thead>
                  <tr>
                    <th class="sortable" @click="toggleDnsSort('domain')">域名 <i class="sort-ico">{{ dnsSortMark('domain') }}</i></th>
                    <th class="sortable" @click="toggleDnsSort('hostname')">涉及终端 <i class="sort-ico">{{ dnsSortMark('hostname') }}</i></th>
                    <th class="sortable" @click="toggleDnsSort('hits')">次数 <i class="sort-ico">{{ dnsSortMark('hits') }}</i></th>
                    <th class="sortable" @click="toggleDnsSort('nx_hits')">失败 <i class="sort-ico">{{ dnsSortMark('nx_hits') }}</i></th>
                    <th class="sortable" @click="toggleDnsSort('max_dga')">DGA <i class="sort-ico">{{ dnsSortMark('max_dga') }}</i></th>
                    <th>情报</th>
                    <th>进程</th>
                    <th>应答</th>
                    <th class="sortable" @click="toggleDnsSort('first_seen')">首次 <i class="sort-ico">{{ dnsSortMark('first_seen') }}</i></th>
                    <th class="sortable" @click="toggleDnsSort('last_seen')">最近 <i class="sort-ico">{{ dnsSortMark('last_seen') }}</i></th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="d in pagedDnsItems"
                    :key="d.agent_id + ':' + d.domain"
                    class="row-click"
                    :class="{ 'row-warn': d.nx_hits > 0 || d.max_dga >= 0.7 || d.ioc_hit, on: dnsDetailKey(d) === dnsDetailKey(selectedDns) }"
                    @click="openDnsDetail(d)"
                  >
                    <td class="strong mono" :title="d.domain">{{ d.domain }}</td>
                    <td class="dns-host-cell" :title="dnsHostTitle(d)">
                      <b>{{ dnsHostLabel(d) }}</b>
                      <small v-if="agentIp(d.agent_id)" class="muted">{{ agentIp(d.agent_id) }}</small>
                    </td>
                    <td @click.stop>
                      <button
                        type="button"
                        class="log-n"
                        :class="{ hot: Number(d.hits) > 5, multi: Number(d.hits) >= 20 }"
                        :title="`解析 ${d.hits || 0} 次 · 点击查看相关日志`"
                        @click="openDnsLogHits(d)"
                      >{{ d.hits || 0 }}</button>
                    </td>
                    <td>{{ d.nx_hits || '' }}</td>
                    <td>{{ d.max_dga ? Number(d.max_dga).toFixed(2) : '' }}</td>
                    <td class="dns-ioc-cell" @click.stop>
                      <template v-if="d.ioc_hit && (d.ioc_hits || []).length">
                        <div class="dns-ioc-tags" :title="dnsIocTitle(d)">
                          <span
                            v-for="(h, hi) in (d.ioc_hits || []).slice(0, 3)"
                            :key="hi"
                            class="tag judge dns-ioc-tag"
                            @click="openDnsDetail(d, h)"
                          >
                            <em class="via">{{ h.via_label || (h.via === 'answer' ? '应答IP' : '域名') }}</em>
                            {{ dnsHitChip(h) }}
                          </span>
                          <span v-if="(d.ioc_hits || []).length > 3" class="muted sm">+{{ (d.ioc_hits || []).length - 3 }}</span>
                        </div>
                        <div v-if="dnsHitTags(d).length" class="dns-ioc-fam">
                          <span v-for="(t, ti) in dnsHitTags(d).slice(0, 4)" :key="ti" class="tag soft">{{ t }}</span>
                        </div>
                      </template>
                      <span v-else-if="d.ioc_hit" class="tag judge" :title="dnsIocTitle(d)" @click="openDnsDetail(d)">情报</span>
                      <span v-else class="muted">—</span>
                    </td>
                    <td class="muted" :title="(d.processes || []).join(', ')">{{ (d.processes || []).slice(0, 2).join(', ') }}{{ (d.processes || []).length > 2 ? '…' : '' }}</td>
                    <td class="mono muted" :title="(d.answers || []).join('\n')">{{ (d.answers || []).slice(0, 3).join(', ') }}{{ (d.answers || []).length > 3 ? '…' : '' }}</td>
                    <td class="muted">{{ fmtTime(d.first_seen) }}</td>
                    <td class="muted">{{ fmtTime(d.last_seen) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-if="selectedDns" class="dns-detail panel pad">
              <div class="dns-detail-hd">
                <div>
                  <b class="mono">{{ selectedDns.domain }}</b>
                  <span class="muted"> · {{ dnsHostLabel(selectedDns) }}</span>
                  <span v-if="selectedDns.ioc_hit" class="tag judge" style="margin-left:8px">情报命中</span>
                </div>
                <button type="button" class="btn-text" @click="selectedDns = null; selectedDnsHit = null">关闭</button>
              </div>
              <div class="dns-detail-grid">
                <div><em>涉及终端</em><b>{{ dnsHostLabel(selectedDns) }}</b></div>
                <div><em>终端 IP</em><b>{{ agentIp(selectedDns.agent_id) || '—' }}</b></div>
                <div><em>Agent</em><b class="mono">{{ short(selectedDns.agent_id) }}</b></div>
                <div><em>解析次数</em><b>{{ selectedDns.hits || 0 }}</b></div>
                <div><em>失败</em><b>{{ selectedDns.nx_hits || 0 }}</b></div>
                <div><em>DGA</em><b>{{ selectedDns.max_dga ? Number(selectedDns.max_dga).toFixed(2) : '—' }}</b></div>
                <div><em>首次</em><b>{{ fmtTime(selectedDns.first_seen) }}</b></div>
                <div><em>最近</em><b>{{ fmtTime(selectedDns.last_seen) }}</b></div>
              </div>
              <div class="dns-detail-sec">
                <h4>涉及终端</h4>
                <p>
                  <b>{{ dnsHostLabel(selectedDns) }}</b>
                  <span class="muted" v-if="agentIp(selectedDns.agent_id)"> · {{ agentIp(selectedDns.agent_id) }}</span>
                  <span class="muted"> · {{ short(selectedDns.agent_id) }}</span>
                  <button type="button" class="btn-text sm" style="margin-left:8px" @click="dnsAgent = selectedDns.agent_id; applyDnsFilters()">仅看此终端</button>
                </p>
              </div>
              <div class="dns-detail-sec">
                <h4>进程</h4>
                <p class="mono">{{ (selectedDns.processes || []).join(', ') || '—' }}</p>
              </div>
              <div class="dns-detail-sec">
                <h4>应答 IP</h4>
                <p class="mono">{{ (selectedDns.answers || []).join(', ') || '—' }}</p>
              </div>
              <div v-if="(selectedDns.ioc_hits || []).length" class="dns-detail-sec">
                <h4>情报命中</h4>
                <ul class="dns-ioc-list">
                  <li
                    v-for="(h, hi) in selectedDns.ioc_hits"
                    :key="'di-' + hi"
                    :class="{ on: selectedDnsHit === h }"
                    @click="selectedDnsHit = h"
                  >
                    <span class="tag judge">{{ h.via_label || (h.via === 'answer' ? '应答IP' : '域名') }}</span>
                    <b>{{ dnsHitChip(h) }}</b>
                    <span class="muted">{{ (h.tags || h.malware || '').toString() }}</span>
                  </li>
                </ul>
                <div v-if="selectedDnsHit" class="dns-ioc-focus mono">
                  <div v-for="(v, k) in selectedDnsHit" :key="'dh-' + k">
                    <em>{{ k }}</em> {{ typeof v === 'object' ? JSON.stringify(v) : v }}
                  </div>
                </div>
              </div>
              <div class="dns-detail-acts">
                <button type="button" class="btn sm primary" @click="openDnsLogHits(selectedDns)">相关日志调查</button>
                <button type="button" class="btn sm" @click="openDnsThreat(selectedDns)">筛威胁事件</button>
              </div>
            </div>
            <div class="list-pager dns-pager">
              <span class="pg-info">第 {{ dnsPage }} / {{ dnsPageCount }} 页 · 共 {{ filteredDnsItems.length }} 条</span>
              <div class="pg-acts">
                <select v-model.number="dnsPageSize" class="pg-size" @change="dnsPage = 1">
                  <option :value="10">10 条/页</option>
                  <option :value="20">20 条/页</option>
                  <option :value="50">50 条/页</option>
                </select>
                <button type="button" class="btn sm" :disabled="dnsPage <= 1" @click="dnsPage--">上一页</button>
                <button type="button" class="btn sm" :disabled="dnsPage >= dnsPageCount" @click="dnsPage++">下一页</button>
              </div>
            </div>
          </template>
          <div v-else-if="!dnsBusy" class="empty ov-empty">
            <p>{{ dnsHasFilter ? '当前筛选下无 DNS 记录' : '暂无 DNS 记录（需要 ETW 或 Sysmon 22）' }}</p>
            <div class="row" style="justify-content:center;gap:8px;flex-wrap:wrap">
              <button v-if="dnsHasFilter" type="button" class="btn sm" @click="resetDnsFilters">清除筛选</button>
              <button type="button" class="btn sm" @click="loadDns">重新加载</button>
            </div>
          </div>
        </div>
      </section>

<section v-if="page === 'behaviors'" class="page behaviors-page">
        <header class="bh-top">
          <h1>检出行为</h1>
          <div class="bh-top-r">
            <span class="muted">时间范围：全部</span>
            <button type="button" class="btn sm" @click="goPage('events')">威胁事件 →</button>
          </div>
        </header>

        <div class="bh-filters panel">
          <select v-model="bhNature" class="search">
            <option value="">事件性质：全部</option>
            <option value="threat">威胁行为</option>
            <option value="risk">风险行为</option>
          </select>
          <select v-model="bhGroup" class="search">
            <option value="">职场 / 分组：全部</option>
            <option v-for="g in groupItems" :key="g.id" :value="g.id">{{ g.name }}</option>
          </select>
          <select v-model="bhOs" class="search">
            <option value="">操作系统：全部</option>
            <option v-for="os in bhOsOptions" :key="os" :value="os">{{ os }}</option>
          </select>
          <select v-model="behaviorSev" class="search">
            <option value="">严重级别：全部</option>
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
          <input v-model="bhQ" class="search grow" placeholder="终端名 / 告警标题 / 路径…" @keyup.enter="bhPage = 1" />
          <select v-model="bhTactic" class="search">
            <option value="">ATT&CK 阶段：全部</option>
            <option v-for="(lab, key) in TACTIC_CN" :key="key" :value="key">{{ lab }}</option>
          </select>
          <button type="button" class="btn primary" @click="bhPage = 1">查询</button>
          <button type="button" class="btn" @click="resetBhFilters">重置</button>
        </div>

        <div class="bh-stats">
          <div class="panel bh-sev">
            <div class="panel-hd bare"><h3>严重级别分布</h3></div>
            <div class="bh-sev-body">
              <div class="bh-sev-row">
                <span class="bh-ico threat">威</span>
                <div class="bh-sev-main">
                  <b>威胁行为 <em>{{ bhThreatN }}</em></b>
                  <div class="bh-bar"><i class="threat" :style="{ width: bhBarPct(bhThreatN) + '%' }" /></div>
                  <small>明确威胁，可进行处置</small>
                </div>
              </div>
              <div class="bh-sev-row">
                <span class="bh-ico risk">险</span>
                <div class="bh-sev-main">
                  <b>风险行为 <em>{{ bhRiskN }}</em></b>
                  <div class="bh-bar"><i class="risk" :style="{ width: bhBarPct(bhRiskN) + '%' }" /></div>
                  <small>可疑行为，用于溯源和关联</small>
                </div>
              </div>
            </div>
          </div>

          <div class="panel bh-stage">
            <div class="panel-hd bare">
              <h3>威胁阶段分布</h3>
              <span class="meta">点击节点或图例筛选 · 已覆盖 {{ bhTacticHitN }} / 12</span>
            </div>
            <div class="bh-wave">
              <svg class="bh-wave-svg" viewBox="0 0 720 140" preserveAspectRatio="none" aria-hidden="true">
                <defs>
                  <linearGradient id="bhWaveGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stop-color="#f5c542" />
                    <stop offset="35%" stop-color="#f08a1f" />
                    <stop offset="65%" stop-color="#e11d2e" />
                    <stop offset="100%" stop-color="#94a3b8" />
                  </linearGradient>
                </defs>
                <path
                  class="bh-wave-path"
                  :d="bhWavePath"
                  fill="none"
                  stroke="url(#bhWaveGrad)"
                  stroke-width="22"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
              <button
                v-for="(t, i) in bhTacticRing"
                :key="'wn-' + t.key"
                type="button"
                class="bh-wave-node"
                :class="{ on: bhTactic === t.key, hit: t.count > 0, dim: !t.count }"
                :style="bhWaveNodeStyle(i, t)"
                :title="`${t.stageLabel}：${t.count}`"
                @click="bhTactic = bhTactic === t.key ? '' : t.key; bhPage = 1"
              >
                <svg class="bh-ico-svg" viewBox="0 0 24 24" aria-hidden="true">
                  <path :d="stageIconPath(t.icon)" fill="currentColor" />
                </svg>
              </button>
            </div>
            <div class="bh-wave-legend">
              <button
                v-for="(t, i) in bhTacticRing"
                :key="'wl-' + t.key"
                type="button"
                class="bh-leg"
                :class="{ on: bhTactic === t.key, hit: t.count > 0 }"
                @click="bhTactic = bhTactic === t.key ? '' : t.key; bhPage = 1"
              >
                <i :style="{ background: t.color }" />
                <span>{{ i + 1 }}-{{ t.stageLabel }}</span>
                <b>{{ t.count }}</b>
              </button>
            </div>
          </div>

          <div class="panel bh-top">
            <div class="panel-hd bare"><h3>TOP 检出威胁</h3></div>
            <div class="bh-top-list">
              <button
                v-for="(t, i) in bhTopThreats"
                :key="t.title"
                type="button"
                class="bh-top-row"
                @click="bhQ = t.title; bhPage = 1"
              >
                <em>{{ i + 1 }}</em>
                <div class="bh-top-main">
                  <b :title="t.title">{{ t.title }}</b>
                  <i class="bh-bar"><i :style="{ width: bhBarPct(t.count, bhTopMax) + '%' }" /></i>
                </div>
                <strong>{{ t.count }}</strong>
              </button>
              <p v-if="!bhTopThreats.length" class="empty sm">暂无</p>
            </div>
          </div>
        </div>

        <div class="bh-bottom">
          <aside class="panel bh-hosts">
            <div class="panel-hd bare">
              <h3>检出终端 ({{ bhHostList.length }})</h3>
            </div>
            <button type="button" class="term-all" :class="{ on: !bhAgentId }" @click="bhAgentId = ''">全部终端</button>
            <div class="bh-host-scroll">
              <button
                v-for="h in bhHostList"
                :key="h.agent_id"
                type="button"
                class="term-row"
                :class="{ on: bhAgentId === h.agent_id }"
                @click="bhAgentId = h.agent_id; bhPage = 1"
              >
                <i :class="['dot', h.online ? 'on' : '']" />
                <span>{{ h.hostname }}</span>
                <em class="alert-n">{{ h.count }}</em>
              </button>
            </div>
          </aside>

          <div class="panel bh-list">
            <div class="panel-hd bare">
              <h3>检出行为列表 ({{ behaviorEvents.length }})</h3>
              <span class="meta">点行下方看详情 · 操作里进威胁视图 / 加白 / 删除</span>
            </div>
            <div class="table-scroll" v-if="pagedBhEvents.length">
              <table class="evt-table">
                <thead>
                  <tr>
                    <th>行为 / 告警</th>
                    <th>级别</th>
                    <th>类型</th>
                    <th>终端</th>
                    <th>用户</th>
                    <th>时间</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <template v-for="e in pagedBhEvents" :key="e.id">
                    <tr class="row-click" :class="{ on: listFocusId === e.id }" @click="selectListEvent(e)">
                      <td class="strong">{{ e.title }}</td>
                      <td><span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span></td>
                      <td><span class="tag judge">{{ behaviorKind(e) }}</span></td>
                      <td>{{ e.hostname || short(e.agent_id) }}</td>
                      <td>{{ eventUserHint(e) }}</td>
                      <td>{{ fmtTime(e.updated_at || e.created_at) }}</td>
                      <td class="ops" @click.stop>
                        <div class="op-more" @click.stop>
                          <button type="button" class="btn sm op-more-btn" :class="{ on: opMenuId === e.id }" @click="toggleOpMenu(e.id)">操作 ▾</button>
                          <div v-if="opMenuId === e.id" class="op-more-menu">
                            <button type="button" class="op-more-item primary" @click="runOpMenu(() => openEvent(e))">威胁视图</button>
                            <button type="button" class="op-more-item" @click="runOpMenu(() => openAllow(e))">加入白名单</button>
                            <button type="button" class="op-more-item danger" @click="runOpMenu(() => removeEvent(e))">删除</button>
                          </div>
                        </div>
                      </td>
                    </tr>
                    <tr v-if="listFocusId === e.id && listFocusEvent" class="evt-expand-row">
                      <td colspan="7">
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
                          <div class="bh-expand">
                            <section class="bh-expand-card">
                              <header class="bh-expand-hd">影响终端 / 用户</header>
                              <div class="ed-host-grid">
                                <div class="ed-host-cell">
                                  <span class="ed-k">终端</span>
                                  <div class="ed-host-name">
                                    <i :class="['dot', listFocusAgent?.online ? 'on' : '']" />
                                    <b :title="listFocusEvent.hostname || listFocusAgent?.hostname || listFocusEvent.agent_id">
                                      {{ listFocusEvent.hostname || listFocusAgent?.hostname || short(listFocusEvent.agent_id) }}
                                    </b>
                                    <em :class="listFocusAgent?.online ? 'on' : 'off'">{{ listFocusAgent?.online ? '在线' : '离线' }}</em>
                                  </div>
                                  <div class="ed-host-sub">
                                    <span :title="listFocusAgent?.ip || agentIp(listFocusEvent.agent_id) || ''">IP {{ listFocusAgent?.ip || agentIp(listFocusEvent.agent_id) || '—' }}</span>
                                    <span v-if="listFocusMac" :title="listFocusMac">MAC {{ listFocusMac }}</span>
                                  </div>
                                </div>
                                <div class="ed-host-cell">
                                  <span class="ed-k">用户</span>
                                  <div class="ed-user">
                                    <b :title="listFocusUser || ''">{{ listFocusUser || '未知用户' }}</b>
                                    <small v-if="listFocusUserDomain" :title="listFocusUserDomain">{{ listFocusUserDomain }}</small>
                                    <small v-else :title="listFocusGroupLabel">分组 {{ listFocusGroupLabel }}</small>
                                  </div>
                                </div>
                              </div>
                              <div class="ed-kv bh-expand-kv">
                                <div><span>操作系统</span><b :title="listFocusOsLabel">{{ listFocusOsLabel }}</b></div>
                                <div><span>Agent ID</span><b class="mono clip" :title="listFocusEvent.agent_id || ''">{{ listFocusEvent.agent_id || '—' }}</b></div>
                                <div><span>检测模块</span><b :title="modLabel(listFocusEvent.module) || ''">{{ modLabel(listFocusEvent.module) || '—' }}</b></div>
                                <div><span>判定</span><b>{{ judgeOf(listFocusEvent) }}</b></div>
                              </div>
                            </section>
                            <section class="bh-expand-card bh-expand-main">
                              <header class="bh-expand-hd">
                                行为详情
                                <button v-if="listOverviewExtra.length" type="button" class="ed-more" @click.stop="edMore = !edMore">
                                  {{ edMore ? '收起额外字段' : `展开额外字段（${listOverviewExtra.length}）` }}
                                </button>
                              </header>
                              <div class="bh-field-grid">
                                <div
                                  v-for="r in listBehaviorDetailRows"
                                  :key="'bh-' + r.k"
                                  class="bh-field"
                                  :class="{ wide: r.mono || String(r.v).length > 48, root: r.root }"
                                >
                                  <span>{{ r.k }}</span>
                                  <b :class="{ mono: r.mono }" :title="r.v">{{ r.v }}</b>
                                </div>
                              </div>
                            </section>
                          </div>
                        </div>
                      </td>
                    </tr>
                  </template>
                </tbody>
              </table>
            </div>
            <p v-else class="empty">暂无检出行为</p>
            <div v-if="behaviorEvents.length" class="list-pager">
              <span class="pg-info">第 {{ bhPage }} / {{ bhPageCount }} 页 · 共 {{ behaviorEvents.length }} 条</span>
              <div class="pg-acts">
                <select v-model.number="bhPageSize" class="pg-size" @change="bhPage = 1">
                  <option :value="10">10 条/页</option>
                  <option :value="20">20 条/页</option>
                  <option :value="50">50 条/页</option>
                </select>
                <button type="button" class="btn sm" :disabled="bhPage <= 1" @click="bhPage--">上一页</button>
                <button type="button" class="btn sm" :disabled="bhPage >= bhPageCount" @click="bhPage++">下一页</button>
              </div>
            </div>
          </div>
        </div>
      </section>
</template>

<script>
import { defineAsyncComponent } from 'vue'
import { forwardSetupContext } from './setupContext.js'
const OverviewFleetStrip = defineAsyncComponent(() => import('./OverviewFleetStrip.vue'))
const OverviewThreatCards = defineAsyncComponent(() => import('./OverviewThreatCards.vue'))
export default {
  components: { OverviewFleetStrip, OverviewThreatCards },
  props: { context: { type: Object, required: true } },
  setup(props) { return forwardSetupContext(props.context) },
}
</script>
