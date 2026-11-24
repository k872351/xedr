<template>
<section v-if="page === 'events' || page === 'malware'" class="page events-page" :class="{ 'malware-page': page === 'malware' }">
        <header class="page-hd">
          <div>
            <h1>{{ page === 'malware' ? '恶意文件' : '威胁事件' }}</h1>
            <p class="desc">{{ page === 'malware'
              ? '文件落地、FIM 变更、带可执行路径/样本的告警（含「规则命中」类文件威胁）；点击行查看详情与隔离处置'
              : '点击行在右侧查看详情；「操作」里可进威胁视图 / 加白 / 删除' }}</p>
          </div>
          <div class="hd-right">
            <span class="live-hint" :class="{ on: liveOk }"><i class="live-dot" />{{ liveOk ? liveAgo : '连接中' }}</span>
            <select v-if="page === 'malware'" v-model="eventSevFilter" class="search sev-filter">
              <option value="">全部级别</option>
              <option value="critical">严重</option>
              <option value="high">高危</option>
              <option value="medium">中危</option>
              <option value="low">低危</option>
            </select>
            <button
              v-if="selectedEventIds.length"
              type="button"
              class="btn danger"
              @click="removeSelectedEvents"
            >删除所选 ({{ selectedEventIds.length }})</button>
            <button
              v-if="isAdmin && filteredEvents.length"
              type="button"
              class="btn danger"
              @click="removeAllEvents"
            >{{ eventFiltersActive || page === 'malware' ? '删除筛选结果' : '全部删除' }}</button>
          </div>
        </header>

        <div v-if="page === 'events'" class="evt-filter-bar panel pad">
          <label class="evt-fl">
            <span>威胁 / 域名</span>
            <input
              v-model="eventQName"
              class="field"
              placeholder="标题、域名、进程…"
              @keyup.enter="applyEventFilters"
            />
          </label>
          <label class="evt-fl">
            <span>职场 / 分组</span>
            <select v-model="eventGroupId" class="field">
              <option value="">全部</option>
              <option v-for="g in groupItems" :key="g.id" :value="g.id">{{ g.name }}</option>
            </select>
          </label>
          <label class="evt-fl">
            <span>严重级别</span>
            <select v-model="eventSevFilter" class="field">
              <option value="">全部</option>
              <option value="critical">严重</option>
              <option value="high">高危</option>
              <option value="medium">中危</option>
              <option value="low">低危</option>
            </select>
          </label>
          <label class="evt-fl">
            <span>威胁类型</span>
            <select v-model="eventTypeFilter" class="field">
              <option value="">全部</option>
              <option v-for="c in FOCUS_DEFS" :key="c.key" :value="c.key">{{ c.label }}</option>
            </select>
          </label>
          <label class="evt-fl grow">
            <span>情报 IP / 域名</span>
            <input
              v-model="eventIocQ"
              class="field mono"
              placeholder="外联 IP 或域名，如 1.2.3.4 / evil.com"
              @keyup.enter="applyEventFilters"
            />
          </label>
          <label class="evt-fl">
            <span>来源</span>
            <select v-model="eventSourceFilter" class="field">
              <option value="">全部</option>
              <option value="sysmon">Sysmon</option>
            </select>
          </label>
          <label class="evt-fl">
            <span>EventID</span>
            <input
              v-model="eventEidFilter"
              class="field mono"
              placeholder="如 10 / 8"
              @keyup.enter="applyEventFilters"
            />
          </label>
          <div class="evt-fl-acts">
            <button type="button" class="btn primary" @click="applyEventFilters">查询</button>
            <button type="button" class="btn" @click="resetEventFilters">重置</button>
          </div>
        </div>

        <div class="event-layout single">
          <div class="event-main">
            <div v-if="page === 'malware'" class="malware-summary panel pad">
              <div class="mal-stat">
                <b>{{ malwareFileStats.total }}</b>
                <span>文件相关告警</span>
              </div>
              <div class="mal-stat">
                <b>{{ malwareFileStats.hosts }}</b>
                <span>涉及终端</span>
              </div>
              <div class="mal-stat">
                <b>{{ malwareFileStats.high }}</b>
                <span>高危及以上</span>
              </div>
              <p class="hint sm">含 FIM、文件模块、路径/哈希可识别的规则命中（不仅「文件落地」分类卡片）</p>
            </div>
            <div v-else class="focus-block">
              <div class="focus-title">重点关注事件</div>
              <div class="focus-grid">
                <button
                  v-for="c in focusCats"
                  :key="c.key"
                  type="button"
                  class="focus-card"
                  :class="{ on: focusKey === c.key }"
                  @click="toggleFocusCat(c.key)"
                >
                  <span class="focus-ico" :style="{ background: c.color }">{{ c.short }}</span>
                  <div>
                    <b>{{ c.label }}</b>
                    <em>{{ c.count }} 条 · {{ c.hosts }} 台主机</em>
                  </div>
                </button>
              </div>
            </div>

            <div class="split" :class="{ 'has-detail': !!listFocusEvent }">
              <aside class="term-pane" v-show="!listFocusEvent">
                <div class="term-hd"><b>威胁终端 ({{ eventAgents.length }})</b></div>
                <button type="button" class="term-all" :class="{ on: !eventAgentId }" @click="eventAgentId = ''">全部设备</button>
                <button
                  v-for="a in eventAgents"
                  :key="a.agent_id"
                  type="button"
                  class="term-row"
                  :class="{ on: eventAgentId === a.agent_id }"
                  @click="eventAgentId = a.agent_id"
                >
                  <i :class="['dot', a.online ? 'on' : '']" />
                  <span>{{ a.hostname || short(a.agent_id) }}</span>
                </button>
              </aside>

              <div class="panel table-pane">
                <div class="panel-hd">
                  <h3>{{ page === 'malware' ? '恶意文件告警' : '事件列表' }} ({{ filteredEvents.length }})</h3>
                </div>
                <div class="table-scroll">
                  <table class="evt-table">
                    <thead>
                      <tr>
                        <th class="col-chk">
                          <input type="checkbox" :checked="allEventsSelected" @change="toggleSelectAllEvents" />
                        </th>
                        <th>事件名称</th>
                        <th v-if="page !== 'malware' && !listFocusEvent" class="mono">执行命令（摘要）</th>
                        <th v-if="page === 'malware' && !listFocusEvent">文件路径 / 样本</th>
                        <th class="sortable" @click="toggleEventSort('severity')">
                          严重级别 <i class="sort-ico">{{ sortMark('severity') }}</i>
                        </th>
                        <th v-if="!listFocusEvent && page !== 'malware'">判定结果</th>
                        <th>影响终端</th>
                        <th
                          v-if="!listFocusEvent"
                          class="sortable"
                          @click="toggleEventSort('hit_count')"
                        >
                          告警日志数 <i class="sort-ico">{{ sortMark('hit_count') }}</i>
                        </th>
                        <th class="sortable" @click="toggleEventSort('updated_at')">
                          上次活跃 <i class="sort-ico">{{ sortMark('updated_at') }}</i>
                        </th>
                        <th v-if="!listFocusEvent" class="sortable" @click="toggleEventSort('created_at')">
                          首次发现 <i class="sort-ico">{{ sortMark('created_at') }}</i>
                        </th>
                        <th>操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr
                        v-for="e in pagedEvents"
                        :key="e.id"
                        class="row-click"
                        :class="{ on: listFocusId === e.id }"
                        @click="selectListEvent(e)"
                      >
                        <td class="col-chk" @click.stop>
                          <input type="checkbox" :checked="selectedEventIds.includes(e.id)" @change="toggleEventSelect(e.id)" />
                        </td>
                        <td class="strong">{{ e.title }}</td>
                        <td v-if="page !== 'malware' && !listFocusEvent" class="mono muted cmd-col" :title="eventCmdSummary(e)">{{ eventCmdSummary(e) || '—' }}</td>
                        <td v-if="page === 'malware' && !listFocusEvent" class="mono muted" :title="eventFileHint(e)">{{ shortPath(eventFileHint(e)) }}</td>
                        <td><span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span></td>
                        <td v-if="!listFocusEvent && page !== 'malware'"><span class="tag judge">{{ judgeOf(e) }}</span></td>
                        <td>{{ e.hostname || short(e.agent_id) }}</td>
                        <td v-if="!listFocusEvent" @click.stop>
                          <button
                            type="button"
                            class="log-n"
                            :class="{ hot: eventLogCount(e) > 1, multi: eventLogCount(e) >= 5 }"
                            :title="eventLogCount(e) > 1 ? `累计命中 ${eventLogCount(e)} 次 · 点击查看相关日志` : '首次命中 · 点击查看相关日志'"
                            @click="openEventLogHits(e)"
                          >{{ eventLogCount(e) }}</button>
                        </td>
                        <td>{{ fmtTime(e.updated_at || e.created_at) }}</td>
                        <td v-if="!listFocusEvent">{{ fmtTime(e.created_at) }}</td>
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
                    </tbody>
                  </table>
                  <div v-if="!filteredEvents.length" class="empty ov-empty">
                    <p>{{ page === 'malware' ? '暂无文件类威胁告警' : (eventFiltersActive ? '当前筛选下无威胁事件' : '暂无威胁事件') }}</p>
                    <div class="row" style="justify-content:center;gap:8px;flex-wrap:wrap">
                      <button v-if="eventFiltersActive" type="button" class="btn sm" @click="resetEventFilters">清除筛选</button>
                      <button type="button" class="btn sm" @click="loadEvents(true, true)">重新同步</button>
                    </div>
                  </div>
                </div>
                <div v-if="filteredEvents.length" class="list-pager">
                  <span class="pg-info">第 {{ evtPage }} / {{ evtPageCount }} 页 · 共 {{ filteredEvents.length }} 条</span>
                  <div class="pg-acts">
                    <select v-model.number="evtPageSize" class="pg-size" @change="evtPage = 1">
                      <option :value="10">10 条/页</option>
                      <option :value="20">20 条/页</option>
                      <option :value="50">50 条/页</option>
                    </select>
                    <button type="button" class="btn sm" :disabled="evtPage <= 1" @click="evtPage--">上一页</button>
                    <button type="button" class="btn sm" :disabled="evtPage >= evtPageCount" @click="evtPage++">下一页</button>
                  </div>
                </div>
              </div>

              <aside v-if="listFocusEvent" class="panel ed-side">
                <div class="ed-top">
                  <div class="ed-top-l">
                    <b>威胁事件概览</b>
                    <div class="ed-nav">
                      <button type="button" class="btn-text" :disabled="!listFocusHasPrev" @click="navListFocus(-1)">上一条</button>
                      <button type="button" class="btn-text" :disabled="!listFocusHasNext" @click="navListFocus(1)">下一条</button>
                      <button type="button" class="ed-x" title="关闭" @click="clearListFocus">×</button>
                    </div>
                  </div>
                  <div class="ed-hero">
                    <span class="ed-shield">!</span>
                    <div class="ed-hero-main">
                      <h2 :title="listFocusEvent.title">{{ listFocusEvent.title }}</h2>
                      <div class="ed-hero-meta">
                        <span class="sev" :data-s="listFocusEvent.severity">{{ sevLabel(listFocusEvent.severity) }}</span>
                        <span class="ed-st" :data-s="listFocusEvent.status">{{ statusLabel(listFocusEvent.status) }}</span>
                        <span class="muted">{{ judgeOf(listFocusEvent) }}</span>
                      </div>
                      <button type="button" class="btn primary ed-open" @click="openEvent(listFocusEvent)">威胁视图</button>
                    </div>
                  </div>
                </div>

                <div class="ed-scroll">
                  <section class="ed-card" :class="{ folded: edFold.overview }">
                    <header class="ed-card-hd" @click="edFold.overview = !edFold.overview">
                      <b>威胁事件概览</b>
                      <i>{{ edFold.overview ? '+' : '−' }}</i>
                    </header>
                    <div v-show="!edFold.overview" class="ed-card-bd">
                      <dl class="ed-dl">
                        <div v-for="r in listOverviewCore" :key="'oc-' + r.k">
                          <dt>{{ r.k }}</dt>
                          <dd :class="{ mono: r.mono, 'ed-root': r.root }" :title="r.v">{{ r.v }}</dd>
                        </div>
                      </dl>
                      <template v-if="listOverviewExtra.length">
                        <button type="button" class="ed-more" @click.stop="edMore = !edMore">
                          {{ edMore ? '收起额外字段' : `查看更多（${listOverviewExtra.length}）` }} ▾
                        </button>
                        <dl v-if="edMore" class="ed-dl ed-dl-extra">
                          <div v-for="r in listOverviewExtra" :key="'oe-' + r.k">
                            <dt>{{ r.k }}</dt>
                            <dd :class="{ mono: r.mono }" :title="r.v">{{ r.v }}</dd>
                          </div>
                        </dl>
                      </template>
                    </div>
                  </section>

                  <section class="ed-card" :class="{ folded: edFold.host }">
                    <header class="ed-card-hd" @click="edFold.host = !edFold.host">
                      <b>影响终端 / 用户</b>
                      <i>{{ edFold.host ? '+' : '−' }}</i>
                    </header>
                    <div v-show="!edFold.host" class="ed-card-bd">
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
                            <small v-else-if="listFocusGroupLabel && listFocusGroupLabel !== '—'" :title="listFocusGroupLabel">分组 {{ listFocusGroupLabel }}</small>
                          </div>
                        </div>
                      </div>
                      <div class="ed-kv">
                        <div><span>操作系统</span><b :title="listFocusOsLabel">{{ listFocusOsLabel }}</b></div>
                        <div><span>职场 / 分组</span><b :title="listFocusGroupLabel">{{ listFocusGroupLabel }}</b></div>
                        <div><span>最近登录</span><b :title="listFocusUser || ''">{{ listFocusUser || '—' }}</b></div>
                        <div><span>Agent</span><b class="mono clip" :title="listFocusEvent.agent_id || ''">{{ listFocusEvent.agent_id || '—' }}</b></div>
                      </div>
                    </div>
                  </section>

                  <section class="ed-card" :class="{ folded: edFold.alert }">
                    <header class="ed-card-hd" @click="edFold.alert = !edFold.alert">
                      <b>关键告警</b>
                      <i>{{ edFold.alert ? '+' : '−' }}</i>
                    </header>
                    <div v-show="!edFold.alert" class="ed-card-bd">
                      <div class="ed-tabs">
                        <button type="button" :class="{ on: edAlertTab === 'behavior' }" @click="edAlertTab = 'behavior'">
                          告警行为 ({{ listAlertBehaviors.length }})
                        </button>
                        <button type="button" :class="{ on: edAlertTab === 'file' }" @click="edAlertTab = 'file'">
                          恶意文件 ({{ listMaliciousFiles.length }})
                        </button>
                      </div>
                      <p class="hint sm ed-prev-hint">
                        第 1 条为当前告警。
                        <template v-if="isBuildingBlockUpgrade(listEvidenceFlat, listEventEvidence)">多阶段告警会展开其积木子告警，点击可跳转查看。</template>
                        <template v-else>其余仅当同终端、±2h 内且<strong>同规则 ID / 同路径 / 同 PID / 同标题对象 / 同注册表键</strong> 时才出现。</template>
                      </p>
                      <div v-if="edAlertTab === 'behavior'" class="ed-beh">
                        <article
                          v-for="b in listAlertBehaviors"
                          :key="'beh-' + (b.eventId ?? b.title)"
                          class="ed-beh-row"
                          :class="{ current: b.isCurrent, clickable: !b.isCurrent && b.eventId }"
                          @click="!b.isCurrent && b.eventId && jumpListEvent(b.eventId)"
                        >
                          <span class="sev" :data-s="b.severity">{{ sevLabel(b.severity) }}</span>
                          <div class="ed-beh-main">
                            <b :title="b.title">
                              {{ b.title }}
                              <i v-if="b.isCurrent" class="ed-cur-tag">当前</i>
                              <i v-else-if="b.fromBuildingBlock" class="ed-cur-tag bb">积木</i>
                            </b>
                            <small>{{ b.sub }}</small>
                            <em>{{ b.time || (b.eventId ? `#${b.eventId}` : '') }}</em>
                          </div>
                        </article>
                        <p v-if="!listAlertBehaviors.length" class="empty sm">暂无关联告警行为</p>
                        <p v-else-if="listAlertBehaviors.length === 1" class="hint sm">仅展示当前告警；同终端 ±2h 内未找到规则/路径/标题强相关的其它事件</p>
                      </div>
                      <div v-else class="ed-beh">
                        <article v-for="(f, i) in listMaliciousFiles" :key="'mf-' + i" class="ed-beh-row">
                          <span class="ed-file-ico">文</span>
                          <div class="ed-beh-main">
                            <b class="mono" :title="f.name">{{ f.name }}</b>
                            <small class="mono" :title="f.path">{{ f.path }}</small>
                            <small v-if="f.extra" class="mono">{{ f.extra }}</small>
                            <em v-if="f.sourceTitle" class="ed-file-src">来自：{{ f.sourceTitle }}</em>
                          </div>
                        </article>
                        <p v-if="!listMaliciousFiles.length" class="empty sm">当前关联告警中无路径/样本（如纯注册表、网络类）— 请查看「告警行为」</p>
                        <p v-else-if="listAlertBehaviors.length > listMaliciousFiles.length" class="hint sm">注册表、父链缺失等告警不会出现在此列表；每条文件均标注来源告警。</p>
                      </div>
                    </div>
                  </section>

                  <section class="ed-card" :class="{ folded: edFold.judge }">
                    <header class="ed-card-hd" @click="edFold.judge = !edFold.judge">
                      <b>威胁研判</b>
                      <i>{{ edFold.judge ? '+' : '−' }}</i>
                    </header>
                    <div v-show="!edFold.judge" class="ed-card-bd">
                      <div class="ed-kv">
                        <div><span>判定结果</span><b>{{ judgeOf(listFocusEvent) }}</b></div>
                        <div><span>处置状态</span><b>{{ statusLabel(listFocusEvent.status) }}</b></div>
                        <div>
                          <span>严重级别</span>
                          <b><span class="sev" :data-s="listFocusEvent.severity">{{ sevLabel(listFocusEvent.severity) }}</span></b>
                        </div>
                        <div><span>检测模块</span><b>{{ modLabel(listFocusEvent.module) || '—' }}</b></div>
                        <div><span>事件类型</span><b class="mono">{{ listEvidenceFlat.etype || listEventEvidence.etype || listInferredEtype || '—' }}</b></div>
                        <div><span>规则 ID</span><b class="mono">{{ listEventEvidence.rule_id || listEvidenceFlat.watch || '—' }}</b></div>
                        <div class="span2"><span>匹配特征</span><b class="mono">{{ listEventEvidence.matched || '—' }}</b></div>
                        <div class="span2"><span>首次 / 活跃</span><b>{{ fmtTime(listFocusEvent.created_at) }} · {{ fmtTime(listFocusEvent.updated_at || listFocusEvent.created_at) }}</b></div>
                      </div>
                      <div class="ed-acts">
                        <button type="button" class="btn sm primary" @click="openEvent(listFocusEvent)">威胁视图</button>
                        <button type="button" class="btn sm" @click="openAllow(listFocusEvent)">加入白名单</button>
                        <button type="button" class="btn sm danger" @click="removeEvent(listFocusEvent)">删除</button>
                        <button type="button" class="btn sm" @click="openTimelineFor(listFocusEvent.agent_id)">时间线</button>
                      </div>
                    </div>
                  </section>
                </div>
              </aside>
            </div>
          </div>
        </div>
      </section>

<section v-if="page === 'threat-view' && activeEvent" class="page threat-detail">
        <div class="tv-crumb">
          <button type="button" class="btn-text" @click="closeThreat">威胁事件</button>
          <span>/</span>
          <em>威胁事件详情：#{{ activeEvent.id }}</em>
        </div>

        <header class="tv-head">
          <div class="tv-head-main">
            <span class="tv-warn">⚠</span>
            <div>
              <h1>{{ activeEvent.title }}</h1>
              <div class="tv-meta">
                <span class="sev" :data-s="activeEvent.severity">{{ sevLabel(activeEvent.severity) }}</span>
                <span>发现 {{ fmtTime(activeEvent.created_at) }}</span>
                <span>活跃 {{ fmtTime(activeEvent.updated_at || activeEvent.created_at) }}</span>
                <span>{{ activeEvent.hostname || short(activeEvent.agent_id) }} · {{ agentIp(activeEvent.agent_id) }}</span>
              </div>
            </div>
          </div>
          <div class="tv-head-actions">
            <div class="tv-act-group">
              <span class="tv-act-label">处置</span>
              <button type="button" class="btn danger" :disabled="respBusy" @click="doResponse('kill_process')">结束进程</button>
              <button type="button" class="btn danger-outline" :disabled="respBusy" @click="doResponse('quarantine_file')">隔离文件</button>
              <button type="button" class="btn danger-outline" :disabled="respBusy" @click="doResponse('isolate_network')">网络隔离</button>
              <button type="button" class="btn" :disabled="respBusy" @click="doResponse('unisolate_network')">解除隔离</button>
              <button type="button" class="btn" :disabled="respBusy" @click="doResponse('scan_memory')">内存扫描</button>
            </div>
            <div class="tv-act-group nav">
              <button type="button" class="btn" @click="threatTab = 'response'; loadRespCommands()">处置结果</button>
              <button type="button" class="btn" @click="openTimelineFor(activeEvent.agent_id)">时间线</button>
              <button type="button" class="btn" @click="jumpToHost">终端资产</button>
              <button type="button" class="btn" @click="openAllow(activeEvent)">加入白名单</button>
              <button type="button" class="btn" @click="closeThreat">返回列表</button>
            </div>
          </div>
        </header>

        <div class="tv-tabs">
          <button type="button" class="tv-tab" :class="{ on: threatTab === 'graph' }" @click="threatTab = 'graph'">威胁视图</button>
          <button type="button" class="tv-tab" :class="{ on: threatTab === 'chain' }" @click="threatTab = 'chain'; loadThreatProcessTree()">进程链</button>
          <button type="button" class="tv-tab" :class="{ on: threatTab === 'story' }" @click="threatTab = 'story'; loadAttackStory()">攻击路线</button>
          <button type="button" class="tv-tab" :class="{ on: threatTab === 'evidence' }" @click="threatTab = 'evidence'">证据详情</button>
          <button type="button" class="tv-tab" :class="{ on: threatTab === 'response' }" @click="threatTab = 'response'; loadRespCommands()">
            处置结果
            <em v-if="respPendingCount" class="tab-n">{{ respPendingCount }}</em>
          </button>
        </div>

        <div class="tv-body">
          <div class="tv-canvas graph" v-show="threatTab === 'graph'">
            <div class="tv-graph-banner">
              <div class="tv-graph-banner-l">
                <span class="tv-chain-mark graph">视</span>
                <div class="tv-graph-banner-copy">
                  <div class="tv-graph-banner-row">
                    <span class="sev lg" :data-s="activeEvent.severity">{{ sevLabel(activeEvent.severity) }}</span>
                    <span class="tv-graph-banner-t">攻击链概览</span>
                  </div>
                  <small class="muted">{{ judgeOf(activeEvent) }} · 点击威胁命中节点查看处置</small>
                </div>
              </div>
              <div class="tv-canvas-tools">
                <span class="chip soft">逻辑关系</span>
                <span class="chip soft">{{ modLabel(activeEvent.module) || '检测模块' }}</span>
                <span v-if="eventAttck.technique" class="chip soft atk">{{ eventAttck.technique }}</span>
              </div>
            </div>
            <div class="tv-tree-bar">
              <div class="tv-tree-opts">
                <label class="tv-tree-opt"><input type="checkbox" v-model="tvShowDotted" /> 展示虚线关联</label>
                <label class="tv-tree-opt"><input type="checkbox" v-model="tvReadable" /> 增强可读性</label>
              </div>
              <button type="button" class="btn sm" :disabled="threatTreeBusy" @click="loadThreatProcessTree">{{ threatTreeBusy ? '加载中…' : '刷新进程树' }}</button>
            </div>
            <div v-if="threatDropChainSteps.length >= 2" class="tv-drop-chain">
              <div class="tv-drop-head">
                <span class="tv-drop-title">释放 / 投递链</span>
                <span class="muted">父进程 → 写文件 → 子进程（告警前后时间窗口）</span>
              </div>
              <div class="tv-drop-row">
                <template v-for="(s, i) in threatDropChainSteps" :key="s.id || i">
                  <div v-if="i > 0" class="tv-drop-edge">
                    <em>{{ threatDropEdgeLabel(i) }}</em>
                    <span class="line" />
                  </div>
                  <div
                    class="tv-drop-node"
                    :class="[s.kind, s.role, { hit: s.is_hit }]"
                    @click="s.is_hit && (threatPanelNode = 'hit')"
                  >
                    <span class="tv-drop-kind">{{ threatDropKindLabel(s) }}</span>
                    <b :title="s.path || s.name">{{ s.name }}</b>
                    <small v-if="s.kind === 'proc' && s.pid">PID {{ s.pid }}</small>
                    <small v-else-if="s.path" :title="s.path">{{ shortPath(s.path) }}</small>
                  </div>
                </template>
              </div>
            </div>
            <div class="tv-graph-wrap">
              <div class="tv-graph-stage" :style="{ transform: `scale(${tvZoom})` }">
                <p v-if="threatTreeBusy" class="empty sm">进程树加载中…</p>
                <template v-else-if="threatGraphLayout.layers.length">
                  <div class="tv-graph-host">
                    <span class="tv-host-mark">端</span>
                    <div>
                      <b>{{ activeEvent.hostname || short(activeEvent.agent_id) }}</b>
                      <small>{{ agentIp(activeEvent.agent_id) }} · {{ judgeOf(activeEvent) }}</small>
                    </div>
                  </div>
                  <div
                    class="tv-graph-scroll"
                    :style="{ width: threatGraphLayout.width + 'px', height: threatGraphLayout.height + 'px' }"
                  >
                    <svg
                      class="tv-graph-svg"
                      :class="{ dotted: tvShowDotted }"
                      :width="threatGraphLayout.width"
                      :height="threatGraphLayout.height"
                      aria-hidden="true"
                    >
                      <defs>
                        <marker
                          id="tv-graph-arrow"
                          markerWidth="8"
                          markerHeight="8"
                          refX="7"
                          refY="4"
                          orient="auto"
                          markerUnits="strokeWidth"
                        >
                          <path d="M0,0 L8,4 L0,8 z" fill="context-stroke" />
                        </marker>
                      </defs>
                      <path
                        v-for="(p, i) in threatGraphLayout.paths"
                        :key="'tg-' + i"
                        class="tv-graph-edge"
                        :class="{ repaired: p.repaired, hot: p.hot }"
                        :d="p.d"
                        fill="none"
                        :stroke="p.repaired ? '#f97316' : (p.hot ? '#f87171' : '#64748b')"
                        stroke-width="2.5"
                        stroke-linecap="round"
                        :stroke-dasharray="(tvShowDotted || p.repaired) ? '7 5' : '0'"
                        marker-end="url(#tv-graph-arrow)"
                      />
                    </svg>
                    <div class="tv-graph-cols">
                      <div
                        v-for="(col, ci) in threatGraphLayout.layers"
                        :key="'col-' + ci"
                        class="tv-graph-col"
                        :style="{ width: threatGraphLayout.colW + 'px', minHeight: threatGraphLayout.height + 'px' }"
                      >
                        <div
                          v-for="n in col"
                          :key="n.id"
                          class="tv-proc-node"
                          :class="{
                            hit: n.is_hit,
                            on: n.is_hit && threatPanelNode === 'hit',
                            readable: tvReadable,
                            missing: n.synthetic || n.missing,
                          }"
                          :style="threatNodeStyle(n.id)"
                          @click="onThreatGraphNode(n)"
                        >
                          <button
                            v-if="threatTreeHasKids(n.id)"
                            type="button"
                            class="tv-proc-fold"
                            @click.stop="toggleThreatTreeNode(n.id)"
                          >{{ tvTreeExpanded[n.id] === false ? '+' : '−' }}</button>
                          <span class="tv-proc-ico" :class="{ hit: n.is_hit }">P</span>
                          <b :title="n.name">{{ n.name }}</b>
                          <small>PID {{ n.pid }}<template v-if="n.exit_time"> · 已退出</template></small>
                          <small
                            v-if="n.command_line"
                            class="tv-proc-cmd mono"
                            :class="{ hit: n.is_hit }"
                            :title="n.command_line"
                          >{{ n.command_line }}</small>
                          <small v-else-if="n.path" class="tv-proc-cmd mono" :title="n.path">{{ n.path }}</small>
                          <em v-if="n.is_hit" class="tv-hit-tag">威胁命中</em>
                        </div>
                      </div>
                    </div>
                  </div>
                </template>
                <div v-else class="tv-flow-stage">
                  <div class="tv-flow">
                    <template v-for="(n, i) in graphNodes" :key="n.key">
                      <div v-if="i > 0" class="tvf-edge" :class="{ hot: n.tone === 'hit' }">
                        <em>{{ n.edge }}</em>
                        <span class="line" />
                      </div>
                      <div
                        class="tvf-node"
                        :class="[n.tone, { on: n.tone === 'hit' && threatPanelNode === 'hit' }]"
                        @click="n.tone === 'hit' && (threatPanelNode = 'hit')"
                      >
                        <span class="tvf-kind">{{ n.kind }}</span>
                        <b :title="n.title">{{ n.title }}</b>
                        <small v-if="n.sub" :title="n.sub">{{ n.sub }}</small>
                        <div v-if="n.meta && n.meta.length" class="tvf-meta">
                          <span v-for="m in n.meta" :key="m.k" :class="m.cls"><i>{{ m.k }}</i>{{ m.v }}</span>
                        </div>
                      </div>
                    </template>
                  </div>
                </div>
              </div>
              <aside class="tv-graph-tools">
                <button type="button" title="放大" @click="tvZoom = Math.min(1.45, +(tvZoom + 0.1).toFixed(2))">+</button>
                <button type="button" title="缩小" @click="tvZoom = Math.max(0.55, +(tvZoom - 0.1).toFixed(2))">−</button>
                <button type="button" title="重置视图" @click="tvZoom = 1">⟲</button>
              </aside>
            </div>
            <div class="tv-graph-foot">
              <div class="tvf-rule">
                <div class="tvf-rule-item span4">
                  <label>规则名称</label>
                  <b>{{ displayRuleTitle(activeEvent) }}</b>
                </div>
                <div class="tvf-rule-item span2">
                  <label>规则 ID</label>
                  <b class="mono">{{ eventEvidence.rule_id || '—' }}</b>
                </div>
                <div class="tvf-rule-item span3">
                  <label>规则来源</label>
                  <b>{{ ruleSourceLabel }}</b>
                </div>
                <div class="tvf-rule-item span3">
                  <label>判定结果</label>
                  <b class="judge">{{ judgeOf(activeEvent) }}</b>
                </div>
                <div class="tvf-rule-item wide">
                  <label>匹配特征</label>
                  <b class="mono">{{ eventEvidence.matched || evidencePath || '—' }}</b>
                </div>
                <div class="tvf-rule-item span4">
                  <label>影响终端</label>
                  <b>{{ activeEvent.hostname || short(activeEvent.agent_id) }} · {{ agentIp(activeEvent.agent_id) }}</b>
                </div>
                <div class="tvf-rule-item span4">
                  <label>ATT&CK</label>
                  <b>{{ eventAttck.technique ? techChip(eventAttck.technique, eventAttck.label) : '—' }}</b>
                </div>
                <div class="tvf-rule-item span4">
                  <label>检测模块</label>
                  <b>{{ modLabel(activeEvent.module) || '—' }}</b>
                </div>
              </div>
              <p class="tv-canvas-hint">横向进程树：点击「威胁命中」节点 · 右侧查看对象详情与处置；± 折叠子进程</p>
            </div>
          </div>

          <div class="tv-canvas chain-pane" v-show="threatTab === 'chain'">
            <div class="tv-chain-banner">
              <div class="tv-chain-banner-l">
                <span class="tv-chain-mark">链</span>
                <div>
                  <b>进程链研判</b>
                  <small>祖先 → 命中进程 · 点选节点查看详情与关联行为</small>
                </div>
              </div>
              <button type="button" class="btn sm" :disabled="threatTreeBusy" @click="loadThreatProcessTree">{{ threatTreeBusy ? '加载中…' : '刷新进程链' }}</button>
            </div>

            <div class="tv-chain-split on-page">
              <div class="tv-vchain">
                <div class="tv-vchain-hd">
                  <b>执行链</b>
                  <span class="tv-chain-count">{{ threatAncestorChain.length || 0 }} 层</span>
                </div>
                <ol v-if="threatAncestorChain.length" class="tv-vchain-list">
                  <li
                    v-for="(n, i) in threatAncestorChain"
                    :key="n.id || i"
                    class="tv-vchain-node"
                    :class="{ hit: n.is_hit, on: threatChainSelId === n.id || (!threatChainSelId && n.is_hit), miss: n.missing || n.synthetic }"
                    @click="selectThreatChainNode(n)"
                  >
                    <span class="tv-vchain-idx">{{ i + 1 }}</span>
                    <i class="tv-vchain-dot" />
                    <div class="tv-vchain-body">
                      <div class="tv-vchain-title">
                        <b :title="n.path || n.name">{{ n.name || ('PID ' + n.pid) }}</b>
                        <em v-if="n.is_hit" class="tv-hit-pill">威胁命中</em>
                        <em v-else-if="n.missing || n.synthetic" class="tv-miss-pill">推断</em>
                      </div>
                      <small>PID {{ n.pid ?? '—' }}<template v-if="n.user"> · {{ n.user }}</template></small>
                    </div>
                  </li>
                </ol>
                <p v-else class="empty sm tv-chain-empty">{{ threatTreeBusy ? '进程链加载中…' : '暂无进程链信息（告警未关联到进程实体）' }}</p>
              </div>
              <div class="tv-vchain-detail" :class="{ dual: threatChainShowDual }">
                <div class="tv-vchain-hd">
                  <b>终端行为：{{ threatChainBehaviorKind() }}</b>
                  <span class="muted mono">{{ threatChainSel?.name || '—' }}</span>
                </div>
                <div v-if="threatChainProcRows.length || threatChainTargetRows.length" class="tv-vchain-dual">
                  <section class="tv-vchain-col">
                    <h5>发起进程</h5>
                    <dl class="td-dl tv-vchain-dl">
                      <div v-for="row in threatChainProcRows" :key="'p-' + row.k" :class="{ wide: row.mono && String(row.v).length > 48 }">
                        <dt>{{ row.k }}</dt>
                        <dd :class="{ mono: row.mono }" :title="row.v">{{ row.v }}</dd>
                      </div>
                    </dl>
                  </section>
                  <section v-if="threatChainShowDual" class="tv-vchain-col target">
                    <h5>目标对象</h5>
                    <dl class="td-dl tv-vchain-dl">
                      <div v-for="row in threatChainTargetRows" :key="'t-' + row.k" :class="{ wide: row.mono && String(row.v).length > 40 }">
                        <dt>{{ row.k }}</dt>
                        <dd :class="{ mono: row.mono }" :title="row.v">{{ row.v }}</dd>
                      </div>
                    </dl>
                  </section>
                </div>
                <p v-else class="empty sm tv-chain-empty">选择左侧进程节点查看详情</p>
              </div>
            </div>

            <div class="tv-chain-below">
              <section class="tv-chain-card">
                <div class="tv-chain-card-hd">
                  <b>子进程</b>
                  <span class="tv-chain-count">{{ threatChainChildren.length }}</span>
                </div>
                <div v-if="threatChainChildren.length" class="tv-chain-kids">
                  <button
                    v-for="c in threatChainChildren"
                    :key="c.id || (c.pid + ':' + c.name)"
                    type="button"
                    class="tv-chain-kid"
                    @click="selectThreatChainNode(c)"
                  >
                    <b :title="c.path || c.name">{{ c.name || ('PID ' + c.pid) }}</b>
                    <small>PID {{ c.pid ?? '—' }}</small>
                    <small v-if="c.command_line" class="mono" :title="c.command_line">{{ c.command_line }}</small>
                  </button>
                </div>
                <p v-else class="empty sm tv-chain-empty">当前节点暂无子进程记录</p>
              </section>

              <section class="tv-chain-card wide">
                <div class="tv-chain-card-hd">
                  <b>关联行为</b>
                  <span class="tv-chain-count">{{ threatChainRelatedEvents.length }}</span>
                </div>
                <div v-if="threatChainRelatedEvents.length" class="tv-chain-evts">
                  <table>
                    <thead>
                      <tr><th>时间</th><th>类型</th><th>摘要</th><th>严重性</th></tr>
                    </thead>
                    <tbody>
                      <tr v-for="t in threatChainRelatedEvents" :key="t.id || (t.ts + t.etype + t.summary)">
                        <td class="mono muted">{{ fmtTime(t.ts) }}</td>
                        <td><span class="tv-etype">{{ etypeLabel(t.etype) }}</span></td>
                        <td :title="cleanSummary(t.summary)">{{ cleanSummary(t.summary) }}</td>
                        <td><span class="sev" :data-s="t.severity || 'info'">{{ sevLabel(t.severity || 'info') }}</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <p v-else class="empty sm tv-chain-empty">暂无该进程关联时间线（网络/文件/DNS 等）</p>
              </section>

              <section class="tv-chain-card">
                <div class="tv-chain-card-hd">
                  <b>告警上下文</b>
                  <span class="muted">规则 / 终端</span>
                </div>
                <dl class="td-dl tv-vchain-dl compact">
                  <div v-for="row in threatChainContextRows" :key="row.k">
                    <dt>{{ row.k }}</dt>
                    <dd :class="{ mono: row.mono }" :title="row.v">{{ row.v }}</dd>
                  </div>
                </dl>
                <div v-if="(relatedPayload?.items || []).length" class="tv-chain-related">
                  <h5>关联告警</h5>
                  <button
                    v-for="it in (relatedPayload.items || []).slice(0, 6)"
                    :key="it.id"
                    type="button"
                    class="tv-rel-link"
                    @click="openEventById(it.id)"
                  ><em>#{{ it.id }}</em>{{ it.title || it.summary || '' }}</button>
                </div>
              </section>
            </div>
          </div>

          <div class="tv-canvas story-pane" v-show="threatTab === 'story'">
            <div class="panel-hd bare">
              <h3>攻击路线</h3>
              <button type="button" class="btn sm" @click="loadAttackStory">刷新</button>
            </div>
            <div v-if="storyTech.length" class="story-techs">
              <span v-for="t in storyTech" :key="t.id" class="stech" :title="t.tactic || ''">{{ techChip(t.id, t.label) }}</span>
            </div>
            <div v-if="storyRouteSteps.length" class="story-route">
              <div class="story-route-hd">
                <strong>攻击路线</strong>
                <span class="muted sm">按时间串联工具/进程 · 点击步骤定位下方时间线</span>
              </div>
              <div class="story-route-scroll">
                <ol class="story-route-track">
                  <li
                    v-for="(n, i) in storyRouteSteps"
                    :key="n.id"
                    class="route-step"
                    :class="{ on: storyLaneSel === n.id, threat: n.kind === 'threat' }"
                    :data-s="n.severity || 'info'"
                  >
                    <button type="button" class="route-card" :title="n.title" @click="selectStoryLaneNode(n.id)">
                      <span class="route-seq">{{ i + 1 }}</span>
                      <span class="route-body">
                        <span class="route-top">
                          <span class="sev" v-if="n.severity && n.severity !== 'info'" :data-s="n.severity">{{ sevLabel(n.severity) }}</span>
                          <span v-if="n.tactic_name" class="route-tac">{{ n.tactic_name }}</span>
                          <time>{{ fmtTime(n.ts) }}</time>
                        </span>
                        <strong class="route-name">{{ storyRouteName(n) }}</strong>
                        <span class="route-sub">
                          <template v-if="n.technique">{{ techChip(n.technique, n.technique_label) }}</template>
                          <template v-else>{{ storyLaneShort(n.title, 28) }}</template>
                          <em v-if="n.count > 1">×{{ n.count }}</em>
                        </span>
                      </span>
                    </button>
                    <span v-if="i < storyRouteSteps.length - 1" class="route-arrow" aria-hidden="true">→</span>
                  </li>
                </ol>
              </div>
              <div v-if="storyRouteFocus" class="story-route-focus">
                <span class="sev" :data-s="storyRouteFocus.severity">{{ sevLabel(storyRouteFocus.severity) }}</span>
                <strong :title="storyRouteFocus.title">{{ storyRouteFocus.title }}</strong>
                <span class="muted">
                  {{ storyRouteFocus.tactic_name || '未映射' }}
                  <template v-if="storyRouteFocus.process_name"> · {{ storyRouteFocus.process_name }}</template>
                  · {{ fmtTime(storyRouteFocus.ts) }}
                </span>
              </div>
            </div>
            <div v-if="storyNodes.length" class="story-chain">
              <article
                v-for="(n, i) in storyNodes"
                :key="i"
                class="story-node"
                :data-k="n.kind"
                :data-i="i"
                :data-title="n.title"
                :class="{ on: storyLaneSel && storyRouteFocus?.title === n.title }"
              >
                <div class="sn-axis">
                  <i class="dot" /><span class="line" v-if="i < storyNodes.length - 1" />
                </div>
                <div class="sn-body">
                  <div class="sn-top">
                    <span class="sn-kind" :data-k="n.kind">{{ n.kind === 'threat' ? '威胁' : '时间线' }}</span>
                    <span v-if="n.technique" class="stech compact" :title="n.tactic || ''">{{ techChip(n.technique, n.technique_label) }}</span>
                    <span v-if="n.severity && n.severity !== 'info'" class="sev" :data-s="n.severity">{{ sevLabel(n.severity) }}</span>
                    <time>{{ fmtTime(n.ts) }}</time>
                  </div>
                  <h4 class="sn-title">{{ n.title }}</h4>
                  <div v-if="storyDetailPreview(n).length" class="sn-meta">
                    <span v-for="p in storyDetailPreview(n)" :key="p.k"><em>{{ p.k }}</em>{{ p.v }}</span>
                  </div>
                </div>
              </article>
            </div>
            <p v-else class="empty">暂无故事节点；主机有时间线或威胁事件后将自动串联。</p>
            <div v-if="relatedPayload?.edges?.length || relatedPayload?.items?.length" class="panel pad" style="margin-top:12px">
              <h4>载荷关联边</h4>
              <p v-if="relatedPayload.payload_key" class="mono sm muted">key {{ relatedPayload.payload_key }}</p>
              <div v-if="relatedPayload.edges?.length" class="sn-meta" style="margin:6px 0">
                <span v-for="(e, i) in relatedPayload.edges" :key="i"><em>{{ e.kind }}</em>{{ e.value }}</span>
              </div>
              <ul v-if="relatedPayload.items?.length" class="hsp-advise">
                <li v-for="it in relatedPayload.items" :key="it.id">
                  <button type="button" class="btn-text" @click="openEventById(it.id)">#{{ it.id }} {{ it.title }}</button>
                  <span class="muted sm"> · {{ it.module }} · {{ sevLabel(it.severity) }}</span>
                </li>
              </ul>
            </div>
          </div>

          <div class="tv-canvas plain" v-show="threatTab === 'evidence'">
            <div class="ev-hero">
              <div>
                <span class="sev" :data-s="activeEvent.severity">{{ sevLabel(activeEvent.severity) }}</span>
                <b>{{ activeEvent.title }}</b>
                <p>{{ alertDesc || '结合进程链、路径与签名综合研判。' }}</p>
              </div>
              <div class="ev-hero-tags">
                <span class="chip soft">{{ modLabel(activeEvent.module) || '模块' }}</span>
                <span class="chip soft">{{ ruleSourceLabel }}</span>
                <span v-if="eventAttck.technique" class="stech compact" :title="eventAttck.tactic">{{ techChip(eventAttck.technique, eventAttck.label) }}</span>
              </div>
            </div>
            <div class="ev-groups">
              <section v-for="g in evidenceGroupsFull" :key="g.title" class="ev-group">
                <h4><i :data-t="g.tone" />{{ g.title }}<em>{{ g.items.length }}</em></h4>
                <div class="ev-cards">
                  <div v-for="it in g.items" :key="it.k" class="ev-card" :class="{ wide: it.wide, mono: it.mono }">
                    <label>{{ it.label }}</label>
                    <div class="ev-val" :title="it.v">
                      <span v-if="it.badge" class="ev-badge" :data-t="it.badge">{{ it.v }}</span>
                      <template v-else>{{ it.v }}</template>
                    </div>
                    <button v-if="it.wide || it.copy" type="button" class="ev-copy" @click="copyText(it.v)">复制</button>
                  </div>
                </div>
              </section>
            </div>
            <details class="ev-raw">
              <summary>原始证据 JSON</summary>
              <pre class="raw-detail">{{ evidenceRawText }}</pre>
            </details>
          </div>

          <div class="tv-canvas" v-show="threatTab === 'response'">
            <div class="panel-hd bare">
              <h3>本机处置指令</h3>
              <button type="button" class="btn sm" @click="loadRespCommands">刷新状态</button>
            </div>
            <p class="hint" style="margin:0 0 12px">下发后由 Agent 下一心跳执行；状态：pending→sent→done/failed</p>
            <table v-if="respCommands.length">
              <thead>
                <tr><th>时间</th><th>动作</th><th>状态</th><th>参数</th><th>结果</th><th></th></tr>
              </thead>
              <tbody>
                <tr v-for="c in respCommands" :key="c.id">
                  <td>{{ fmtTime(c.updated_at || c.created_at) }}</td>
                  <td>{{ actionLabel(c.action) }}</td>
                  <td><span class="cmd-st" :data-s="c.status">{{ cmdStatusLabel(c.status) }}</span></td>
                  <td class="muted mono">{{ shortJson(c.params_json) }}</td>
                  <td class="muted" :title="c.result_json">
                    <template v-if="c.action === 'scan_memory' && c.status === 'done'">
                      扫描 {{ parseJsonSafe(c.result_json).scanned ?? 0 }} 个进程，发现 {{ parseJsonSafe(c.result_json).finding_count ?? 0 }} 处
                    </template>
                    <template v-else>{{ shortJson(c.result_json) }}</template>
                  </td>
                  <td>
                    <button
                      v-if="c.action === 'quarantine_file' && c.status === 'done'"
                      type="button"
                      class="btn-text"
                      @click="restoreQuarantined(c)"
                    >回滚</button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p v-else class="empty">暂无处置指令。点击上方红色按钮下发后，在此查看是否成功。</p>
            <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">
              <button type="button" class="btn" @click="goMenu('resp-results')">全平台处置结果 →</button>
              <button type="button" class="btn" @click="goAuditPage">打开处置审计 →</button>
            </div>
          </div>

          <aside class="tv-side">
            <div class="tvs-hd">
              <span class="tvs-file">!</span>
              <div>
                <b>{{ evidenceDesc?.title || evidenceName || activeEvent.title }}</b>
                <small>威胁视图</small>
              </div>
            </div>

            <div class="tvs-sec tvs-cmd-block">
              <h4>执行命令 / 启动项</h4>
              <pre v-if="evidenceCommandLine || evidenceFlat.script_block" class="tvs-cmd-pre mono" :title="evidenceCommandLine || evidenceFlat.script_block">{{ evidenceCommandLine || evidenceFlat.script_block }}</pre>
              <p v-else-if="evidenceFlat.reg_key || evidenceFlat.key" class="hint sm tvs-cmd-hint">
                本条为注册表类告警，无独立进程命令行。写入值：<span class="mono">{{ evidenceFlat.value || '—' }}</span>
                <template v-if="evidenceFlat.image || evidenceFlat.process_path"> · 关联进程映像 {{ evidenceFlat.image || evidenceFlat.process_path }}</template>
              </p>
              <p v-else-if="isBuildingBlockUpgrade(evidenceFlat, eventEvidence)" class="hint sm tvs-cmd-hint">
                本条为多阶段积木升级告警，无单一进程命令行；请查看下方「积木子告警」与匹配特征。
              </p>
              <p v-else class="hint sm tvs-cmd-hint">
                暂无命令行。可点「刷新进程树」从进程实体/时间线补全，或查看「匹配特征」。
                <template v-if="threatHostAgent">
                  <br><span class="capture-hint">采集能力：{{ captureCaptureHint(threatHostAgent) }}</span>
                </template>
                <span v-if="!(evidenceFlat.chain && evidenceFlat.chain.length)" class="muted"> · 本条无 PTM 规则链</span>
              </p>
              <div v-if="!(evidenceCommandLine || evidenceFlat.script_block)" class="tvs-cmd-actions">
                <button type="button" class="btn-text sm" @click="jumpThreatTimelineWindow">同主机 ±5 分钟时间线</button>
                <button type="button" class="btn-text sm" @click="huntFromEmptyCmd">按 PID/进程名狩猎</button>
              </div>
            </div>

            <div v-if="evidenceChainRows.length" class="tvs-sec tvs-chain-block">
              <h4>规则链 / 时间序</h4>
              <table class="chain-tbl">
                <thead><tr><th>#</th><th>时间</th><th>类型</th><th>摘要</th><th>命令行</th></tr></thead>
                <tbody>
                  <tr v-for="(row, idx) in evidenceChainRows" :key="idx">
                    <td>{{ idx + 1 }}</td>
                    <td class="muted">{{ row.ts || '—' }}</td>
                    <td class="mono">{{ row.etype || '—' }}</td>
                    <td>{{ row.summary || '—' }}</td>
                    <td class="mono" :title="row.command_line">{{ row.command_line || '—' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div
              v-if="isBuildingBlockUpgrade(evidenceFlat, eventEvidence) && buildingBlockHitsOf(evidenceFlat, eventEvidence).length"
              class="tvs-sec tvs-bb-block"
            >
              <h4>积木子告警（{{ buildingBlockHitsOf(evidenceFlat, eventEvidence).length }}）</h4>
              <p class="hint sm" style="margin:0 0 8px">{{ evidenceFlat.investigation || eventEvidence.investigation || '同一主机多条低置信告警升级为多阶段事件。' }}</p>
              <div class="ed-beh">
                <article
                  v-for="(h, i) in buildingBlockHitsOf(evidenceFlat, eventEvidence)"
                  :key="'bb-' + (h.event_id || i)"
                  class="ed-beh-row clickable"
                  @click="h.event_id && openEventById(h.event_id)"
                >
                  <span class="sev" :data-s="h.severity || 'medium'">{{ sevLabel(h.severity || 'medium') }}</span>
                  <div class="ed-beh-main">
                    <b :title="h.title">{{ h.title || h.rule_id || `#${h.event_id || i + 1}` }}</b>
                    <small>{{ [h.summary, h.process_name ? `${h.process_name}${h.pid != null ? ` PID ${h.pid}` : ''}` : '', h.rule_id].filter(Boolean).join(' · ') }}</small>
                    <em v-if="h.event_id">#{{ h.event_id }} · 打开详情</em>
                  </div>
                </article>
              </div>
            </div>

            <div class="tvs-sec">
              <h4>对象信息</h4>
              <dl class="td-dl">
                <template v-if="evidenceDesc && evidenceDesc.rows.length">
                  <div v-for="r in evidenceDesc.rows" :key="r.k">
                    <dt>{{ r.k }}</dt><dd :class="{ mono: r.mono }" :title="r.v">{{ r.v }}</dd>
                  </div>
                </template>
                <template v-else-if="isRegistryEvidence">
                  <div><dt>监控点</dt><dd>{{ evidenceFlat.label || evidenceName || '—' }}</dd></div>
                  <div><dt>值名</dt><dd>{{ evidenceFlat.value_name || '—' }}</dd></div>
                  <div><dt>注册表键</dt><dd class="mono" :title="evidenceFlat.key || evidenceFlat.reg_key">{{ evidenceFlat.key || evidenceFlat.reg_key || '—' }}</dd></div>
                  <div><dt>写入值</dt><dd class="mono" :title="evidenceFlat.value">{{ evidenceFlat.value != null && evidenceFlat.value !== '' ? evidenceFlat.value : '—' }}</dd></div>
                  <div v-if="evidenceFlat.old_value"><dt>旧值</dt><dd class="mono">{{ evidenceFlat.old_value }}</dd></div>
                  <div><dt>Hive</dt><dd>{{ evidenceFlat.hive || '—' }}</dd></div>
                  <div><dt>变更</dt><dd>{{ evidenceFlat.change ? evValueText('change', evidenceFlat.change) : '—' }}</dd></div>
                </template>
                <template v-else>
                  <div><dt>名称</dt><dd>{{ evidenceName || '—' }}</dd></div>
                  <div><dt>路径</dt><dd class="mono" :title="evidencePath">{{ evidencePath || '—' }}</dd></div>
                  <div v-if="evidenceCommandLine" class="span2"><dt>命令行</dt><dd class="mono" :title="evidenceCommandLine">{{ evidenceCommandLine }}</dd></div>
                  <div v-if="evidenceFlat.parent_name || evidenceFlat.ppid"><dt>父进程</dt><dd>{{ evidenceFlat.parent_name || '—' }}{{ evidenceFlat.ppid ? `（PPID ${evidenceFlat.ppid}）` : '' }}</dd></div>
                  <div v-if="evidenceFlat.user"><dt>用户</dt><dd>{{ evidenceFlat.user }}</dd></div>
                  <div v-if="evidenceFlat.signed"><dt>签名</dt><dd>{{ evValueText('signed', evidenceFlat.signed) }}</dd></div>
                  <div v-if="evidenceFlat.sha256"><dt>SHA256</dt><dd class="mono" :title="evidenceFlat.sha256">{{ evidenceFlat.sha256 }}</dd></div>
                </template>
                <div><dt>模块</dt><dd>{{ modLabel(activeEvent.module) || '—' }}</dd></div>
                <div><dt>主机</dt><dd>{{ activeEvent.hostname || short(activeEvent.agent_id) }}</dd></div>
                <div><dt>IP</dt><dd>{{ agentIp(activeEvent.agent_id) }}</dd></div>
                <div><dt>Agent</dt><dd class="mono">{{ short(activeEvent.agent_id) }}</dd></div>
                <div><dt>首次发现</dt><dd>{{ fmtTime(activeEvent.created_at) }}</dd></div>
                <div><dt>最近活跃</dt><dd>{{ fmtTime(activeEvent.updated_at) }}</dd></div>
                <div><dt>状态</dt><dd>{{ statusLabel(activeEvent.status) }}</dd></div>
              </dl>
            </div>

            <div class="tvs-sec">
              <h4>威胁信息</h4>
              <div class="intel">
                <p class="intel-tip">{{ isRegistryEvidence ? '注册表安全项被修改，请核对是否为预期变更' : '该对象被判定为规则命中 / 可疑项' }}</p>
                <span class="virus-tag">{{ activeEvent.title }}</span>
                <dl class="td-dl compact">
                  <div><dt>严重级别</dt><dd><span class="sev" :data-s="activeEvent.severity">{{ sevLabel(activeEvent.severity) }}</span></dd></div>
                  <div><dt>规则 ID</dt><dd>{{ eventEvidence.rule_id || evidenceFlat.watch || '—' }}</dd></div>
                  <div><dt>规则来源</dt><dd>{{ ruleSourceLabel }}</dd></div>
                  <div><dt>匹配特征</dt><dd class="mono">{{ eventEvidence.matched || '—' }}</dd></div>
                  <div><dt>判定结果</dt><dd>{{ judgeOf(activeEvent) }}</dd></div>
                  <div v-if="eventAttck.technique"><dt>ATT&CK</dt><dd>{{ techChip(eventAttck.technique, eventAttck.label) }}</dd></div>
                  <div v-if="eventAttck.tactic"><dt>战术</dt><dd>{{ eventAttck.tacticLabel || eventAttck.tactic }}</dd></div>
                </dl>
              </div>
            </div>

            <div class="tvs-sec" v-if="isRegistryEvidence && !evidenceDesc">
              <h4>注册表详情</h4>
              <dl class="td-dl">
                <div><dt>事件类型</dt><dd>{{ evidenceFlat.etype || eventEvidence.etype || 'registry_set' }}</dd></div>
                <div><dt>类别</dt><dd>{{ evidenceFlat.category || '—' }}</dd></div>
                <div><dt>值类型</dt><dd>{{ evidenceFlat.value_type || '—' }}</dd></div>
                <div><dt>采集来源</dt><dd>{{ evidenceFlat.source || 'reg_notify' }}</dd></div>
                <div><dt>监控规则</dt><dd>{{ evidenceFlat.watch || '—' }}</dd></div>
                <div v-if="evidenceFlat.user_sid"><dt>用户 SID</dt><dd class="mono">{{ evidenceFlat.user_sid }}</dd></div>
                <div v-if="evidenceFlat.offline"><dt>离线变更</dt><dd>是</dd></div>
              </dl>
            </div>
            <div class="tvs-sec" v-else>
              <h4>进程 / 文件</h4>
              <dl class="td-dl">
                <div><dt>命令行</dt><dd>{{ evidenceFlat.command_line || evidenceFlat.command || '—' }}</dd></div>
                <div><dt>PID</dt><dd>{{ evidenceFlat.pid ?? '—' }}</dd></div>
                <div><dt>进程名</dt><dd>{{ evidenceFlat.process_name || evidenceFlat.name || evidenceFlat.host_process || '—' }}</dd></div>
                <div v-if="evidenceFlat.path || evidenceFlat.image"><dt>路径</dt><dd class="mono" :title="evidenceFlat.path || evidenceFlat.image">{{ evidenceFlat.path || evidenceFlat.image }}</dd></div>
                <div><dt>父进程</dt><dd>{{ evidenceFlat.parent_name || '—' }} <em v-if="evidenceFlat.ppid">({{ evidenceFlat.ppid }})</em></dd></div>
                <div><dt>用户</dt><dd>{{ evidenceFlat.user || '—' }}</dd></div>
                <div><dt>签名</dt><dd>{{ evidenceFlat.signed || '—' }}</dd></div>
                <div><dt>签名者</dt><dd>{{ evidenceFlat.signer || '—' }}</dd></div>
                <div><dt>公司</dt><dd>{{ evidenceFlat.company || '—' }}</dd></div>
                <div><dt>SHA256</dt><dd class="mono">{{ evidenceFlat.sha256 || '—' }}</dd></div>
                <div><dt>事件类型</dt><dd>{{ evidenceFlat.etype || eventEvidence.etype || '—' }}</dd></div>
                <div><dt>扩展名</dt><dd>{{ evidenceFlat.ext || '—' }}</dd></div>
                <div><dt>大小</dt><dd>{{ evidenceFlat.size_kb != null ? `${evidenceFlat.size_kb} KB` : (evidenceFlat.size ?? '—') }}</dd></div>
              </dl>
            </div>

            <div class="tvs-sec" v-if="sideExtraFields.length">
              <h4>更多字段</h4>
              <dl class="td-dl">
                <div v-for="it in sideExtraFields" :key="it.k">
                  <dt>{{ it.label }}</dt>
                  <dd :title="it.v">{{ it.v }}</dd>
                </div>
              </dl>
            </div>
          </aside>
        </div>
      </section>

<section v-if="page === 'hosts' && !selected" class="page hosts-page">
        <header class="page-hd">
          <div>
            <h1>终端列表</h1>
            <p class="desc">接入主机一览；可按业务分组筛选，点主机查看进程 / 服务 / 网络等模块</p>
          </div>
          <div class="hd-right">
            <input v-model="q" class="search" placeholder="搜索主机 / IP / 分组…" />
            <button type="button" class="btn" @click="goMenu('groups')">管理分组</button>
            <button type="button" class="btn primary" @click="refresh(); loadGroups()">刷新</button>
          </div>
        </header>

        <div class="host-summary">
          <div class="hs"><span>全部</span><b>{{ agents.length }}</b></div>
          <div class="hs on"><span>在线</span><b>{{ onlineCount }}</b></div>
          <div class="hs off"><span>离线</span><b>{{ agents.length - onlineCount }}</b></div>
          <div class="hs danger"><span>有告警</span><b>{{ hostsWithAlert }}</b></div>
        </div>

        <div class="host-group-bar">
          <button type="button" class="hg-chip" :class="{ on: hostGroupFilter === '' }" @click="hostGroupFilter = ''">
            全部 <em>{{ agents.length }}</em>
          </button>
          <button type="button" class="hg-chip" :class="{ on: hostGroupFilter === '__none__' }" @click="hostGroupFilter = '__none__'">
            未分组 <em>{{ agents.filter((a) => !groupsOfAgent(a.agent_id).length).length }}</em>
          </button>
          <button
            v-for="g in groupItems"
            :key="g.id"
            type="button"
            class="hg-chip"
            :class="{ on: String(hostGroupFilter) === String(g.id) }"
            @click="hostGroupFilter = String(g.id)"
          >
            {{ g.name }} <em>{{ (g.agent_ids || []).length }}</em>
          </button>
          <span v-if="!groupItems.length" class="hg-empty">
            还没有业务分组，可点「管理分组」创建（如财务 / 研发）
          </span>
        </div>

        <div class="panel host-panel">
          <div class="host-table">
            <div class="ht-head">
              <span>主机</span><span>分组</span><span>系统</span><span>IP</span><span>状态</span><span>最近心跳</span><span>版本</span><span>告警</span><span>操作</span>
            </div>
            <template v-for="sec in hostPageData.sections" :key="sec.key">
              <div class="ht-group-hd">
                <b>{{ sec.name }}</b>
                <em>{{ sec.total }} 台</em>
              </div>
              <div
                v-for="a in sec.agents"
                :key="sec.key + ':' + a.agent_id"
                class="ht-row"
              >
                <span class="ht-host">
                  <i :class="['dot', a.online ? 'on' : '']" />
                  <b>{{ a.hostname || short(a.agent_id) }}</b>
                </span>
                <span class="ht-group">
                  <select
                    class="ht-group-sel"
                    :value="agentPrimaryGroupId(a.agent_id)"
                    :disabled="!isAdmin || groupBusy"
                    :title="isAdmin ? '更改业务分组（在线/离线均可）' : '仅管理员可改分组'"
                    @click.stop
                    @change="onHostGroupChange(a, $event.target.value)"
                  >
                    <option value="">未分组</option>
                    <option v-for="g in groupItems" :key="g.id" :value="String(g.id)">{{ g.name }}</option>
                  </select>
                </span>
                <span>{{ a.os_family || '—' }}</span>
                <span class="mono">{{ a.ip || '—' }}</span>
                <span><em class="pill" :class="{ on: a.online }">{{ a.online ? '在线' : '离线' }}</em></span>
                <span class="muted">{{ fmtTime(a.last_seen) }}</span>
                <span>{{ a.version || '—' }}<em v-if="a.outdated" class="pill warn" title="落后于当前发布版本" style="margin-left:4px">可升级</em></span>
                <span>
                  <em v-if="alertCount(a.agent_id)" class="alert-n">{{ alertCount(a.agent_id) }}</em>
                  <em v-else class="muted">0</em>
                </span>
                <span class="ops">
                  <button type="button" class="btn sm" @click="openHost(a, 'hosts')">查看主机</button>
                  <button type="button" class="btn sm" :disabled="!a.online" @click="uninstallHost(a)">远程卸载</button>
                  <button type="button" class="btn sm danger" @click="removeHost(a)">删除记录</button>
                </span>
              </div>
            </template>
            <p v-if="!filteredAgents.length" class="empty">暂无终端，请先部署安装包</p>
          </div>
          <PagedListFooter :page-data="hostPageData" :page-size="hostPageSize"
            @size-change="hostPageSize = $event" @page-change="hostPage = $event" />
        </div>
      </section>

<section v-if="page === 'hosts' && selected" class="page host-detail">
        <header class="host-hdr">
          <div class="host-hdr-top">
            <div class="host-hdr-id">
              <button type="button" class="btn sm ghost host-back" @click="backFromHost">← 返回</button>
              <div class="host-hdr-title">
                <h1>{{ selected.hostname || selected.agent_id }}</h1>
                <p class="host-hdr-meta">
                  <i :class="['dot', selected.online ? 'on' : '']" />
                  <em class="pill" :class="{ on: selected.online }">{{ selected.online ? '在线' : '离线' }}</em>
                  <span>{{ selected.ip || '—' }}</span>
                  <span>心跳 {{ fmtTime(selected.last_seen) }}</span>
                  <span>Agent v{{ selected.version || '—' }}</span>
                  <em v-if="selected.revoked" class="pill warn">凭据已吊销</em>
                </p>
              </div>
            </div>
            <div class="host-hdr-acts">
              <span class="sync-pill" :class="{ on: selected.online }">
                <i class="sync-dot" />
                {{ selected.online ? '实时同步' : '离线' }}
              </span>
              <button type="button" class="btn" :disabled="diagBusy || !selected.online" @click="requestDiagnostics(selected)">
                {{ diagBusy ? '诊断中…' : '诊断包' }}
              </button>
              <button type="button" class="btn primary" @click="refreshHostDetail">刷新</button>
              <div class="host-more">
                <button type="button" class="btn" :class="{ on: hostHdrMore }" @click="hostHdrMore = !hostHdrMore">更多 ▾</button>
                <div v-if="hostHdrMore" class="host-more-menu" @click.stop>
                  <label class="host-more-tags">
                    <span>标签</span>
                    <input v-model="hostTagEdit" class="field" placeholder="逗号分隔" @focus="hostTagEdit = (tagMap[selected.agent_id] || []).join(',')" />
                    <button type="button" class="btn sm" @click="saveHostTags(selected); hostHdrMore = false">保存</button>
                  </label>
                  <button type="button" class="host-more-item" :disabled="!selected.online" @click="uninstallHost(selected); hostHdrMore = false">远程卸载</button>
                  <button v-if="isAdmin && selected.has_secret" type="button" class="host-more-item" @click="toggleRevoke(selected); hostHdrMore = false">
                    {{ selected.revoked ? '恢复凭据' : '吊销凭据' }}
                  </button>
                  <button type="button" class="host-more-item danger" @click="removeHost(selected); hostHdrMore = false">删除记录</button>
                </div>
              </div>
            </div>
          </div>

          <div class="host-hdr-stats">
            <span v-for="c in hostQuickStats(selected)" :key="c.k" class="hchip" :class="{ warn: c.warn }" :title="c.title || ''">{{ c.k }} {{ c.v }}</span>
            <span
              v-for="c in componentWarnChips(selected).slice(0, 3)"
              :key="'cw-' + c.k"
              class="hchip warn"
              :title="c.message || ''"
            >{{ c.k }} {{ c.state }}</span>
            <button
              v-if="hostSensorsPanel(selected)"
              type="button"
              class="host-health-toggle"
              :class="{ warn: (hostSensorsPanel(selected).advise?.length || 0) > 0 || hostSensorsPanel(selected).level === 'poor' }"
              @click="hostHealthOpen = !hostHealthOpen"
            >
              采集健康 {{ hostSensorsPanel(selected).score ?? '—' }}
              <em>{{ hostHealthOpen ? '▾' : '▸' }}</em>
            </button>
          </div>

          <div v-if="hostHealthOpen && hostSensorsPanel(selected)" class="host-health-card open">
            <div class="host-health-body">
              <div class="hsp-row">
                <span class="hsp-score" :data-lv="hostSensorsPanel(selected).level">{{ hostSensorsPanel(selected).score ?? '—' }}</span>
                <span class="hsp-chip">{{ hostSensorsPanel(selected).pipeline }}</span>
                <span v-if="hostSensorsPanel(selected).cmdFill != null" class="hsp-chip">cmd {{ hostSensorsPanel(selected).cmdFill }}%</span>
                <span v-if="hostSensorsPanel(selected).loadLine" class="hsp-chip">{{ hostSensorsPanel(selected).loadLine }}</span>
                <span v-if="hostSensorsPanel(selected).hostMemoryLine" class="hsp-chip">{{ hostSensorsPanel(selected).hostMemoryLine }}</span>
                <span v-if="hostSensorsPanel(selected).disks" class="hsp-chip" :class="{ warn: String(hostSensorsPanel(selected).disks).includes('100%') }">{{ hostSensorsPanel(selected).disks }}</span>
                <span v-if="hostSensorsPanel(selected).netLine" class="hsp-chip">{{ hostSensorsPanel(selected).netLine }}</span>
              </div>
              <div v-if="hostSensorsPanel(selected).statusChips?.length" class="hsp-row hsp-chips">
                <span
                  v-for="(c, i) in hostSensorsPanel(selected).statusChips"
                  :key="i"
                  class="hsp-chip"
                  :class="{ warn: c.warn, ok: c.ok }"
                  :title="c.title || ''"
                >{{ c.label }}</span>
              </div>
              <ComponentHealthMatrix :rows="componentHealthChips(selected)" />
              <div v-if="capabilityStatusChips(selected).length" class="hsp-row hsp-chips" style="flex-wrap:wrap;margin-top:8px">
                <span class="hsp-label">能力</span>
                <span
                  v-for="c in capabilityStatusChips(selected)"
                  :key="'cap-' + c.id"
                  class="hsp-chip"
                  :class="{ warn: c.warn, ok: !c.warn }"
                  :title="(c.label || '') + (c.message ? ' · ' + c.message : '')"
                >{{ c.id }} · {{ c.label }}</span>
              </div>
              <ResourceTrend :agent="selected" />
              <ResourceBudget :health="selected?.health" />
              <div v-if="hostSensorsPanel(selected).channelChips?.length" class="hsp-row hsp-channels">
                <span class="hsp-label">Winlog</span>
                <span v-for="ch in hostSensorsPanel(selected).channelChips" :key="ch" class="hsp-chip soft">{{ ch }}</span>
              </div>
              <div v-if="hostSensorsPanel(selected).sysmonChips?.length" class="hsp-row hsp-channels">
                <span class="hsp-label">Sysmon</span>
                <span
                  v-for="(c, i) in hostSensorsPanel(selected).sysmonChips"
                  :key="'sm-' + i"
                  class="hsp-chip soft"
                  :title="c.title || ''"
                >{{ c.label }}</span>
              </div>
              <div v-if="healthChips(selected).length" class="hsp-row hsp-chips">
                <span class="hsp-label">运行</span>
                <span v-for="c in healthChips(selected)" :key="'hc-' + c.k" class="hsp-chip" :class="{ warn: c.warn }" :title="c.title || ''">{{ c.k }} {{ c.v }}</span>
              </div>
              <div v-if="hostSensorsPanel(selected).byKindLine" class="hsp-row mono sm muted">outbox {{ hostSensorsPanel(selected).byKindLine }}</div>
              <p v-if="agentDriftLine(selected)" class="hsp-drift">{{ agentDriftLine(selected) }}</p>
              <ul v-if="hostSensorsPanel(selected).advise?.length" class="hsp-advise">
                <li v-for="(a, i) in hostSensorsPanel(selected).advise" :key="i">{{ a }}</li>
              </ul>
            </div>
          </div>
        </header>

        <div class="snap-shell">
          <nav class="host-group-nav">
            <button
              v-for="g in HOST_TAB_GROUPS"
              :key="g.id"
              type="button"
              class="host-group-btn"
              :class="{ on: hostTabGroup === g.id }"
              @click="selectHostGroup(g.id)"
            >{{ g.label }}</button>
          </nav>
          <nav v-if="hostTabGroup !== 'remote'" class="mod-tabs bar">
            <button
              v-for="m in hostGroupMods"
              :key="m"
              type="button"
              class="mod-tab"
              :class="{ on: module === m }"
              @click="loadSnap(m)"
            >{{ modLabel(m) }}</button>
          </nav>

          <RemoteWorkbench
            v-if="hostTabGroup === 'remote' && selected"
            :agent-id="selected.agent_id"
            :hostname="selected.hostname || ''"
            :online="!!selected.online"
            :is-admin="!!isAdmin"
          />

          <template v-if="hostTabGroup !== 'remote'">
          <div class="snap-flags">
            <span v-for="f in snapStats.flags" :key="f.k" class="sflag" :data-t="f.tone">{{ f.label }}</span>
            <span class="sflag muted">共 {{ snapStats.total }} 条 · 同步 {{ fmtTime(snap?.collected_at) }}</span>
            <span v-if="columns.length" class="sflag muted">展示 {{ columns.length }} 列</span>
            <span v-if="snapNoiseHiddenCount > 0 && snapView === 'hide_noise'" class="sflag muted">
              已隐藏噪声 {{ snapNoiseHiddenCount }}
            </span>
          </div>
          <div class="snap-viewbar" v-if="module !== 'sysinfo' && hostTabGroup === 'runtime'">
            <button type="button" class="tl-fchip" :class="{ on: snapView === 'all' }" @click="snapView = 'all'">全部</button>
            <button type="button" class="tl-fchip" :class="{ on: snapView === 'risk' }" data-k="file" @click="snapView = 'risk'">
              仅可疑 <em>{{ snapRiskCount }}</em>
            </button>
            <button type="button" class="tl-fchip" :class="{ on: snapView === 'hide_noise' }" @click="snapView = 'hide_noise'">
              隐藏系统噪声
            </button>
            <span class="meta">{{ snapModuleHint }}</span>
          </div>
          <div class="snap-viewbar" v-else-if="module !== 'sysinfo' && hostTabGroup === 'inventory'">
            <span class="meta">资产清单：软件 / 补丁 / 监听端口 / 用户 · 与检测态分离</span>
          </div>

          <div class="snap-work has-detail">
            <div class="panel snap-list">
              <div class="panel-hd">
                <div>
                  <h3>{{ modLabel(module) }}</h3>
                  <span class="meta" v-if="snap">
                    最近同步 {{ fmtTime(snap.collected_at) }} · {{ filteredSnapRows.length }} / {{ (snap.items || []).length }} 条
                    · {{ liveOk ? `已连接 · ${liveAgo}` : '同步中' }}
                  </span>
                </div>
                <input
                  v-if="module !== 'sysinfo'"
                  v-model="snapQ"
                  class="search"
                  placeholder="搜索名称 / 路径 / 命令 / DLL…"
                />
              </div>

              <div v-if="snapLoading" class="empty">加载中…</div>
              <div v-else-if="snapError" class="empty err">
                <p>{{ snapError }}</p>
                <p v-if="snapModuleStatus" class="hint snap-collect-status">{{ snapStatusMessage }}</p>
                <p v-if="!snapModuleStatus" class="hint">尚无可用快照，请检查最近采集状态</p>
              </div>
              <div v-else-if="module === 'sysinfo'" class="sysinfo-grid">
                <div v-for="(v, k) in (snap?.items?.[0] || {})" :key="k" class="si-item">
                  <label>{{ colLabel(k) }}</label>
                  <div>{{ cell({ [k]: v }, k) }}</div>
                </div>
                <p v-if="!(snap?.items || []).length" class="empty">暂无系统信息</p>
                <p v-if="snapModuleStatus" class="hint snap-collect-status">{{ snapStatusMessage }}</p>
              </div>
              <div v-else class="table-scroll snap-table">
                <table>
                  <thead>
                    <tr>
                      <th v-for="c in columns" :key="c">{{ colLabel(c) }}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="(row, i) in filteredSnapRows"
                      :key="i"
                      class="row-click"
                      :class="{ active: snapRow === row }"
                      @click="snapRow = row"
                    >
                      <td v-for="c in columns" :key="c" :title="cell(row, c)">{{ cell(row, c) }}</td>
                    </tr>
                  </tbody>
                </table>
                <p v-if="!(snap?.items || []).length" class="empty">{{ snapStatusMessage }}</p>
                <p v-if="snapModuleStatus" class="hint snap-collect-status">{{ snapStatusMessage }}</p>
                <p v-else-if="!filteredSnapRows.length" class="empty">无匹配结果</p>
              </div>
            </div>

            <aside class="panel snap-detail">
              <template v-if="module === 'sysinfo' && (snap?.items?.[0])">
                <div class="sd-hd">
                  <div>
                    <b>系统信息</b>
                    <small>完整字段</small>
                  </div>
                </div>
                <dl class="sd-dl">
                  <div v-for="(v, k) in snap.items[0]" :key="k">
                    <dt>{{ colLabel(k) }}</dt>
                    <dd>{{ v == null || v === '' ? '—' : String(v) }}</dd>
                  </div>
                </dl>
              </template>
              <template v-else-if="snapRow">
                <div class="sd-hd">
                  <div>
                    <b>{{ rowTitle(snapRow) }}</b>
                    <small>{{ modLabel(module) }} · 共 {{ Object.keys(snapRow).length }} 个字段</small>
                  </div>
                  <button type="button" class="icon-x" @click="snapRow = null">×</button>
                </div>
                <div class="sd-groups">
                  <div v-for="g in detailGroups(snapRow)" :key="g.title" class="sd-group">
                    <h4>{{ g.title }}</h4>
                    <dl class="sd-dl compact-gap">
                      <div v-for="(v, k) in g.fields" :key="k">
                        <dt>{{ colLabel(k) }}</dt>
                        <dd :title="String(v ?? '')">{{ formatDetail(v) }}</dd>
                      </div>
                    </dl>
                  </div>
                </div>
                <div class="sd-actions" v-if="snapRow && (module === 'process' || module === 'file')">
                </div>
                <div class="sd-actions" v-if="module === 'process' && snapRow">
                  <h4>进程关系</h4>
                  <dl class="sd-dl compact-gap">
                    <div>
                      <dt>父进程</dt>
                      <dd>
                        <button
                          v-if="snapRow.parent_name || snapRow.ppid"
                          type="button"
                          class="btn-text"
                          @click="jumpToPid(snapRow.ppid)"
                        >{{ snapRow.parent_name || '—' }} ({{ snapRow.ppid }})</button>
                        <span v-else>—</span>
                      </dd>
                    </div>
                    <div v-if="snapRow.risk_tags">
                      <dt>风险标签</dt>
                      <dd>{{ snapRow.risk_tags }}</dd>
                    </div>
                    <div v-if="snapRow.module_count != null">
                      <dt>模块数</dt>
                      <dd>共 {{ snapRow.module_count }} · 第三方/可疑 {{ snapRow.module_third_count || processDlls.length }}</dd>
                    </div>
                  </dl>
                  <div v-if="childProcesses.length" class="child-list">
                    <small>子进程 ({{ childProcesses.length }})</small>
                    <button
                      v-for="c in childProcesses"
                      :key="c.pid"
                      type="button"
                      class="child-row"
                      @click="snapRow = c"
                    >
                      <b>{{ c.name }}</b>
                      <em>PID {{ c.pid }}</em>
                    </button>
                  </div>
                  <div v-if="processDlls.length" class="dll-list">
                    <small>已加载 DLL（已过滤 System32）· {{ processDlls.length }} · 点击查看详情</small>
                    <button
                      v-for="(d, i) in processDlls"
                      :key="i"
                      type="button"
                      class="dll-row"
                      :class="{ hot: d.hot || d.unsigned, on: selectedDll === d }"
                      @click="selectedDll = selectedDll === d ? null : d"
                    >
                      <b :title="d.path">{{ d.name || '—' }}</b>
                      <em :title="d.path">{{ shortPath(d.path || '') }}</em>
                      <span v-if="d.hot" class="sev" data-s="high">可疑路径</span>
                      <span v-else-if="d.unsigned" class="sev" data-s="medium">未签名</span>
                      <span v-else-if="d.signed" class="sev" data-s="info">{{ d.signed }}</span>
                    </button>
                    <div v-if="selectedDll" class="dll-detail">
                      <h5>{{ selectedDll.name || '模块详情' }}</h5>
                      <dl class="sd-dl compact-gap">
                        <div><dt>模块名</dt><dd>{{ selectedDll.name || '—' }}</dd></div>
                        <div><dt>完整路径</dt><dd class="mono" :title="selectedDll.path">{{ selectedDll.path || '—' }}</dd></div>
                        <div><dt>签名</dt><dd>
                          <span class="sev" :data-s="selectedDll.unsigned ? 'medium' : (selectedDll.signed === 'Valid' ? 'info' : 'low')">
                            {{ selectedDll.signed || '—' }}
                          </span>
                        </dd></div>
                        <div v-if="selectedDll.signer"><dt>签名者</dt><dd :title="selectedDll.signer">{{ selectedDll.signer }}</dd></div>
                        <div v-if="selectedDll.company"><dt>公司</dt><dd>{{ selectedDll.company }}</dd></div>
                        <div v-if="selectedDll.file_version"><dt>文件版本</dt><dd>{{ selectedDll.file_version }}</dd></div>
                        <div v-if="selectedDll.size"><dt>大小</dt><dd>{{ fmtSize(selectedDll.size) }}</dd></div>
                        <div v-if="selectedDll.sha256"><dt>SHA256</dt><dd class="mono" :title="selectedDll.sha256">{{ selectedDll.sha256 }}</dd></div>
                        <div v-if="selectedDll.hot"><dt>风险</dt><dd><span class="sev" data-s="high">可疑路径</span></dd></div>
                      </dl>
                      <div class="row" style="margin-top:8px;gap:8px">
                        <button v-if="selectedDll.path" type="button" class="btn sm" @click="copyText(selectedDll.path)">复制路径</button>
                        <button v-if="selectedDll.sha256" type="button" class="btn sm" @click="copyText(selectedDll.sha256)">复制哈希</button>
                      </div>
                    </div>
                  </div>
                  <p v-else-if="snapRow.module_count" class="hint">该进程模块均为系统目录 DLL，或尚未完成模块采集（请「立即刷新」）。</p>
                </div>
                <div class="sd-actions" v-if="(module === 'service' || module === 'task') && snapRow">
                  <h4>风险研判</h4>
                  <dl class="sd-dl compact-gap">
                    <div><dt>风险分</dt><dd>{{ snapRow.risk_score ?? 0 }}</dd></div>
                    <div><dt>标签</dt><dd>{{ snapRow.risk_tags || (snapRow.noise ? '系统噪声' : '—') }}</dd></div>
                    <div><dt>系统噪声</dt><dd>{{ snapRow.noise ? '是（可隐藏）' : '否' }}</dd></div>
                  </dl>
                </div>
                <div class="sd-actions" v-if="(module === 'service' || module === 'network') && snapRow?.pid">
                  <button type="button" class="btn sm" @click="jumpToPid(snapRow.pid)">跳转到进程 PID {{ snapRow.pid }}</button>
                </div>
                <div class="sd-actions" v-if="hostTabGroup === 'runtime' && rowRelatedAlerts(snapRow).length">
                  <h4>跳转检测</h4>
                  <button
                    v-for="e in rowRelatedAlerts(snapRow)"
                    :key="e.id"
                    type="button"
                    class="ha-row"
                    @click="openEvent(e)"
                  >
                    <span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span>
                    <span class="strong">{{ e.title }}</span>
                  </button>
                </div>
              </template>
              <div v-else class="snap-sum">
                <div class="sd-hd">
                  <div>
                    <b>{{ modLabel(module) }} 模块摘要</b>
                    <small>{{ hostTabGroup === 'inventory' ? '资产字段概览' : '点击左侧行查看完整字段' }}</small>
                  </div>
                </div>
                <div class="ss-kpis">
                  <div><span>条目</span><strong>{{ snapStats.total }}</strong></div>
                  <div v-if="snapStats.unsigned != null"><span>未签名</span><strong class="c-danger">{{ snapStats.unsigned }}</strong></div>
                  <div v-if="snapStats.hotpath != null"><span>可疑路径</span><strong class="c-warn">{{ snapStats.hotpath }}</strong></div>
                  <div v-if="snapStats.admins != null"><span>管理员身份</span><strong>{{ snapStats.admins }}</strong></div>
                  <div v-if="snapStats.fields"><span>字段数</span><strong>{{ snapStats.fields }}</strong></div>
                </div>
                <div v-if="hostTabGroup === 'runtime' && hostAlerts.length" class="ss-list">
                  <h4>检测入口</h4>
                  <button type="button" class="ss-row" @click="openSelectedHostThreats">
                    <span class="sev" data-s="high">威胁</span>
                    <b>本机威胁事件 {{ hostAlerts.length }}</b>
                    <small>打开检测 → 威胁事件</small>
                  </button>
                  <button type="button" class="ss-row" @click="goMenu('timeline'); tlAgentId = selected?.agent_id || ''; loadTimeline()">
                    <span class="sev" data-s="info">时间线</span>
                    <b>主机时间线</b>
                    <small>打开检测 → 主机时间线</small>
                  </button>
                </div>
                <div v-if="snapStats.hotRows.length" class="ss-list">
                  <h4>关注项</h4>
                  <button
                    v-for="(r, i) in snapStats.hotRows"
                    :key="i"
                    type="button"
                    class="ss-row"
                    @click="snapRow = r.row"
                  >
                    <span class="sev" :data-s="r.sev">{{ r.tag }}</span>
                    <b>{{ r.title }}</b>
                    <small>{{ r.sub }}</small>
                  </button>
                </div>
                <div v-if="snapStats.sampleRows.length" class="ss-list">
                  <h4>最近条目</h4>
                  <button
                    v-for="(r, i) in snapStats.sampleRows"
                    :key="'s'+i"
                    type="button"
                    class="ss-row"
                    @click="snapRow = r.row"
                  >
                    <span class="sev" data-s="info">条目</span>
                    <b>{{ r.title }}</b>
                    <small>{{ r.sub }}</small>
                  </button>
                </div>
                <p v-else-if="!snapStats.hotRows.length" class="empty sm">本模块暂无高亮项，可在左侧点行查看详情</p>
                <div class="ss-acts">
                  <button type="button" class="btn sm" @click="openTimelineFor(selected.agent_id)">本机时间线</button>
                  <button type="button" class="btn sm" @click="openHostThreats(selected)">本机威胁</button>
                </div>
              </div>
            </aside>
          </div>
          </template>
        </div>
      </section>

<section v-if="false && page === 'deploy'" class="page deployment-page" aria-hidden="true">
        <header class="page-hd">
          <div>
            <h1>安装包下载</h1>
            <p class="desc">按操作系统和 CPU 架构选择安装包，查看当前版本与终端接入状态。</p>
          </div>
        </header>
        <div v-if="(dlBusy && dlProgress) || dlError" class="deployment-feedback" :class="{ 'is-error': dlError }" :role="dlError ? 'alert' : 'status'">{{ dlError || dlProgress }}</div>
        <div class="deployment-grid">
          <article class="panel pad deployment-card windows-package">
            <div class="deployment-card-heading"><span class="os-mark windows-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h8v8H3zm10 0h8v8h-8zM3 14h8v7H3zm10 0h8v7h-8z"/></svg></span><div><h3>Windows 安装包</h3><small>x64 · x86 · ARM64</small></div></div>
            <p>当前提供脚本 ZIP 安装包，未独立验明的原生安装器与 MSI 暂不分发。包内包含驱动不代表终端已安装或加载驱动。</p>
            <div class="rel-act arch-picker">
              <label for="windows-agent-arch">Windows 目标架构</label>
              <select id="windows-agent-arch" v-model="releaseArch" @change="loadRelease">
                <option value="amd64">x64</option>
                <option value="386">x86</option>
                <option value="arm64">ARM64</option>
              </select>
            </div>
            <div v-if="release" class="rel-box" :class="'rel-' + release.status">
              <div class="rel-hd">
                <span class="pill" :class="{ on: release.is_latest }">{{ releaseLabel }}</span>
                <b v-if="release.version">v{{ release.version }}</b>
                <span v-if="release.build_id" class="muted mono">{{ release.build_id }}</span>
              </div>
              <div v-if="release.exe_sha256" class="rel-line">SHA256 <code class="mono">{{ release.exe_sha256.slice(0, 24) }}…</code></div>
              <div v-if="release.build_time" class="rel-line">构建时间 {{ release.build_time }}</div>
              <div v-if="release.protocol_max" class="rel-line">协议 v{{ release.protocol_min }}–v{{ release.protocol_max }} · 能力 {{ (release.capabilities || []).length }} 项</div>
              <div class="rel-line">安装包接入地址：{{ release.effective_server_url || '未配置有效地址' }}</div>
              <details v-if="release.capabilities?.length"><summary>构建声明能力</summary><p class="mono">{{ release.capabilities.join(' · ') }}</p></details>
              <div v-for="r in (release.reasons || [])" :key="r" class="rel-warn">{{ r }}</div>
              <div class="rel-act">
                <button type="button" class="btn" :disabled="releaseBusy || release.building || !release.go_available" @click="doBuildRelease">
                  {{ release.building ? '构建中…' : '重新构建 Agent' }}
                </button>
                <span v-if="!release.go_available" class="muted">服务器未检测到 Go</span>
              </div>
            </div>
            <button type="button" class="btn primary lg" :disabled="dlBusy" style="margin-top:12px" @click="doDownload">
              {{ dlBusy ? '下载中…' : (release && !release.is_latest ? '仍然下载（非最新）' : '下载静默安装包') }}
            </button>
          </article>
          <article class="panel pad deployment-card linux-package">
              <div class="deployment-card-heading"><span class="os-mark linux-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="5" width="18" height="14" rx="3"/><path d="m7 9 3 3-3 3m6 0h4"/></svg></span><div><h3>Linux 安装包</h3><small>x64 · ARM64 · LoongArch64 · RISC-V64</small></div></div>
              <p class="muted">下载后解压并运行 <code>sudo ./install.sh</code>，脚本会配置并启动 systemd 服务。</p>
              <div class="rel-act">
                <button type="button" class="btn" :disabled="dlBusy" @click="doDownloadLinux('amd64')">下载 Linux x64</button>
                <button type="button" class="btn" :disabled="dlBusy" @click="doDownloadLinux('arm64')">下载 Linux ARM64</button>
                <button type="button" class="btn" :disabled="dlBusy" @click="doDownloadLinux('loong64')">下载 Linux LoongArch64</button>
                <button type="button" class="btn" :disabled="dlBusy" @click="doDownloadLinux('riscv64')">下载 Linux RISC-V64</button>
              </div>
          </article>
          <article class="panel pad deployment-card credentials-card">
            <h3>终端凭据</h3>
            <p>每台终端首次注册后获得专属凭据（仅存哈希），共享接入密钥只用于首次注册。</p>
            <template v-if="credSummary">
            <div class="rel-line">终端 {{ credSummary.total }} 台 · 已用专属凭据 <b>{{ credSummary.with_secret }}</b> · 已吊销 <b>{{ credSummary.revoked }}</b></div>
            <div v-if="credSummary.total > credSummary.with_secret" class="rel-warn">
              {{ credSummary.total - credSummary.with_secret }} 台仍是旧版终端（共享密钥），升级 Agent 后自动迁移
            </div>
            <div class="rel-act">
              <button type="button" class="btn" :disabled="credBusy" @click="toggleSharedKey">
                {{ credSummary.allow_shared_key ? '禁止共享密钥上报' : '允许共享密钥上报' }}
              </button>
              <span class="muted">{{ credSummary.allow_shared_key ? '当前：兼容旧终端' : '当前：仅专属凭据可上报' }}</span>
            </div>
            </template>
            <p v-else class="deployment-empty">暂无凭据统计</p>
          </article>
          <article class="panel pad deployment-card install-guide">
            <h3>安装步骤</h3>
            <ol>
              <li>解压到目标机任意目录</li>
              <li>右键 <code>install.vbs</code> → 以管理员身份运行</li>
              <li>完成后查看弹窗与 install.log</li>
              <li>服务 ForensicAgent 自动启动并回连</li>
              <li>卸载：管理员运行 <code>uninstall.bat</code></li>
            </ol>
          </article>
        </div>
      </section>
</template>

<script>
import { defineAsyncComponent } from 'vue'
import { forwardSetupContext } from './setupContext.js'
const ComponentHealthMatrix = defineAsyncComponent(() => import('./ComponentHealthMatrix.vue'))
const PagedListFooter = defineAsyncComponent(() => import('./PagedListFooter.vue'))
const RemoteWorkbench = defineAsyncComponent(() => import('./RemoteWorkbench.vue'))
const ResourceBudget = defineAsyncComponent(() => import('./ResourceBudget.vue'))
const ResourceTrend = defineAsyncComponent(() => import('./ResourceTrend.vue'))
export default {
  components: { ComponentHealthMatrix, PagedListFooter, RemoteWorkbench, ResourceBudget, ResourceTrend },
  props: { context: { type: Object, required: true } },
  setup(props) { return forwardSetupContext(props.context) },
}
</script>
