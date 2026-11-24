import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import * as Vue from 'vue'
import { parse } from 'vue/compiler-sfc'
import { compile } from '@vue/compiler-dom'
import { renderToString } from 'vue/server-renderer'
import { hostEvidenceStatus } from './hostEvidenceStatus.js'
import { rowTitle, detailGroups } from './hostSnapshotDisplay.js'
import { colLabel as columnLabel, modLabel as moduleLabel, formatDetail } from './consoleDisplay.js'
import { deferredConsolePage } from './deferredConsolePage.js'
import { useNavigationMenu } from './composables/useNavigationMenu.js'
import { useOverviewDisplay } from './composables/useOverviewDisplay.js'
import { useErrorToast } from './composables/useErrorToast.js'
import { safeRailIcon } from './safeRailIcon.js'

// Exercise the real extracted templates, without starting a backend or browser.
function templateComponent(file, setup, components = {}, props = []) {
  const source = readFileSync(new URL(file, import.meta.url), 'utf8')
  const { descriptor, errors } = parse(source)
  assert.deepEqual(errors, [])
  const { code } = compile(descriptor.template.content, { mode: 'function', prefixIdentifiers: true })
  return { setup, components, props, render: new Function('Vue', code)(Vue) }
}

test('host evidence and capture quality preserve empty and populated states', async () => {
  const summary = templateComponent('./HostEvidenceSummary.vue', () => ({ agent: { online: true }, hostEvidenceStatus }))
  const summaryHtml = await renderToString(Vue.createSSRApp(summary))
  for (const label of ['连接', '在线', '最近采集', '数据完整度', '策略生效']) assert.ok(summaryHtml.includes(label))

  const empty = templateComponent('./HostCaptureQuality.vue', () => ({ health: undefined, moduleLabel: x => x }))
  assert.doesNotMatch(await renderToString(Vue.createSSRApp(empty)), /capture-quality-box/)

  const quality = templateComponent('./HostCaptureQuality.vue', () => ({
    health: {
      capture_quality: { source: { received: 0, buffer_dropped: 2 } },
      loop_quality: { live_cycle: { last_ms: 10 } },
      fim_root_health: { '/example': { watch: 'polling', reconcile: 'complete' } },
      inventory_quality: { software: { returned: 1000, limit: 1000, possible_truncation: true } },
      memory_scan_quality: { observed_at: '2026-11-22', scan_status: 'complete' },
      health_truncated: true,
    },
    moduleLabel: () => '软件',
  }))
  const html = await renderToString(Vue.createSSRApp(quality))
  for (const label of ['采集质量', '实时采集周期', 'FIM 目录状态', '软件', '可能截断', '最近内存扫描质量', '超限省略']) assert.ok(html.includes(label))
})

test('App delegates health presentation without losing the expand condition', () => {
  const app = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  const panel = readFileSync(new URL('./HostHealthPanel.vue', import.meta.url), 'utf8')
  const header = readFileSync(new URL('./HostDetailHeader.vue', import.meta.url), 'utf8')
  assert.match(app, /<HostDetailHeader :agent="selected"/)
  assert.match(app, /@toggle-health="hostHealthOpen = !hostHealthOpen"/)
  assert.match(header, /<HostEvidenceSummary :agent="agent"/)
  assert.match(header, /<HostHealthPanel v-if="expanded"/)
  assert.match(panel, /<HostCaptureQuality :health="health" :module-label="moduleLabel"/)
  assert.doesNotMatch(app, /class="capture-quality-box"/)
})

test('host inventory navigation and system information preserve labels, counts and zero values', async () => {
  const nav = templateComponent('./HostInventoryNav.vue', () => ({ emit: () => {} }), {}, ['groups', 'group', 'modules', 'currentModule', 'moduleLabel', 'flags', 'total', 'collectedAt', 'columnCount'])
  const html = await renderToString(Vue.createSSRApp(nav, { groups: [{ id: 'inventory', label: '资产清单' }], group: 'inventory', modules: ['sysinfo', 'software'], currentModule: 'software', moduleLabel: x => x, flags: [{ k: 'fixture', label: '数据完整', tone: 'info' }], total: 0, collectedAt: '—', columnCount: 3 }))
  assert.match(html, /资产清单/)
  assert.match(html, /class="mod-tab on">software/)
  assert.match(html, /共 0 条/)
  assert.match(html, /展示 3 列/)
  const info = templateComponent('./HostSystemInfo.vue', () => ({}), {}, ['items', 'columnLabel', 'cell'])
  const props = { columnLabel: x => x, cell: (row, key) => row[key] }
  assert.match(await renderToString(Vue.createSSRApp(info, props)), /暂无系统信息/)
  const populated = await renderToString(Vue.createSSRApp(info, { ...props, items: [{ fixture: 0 }] }))
  assert.match(populated, /fixture/)
  assert.match(populated, /<div>0<\/div>/)
})

test('snapshot table distinguishes unreported, filtered and truncated results', async () => {
  const table = templateComponent('./HostSnapshotTable.vue', () => ({ emit: () => {} }), {}, ['columns', 'rows', 'selectedRow', 'hasItems', 'filteredCount', 'truncated', 'statusMessage', 'columnLabel', 'cell'])
  const common = { columns: ['fixture'], rows: [], hasItems: false, filteredCount: 0, statusMessage: '尚未上报', columnLabel: x => x, cell: (row, key) => row[key] }
  const empty = await renderToString(Vue.createSSRApp(table, common))
  assert.match(empty, /尚未上报/)
  assert.doesNotMatch(empty, /无匹配结果/)
  const filtered = await renderToString(Vue.createSSRApp(table, { ...common, hasItems: true }))
  assert.match(filtered, /无匹配结果/)
  const row = { fixture: 0 }
  const populated = await renderToString(Vue.createSSRApp(table, { ...common, rows: [row], selectedRow: row, hasItems: true, filteredCount: 1, truncated: true, statusMessage: '可能截断' }))
  assert.match(populated, /row-click active/)
  assert.match(populated, /title="0">0/)
  assert.match(populated, /可能截断/)
})

test('snapshot pager displays page boundaries and detail preserves zero and fields', async () => {
  const pager = templateComponent('./ConsoleListPager.vue', () => ({ emit: () => {} }), {}, ['pageData', 'pageSize', 'pageSizes'])
  const html = await renderToString(Vue.createSSRApp(pager, { pageData: { page: 1, pageCount: 3, total: 41 }, pageSize: 20, pageSizes: [20, 50, 100] }))
  assert.match(html, /第 1 \/ 3 页 · 共 41 条/)
  assert.match(html, /disabled>上一页/)
  assert.doesNotMatch(html, /disabled>下一页/)
  assert.match(html, /100 条\/页/)
  const final = await renderToString(Vue.createSSRApp(pager, { pageData: { page: 3, pageCount: 3, total: 21 }, pageSize: 10, pageSizes: [10, 20, 50] }))
  assert.match(final, /10 条\/页/)
  assert.doesNotMatch(final, /100 条\/页/)
  assert.match(final, /disabled>下一页/)
  const detail = templateComponent('./HostSnapshotDetail.vue', () => ({ emit: () => {}, columnLabel, rowTitle, moduleLabel, detailGroups, formatDetail }), {}, ['currentModule', 'systemInfo', 'row'])
  const system = await renderToString(Vue.createSSRApp(detail, { currentModule: 'sysinfo', systemInfo: { count: 0 } }))
  assert.match(system, /系统信息/)
  assert.match(system, /<dd>0<\/dd>/)
  const selected = await renderToString(Vue.createSSRApp(detail, { currentModule: 'software', row: { count: 0 } }))
  assert.match(selected, /其他字段/)
  assert.match(selected, /title="0">0/)
  assert.match(selected, /关闭详情/)
})

test('snapshot detail grouping preserves raw field values without mutating the row', () => {
  const row = Object.freeze({ name: 'fixture', enabled: false, pid: 0, custom: 'x', noise: true, modules: [] })
  assert.equal(rowTitle(row), 'fixture')
  assert.equal(rowTitle(null), '条目')
  assert.deepEqual(detailGroups(null), [])
  const groups = detailGroups(row)
  assert.deepEqual(groups[0], { title: '基本信息', fields: { name: 'fixture', enabled: false, pid: 0 } })
  assert.deepEqual(groups[1], { title: '其他字段', fields: { custom: 'x' } })
  assert.equal(row.noise, true)
})

test('snapshot summary preserves known zero values and empty row hints', async () => {
  const summary = templateComponent('./HostSnapshotSummary.vue', () => ({ emit: () => {} }), {}, ['stats', 'moduleTitle', 'inventory'])
  const empty = await renderToString(Vue.createSSRApp(summary, { stats: { total: 0, unsigned: 0, hotRows: [], sampleRows: [] }, moduleTitle: '软件', inventory: true }))
  assert.match(empty, /软件 模块摘要/)
  assert.match(empty, /资产字段概览/)
  assert.match(empty, /未签名/)
  assert.match(empty, /class="c-danger">0/)
  assert.match(empty, /本模块暂无高亮项/)
  const populated = await renderToString(Vue.createSSRApp(summary, { stats: { total: 1, sampleRows: [{ title: 'fixture', sub: 'example' }] }, moduleTitle: '软件' }))
  assert.match(populated, /最近条目/)
  assert.match(populated, /fixture/)
  assert.doesNotMatch(populated, /本模块暂无高亮项/)
})

test('snapshot list prioritizes loading and errors before data display', async () => {
  const marker = text => ({ inheritAttrs: false, render() { return Vue.h('div', text) } })
  const list = templateComponent('./HostSnapshotList.vue', () => ({ emit: () => {} }), { HostSystemInfo: marker('system-fixture'), HostSnapshotTable: marker('table-fixture'), ConsoleListPager: marker('pager-fixture') }, ['currentModule', 'moduleTitle', 'snapshot', 'selectedRow', 'collectedAt', 'filteredCount', 'liveOk', 'liveAgo', 'loading', 'error', 'statusMessage', 'truncated', 'columns', 'pageData', 'pageSize', 'columnLabel', 'cell'])
  const props = { currentModule: 'software', moduleTitle: '软件', filteredCount: 1, columns: [], pageData: { rows: [] }, columnLabel: x => x, cell: () => '' }
  const loading = await renderToString(Vue.createSSRApp(list, { ...props, loading: true }))
  assert.match(loading, /加载中/)
  assert.doesNotMatch(loading, /table-fixture|pager-fixture/)
  const error = await renderToString(Vue.createSSRApp(list, { ...props, error: 'fixture-error', statusMessage: '权限不足' }))
  assert.match(error, /fixture-error/)
  assert.match(error, /权限不足/)
  assert.doesNotMatch(error, /table-fixture|pager-fixture/)
  const system = await renderToString(Vue.createSSRApp(list, { ...props, currentModule: 'sysinfo' }))
  assert.match(system, /system-fixture/)
  assert.doesNotMatch(system, /pager-fixture/)
  const normal = await renderToString(Vue.createSSRApp(list, props))
  assert.match(normal, /table-fixture/)
  assert.match(normal, /pager-fixture/)
})

test('accounts page displays current user, disabled state and missing login without altering controls', async () => {
  const header = { props: ['title', 'description'], render() { return Vue.h('h1', this.title) } }
  const statusTag = templateComponent('./ConsoleStatusTag.vue', () => ({}), {}, ['status', 'label'])
  const accounts = templateComponent('./AccountsPage.vue', () => ({}), { ConsolePageHeader: header, ConsoleStatusTag: statusTag }, ['items', 'selfId', 'fmtEpoch'])
  const empty = await renderToString(Vue.createSSRApp(accounts, { items: [], selfId: 1, fmtEpoch: String }))
  assert.match(empty, /暂无账号/)
  const html = await renderToString(Vue.createSSRApp(accounts, { items: [{ id: 1, username: 'fixture', enabled: false, must_change: true }], selfId: 1, fmtEpoch: String }))
  for (const text of ['fixture', 'acct-me', '已禁用', '待改密', '从未登录']) assert.ok(html.includes(text))
})

test('connection badge preserves full and compact connected and reconnecting labels', async () => {
  const badge = templateComponent('./LiveConnectionBadge.vue', () => ({}), {}, ['connected', 'age', 'compact'])
  for (const [props, expected] of [[{ connected: true, age: '3 秒前' }, '已连接 · 3 秒前'], [{ connected: true, compact: true, age: '3 秒前' }, '3 秒前'], [{ connected: false }, '连接中…'], [{ connected: false, compact: true }, '连接中']]) {
    const html = await renderToString(Vue.createSSRApp(badge, props))
    assert.ok(html.includes(expected))
  }
})

test('ATT&CK summary preserves zero counters and unmapped notice', async () => {
  const cards = templateComponent('./AttckSummaryCards.vue', () => ({ emit: () => {} }), {}, ['total', 'open', 'high', 'covered', 'tacticCount', 'techniqueCount', 'unmapped'])
  const html = await renderToString(Vue.createSSRApp(cards, { total: 0, open: 0, high: 0, covered: 0, tacticCount: 12, techniqueCount: 0, unmapped: 2 }))
  assert.match(html, /覆盖战术/)
  assert.match(html, /<strong class="c-ink">0<small class="kpi-den">\/12/)
  assert.match(html, /另有 2 条未映射/)
})

test('overview board preserves empty states and supplied display values', async () => {
  const board = templateComponent('./AttckOverviewBoard.vue', () => ({ emit: () => {} }), {}, ['attckSel', 'attckHeat', 'attckTechList', 'attckSelTacticName', 'attckAgent', 'attckHosts', 'attckStepStyle', 'attckRankPct', 'attckHostPct', 'short'])
  const props = { attckSel: {}, attckHeat: [], attckTechList: [], attckHosts: [], attckStepStyle: () => ({}), attckRankPct: () => 0, attckHostPct: () => 0, short: String }
  const empty = await renderToString(Vue.createSSRApp(board, props))
  assert.match(empty, /暂无命中技术/)
  assert.match(empty, /告警主机/)
  const html = await renderToString(Vue.createSSRApp(board, { ...props, attckSel: { tactic: 'fixture' }, attckSelTacticName: '测试分类', attckHeat: [{ tactic: 'fixture', name: '测试分类', count: 0, techniques: [] }] }))
  assert.match(html, /测试分类/)
  assert.match(html, /ak-step on/)
  assert.match(html, /该战术下暂无命中技术/)
})

test('host detail page preserves original layout slots and display modes', async () => {
  const page = templateComponent('./HostDetailPage.vue', () => ({ emit: () => {} }), {}, ['currentModule', 'group', 'view', 'riskCount'])
  const runtime = await renderToString(Vue.createSSRApp({ render: () => Vue.h(page, { currentModule: 'process', group: 'runtime', view: 'risk', riskCount: 0 }, { header: () => Vue.h('h1', 'fixture-header'), navigation: () => Vue.h('nav', 'fixture-nav'), list: () => Vue.h('div', 'fixture-list'), detail: () => Vue.h('aside', 'fixture-detail') }) }))
  for (const text of ['fixture-header', 'fixture-nav', 'fixture-list', 'fixture-detail', '仅可疑', '<em>0</em>']) assert.ok(runtime.includes(text))
  const inventory = await renderToString(Vue.createSSRApp(page, { currentModule: 'software', group: 'inventory' }))
  assert.match(inventory, /资产清单/)
  assert.doesNotMatch(inventory, /仅可疑/)
  const sysinfo = await renderToString(Vue.createSSRApp(page, { currentModule: 'sysinfo', group: 'inventory' }))
  assert.doesNotMatch(sysinfo, /snap-viewbar/)
})

test('process details preserve supplied zero count and empty module states', async () => {
  const detail = templateComponent('./HostProcessDetails.vue', () => ({ emit: () => {} }), {}, ['snapRow', 'childProcesses', 'processDlls', 'selectedDll', 'shortPath', 'fmtSize'])
  const props = { snapRow: { module_count: 0 }, childProcesses: [], processDlls: [], shortPath: String, fmtSize: String }
  const empty = await renderToString(Vue.createSSRApp(detail, props))
  assert.match(empty, /进程关系/)
  assert.match(empty, /共 0/)
  assert.doesNotMatch(empty, /已加载 DLL/)
  const html = await renderToString(Vue.createSSRApp(detail, { ...props, processDlls: [{ name: 'fixture-module' }], selectedDll: { name: 'fixture-module' } }))
  assert.match(html, /fixture-module/)
  assert.match(html, /模块名/)
})

test('shared page header preserves description visibility, dark theme and slot content', async () => {
  const header = templateComponent('./ConsolePageHeader.vue', () => ({}), {}, ['title', 'description', 'dark', 'hideDescription'])
  const html = await renderToString(Vue.createSSRApp({ render: () => Vue.h(header, { title: '数据概览', description: 'fixture-description', dark: true }, { default: () => Vue.h('button', '刷新') }) }))
  assert.match(html, /overview-header/)
  assert.match(html, /fixture-description/)
  assert.match(html, /<button>刷新<\/button>/)
  const hidden = await renderToString(Vue.createSSRApp(header, { title: '威胁事件', description: 'fixture-hidden', hideDescription: true }))
  assert.match(hidden, /威胁事件/)
  assert.doesNotMatch(hidden, /fixture-hidden/)
})

test('navigation shell preserves visibility, selection, badge limit and user menu permissions', async () => {
  const shell = templateComponent('./ConsoleNavigationShell.vue', () => ({ emit: () => {}, safeRailIcon }), {}, ['railItems', 'section', 'page', 'rulesSection', 'openEventCount', 'user', 'userInitial', 'isAdmin', 'userMenuOpen', 'menuVisible', 'menuPinned', 'sectionTitle', 'menuGroups'])
  const props = { railItems: [{ id: 'detect', label: '终端安全', ico: '' }], section: 'detect', page: 'events', openEventCount: 101, user: { username: 'fixture' }, userInitial: 'F', userMenuOpen: true, menuVisible: true, menuPinned: true, sectionTitle: '终端安全', menuGroups: [{ title: '检测', items: [{ id: 'events', label: '威胁事件' }] }] }
  const html = await renderToString(Vue.createSSRApp(shell, { ...props, isAdmin: false }))
  assert.match(html, /99\+/)
  assert.match(html, /class="menu open"/)
  assert.match(html, /class="menu-item on"/)
  assert.match(html, /已固定/)
  assert.doesNotMatch(html, /账号管理/)
  assert.doesNotMatch(html, /切换为紧凑密度|切换为标准密度|切换为深色模式|界面偏好/)
  assert.match(await renderToString(Vue.createSSRApp(shell, { ...props, isAdmin: true })), /账号管理/)
})

test('toast stack preserves success, error and status messages', async () => {
  const stack = templateComponent('./ConsoleToastStack.vue', () => ({ emit: () => {} }), {}, ['error', 'okMsg', 'respToast'])
  const empty = await renderToString(Vue.createSSRApp(stack))
  assert.doesNotMatch(empty, /toast-stack/)
  const html = await renderToString(Vue.createSSRApp(stack, { error: 'fixture-error', okMsg: 'fixture-ok', respToast: { cls: 'wait', title: 'fixture-status', detail: 'fixture-detail' } }))
  for (const text of ['role="alert"', 'fixture-error', 'fixture-ok', 'fixture-status', 'fixture-detail']) assert.ok(html.includes(text))
})

test('deferred page forwards properties and slots without loading before rendering', async () => {
  let loaded = 0
  const page = deferredConsolePage(async () => {
    loaded++
    return { props: ['title'], render() { return Vue.h('section', [Vue.h('h1', this.title), this.$slots.default?.()]) } }
  })
  assert.equal(loaded, 0)
  const html = await renderToString(Vue.createSSRApp({ render: () => Vue.h(page, { title: 'fixture-title' }, { default: () => Vue.h('button', 'fixture-slot') }) }))
  assert.equal(loaded, 1)
  assert.match(html, /fixture-title/)
  assert.match(html, /fixture-slot/)
})

test('navigation hover state stays pinned and cancels delayed closure on disposal', async () => {
  const scope = Vue.effectScope()
  const state = scope.run(useNavigationMenu)
  assert.equal(state.menuVisible.value, false)
  state.onNavEnter()
  assert.equal(state.menuVisible.value, true)
  state.menuPinned.value = true
  state.onNavLeave()
  await new Promise(resolve => setTimeout(resolve, 210))
  assert.equal(state.menuHover.value, false)
  assert.equal(state.menuVisible.value, true)
  state.menuPinned.value = false
  state.onNavEnter()
  state.onNavLeave()
  scope.stop()
  await new Promise(resolve => setTimeout(resolve, 210))
  assert.equal(state.menuHover.value, true)
})

test('overview display reacts to source changes without altering source records', () => {
  const agents = Vue.ref([{ agent_id: 'fixture', online: true }, { agent_id: 'other', online: false }])
  const allEvents = Vue.ref([])
  const overviewStats = Vue.ref({ timeline_24h: { buckets: [0, 2] } })
  const display = useOverviewDisplay({ agents, allEvents, overviewStats })
  assert.equal(display.onlineCount.value, 1)
  assert.equal(display.ovAgentTotal.value, 2)
  assert.match(display.overviewSparkTl.value, /^0\.0,29\.0 120\.0,3\.0$/)
  const n = new Date()
  const day = `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, '0')}-${String(n.getDate()).padStart(2, '0')}`
  allEvents.value = [{ agent_id: 'fixture', hostname: 'fixture-host', severity: 'high', status: 'open', created_at: day }]
  assert.equal(display.ovStatus.value.open, 1)
  assert.equal(display.ovSevDist.value.find(item => item.key === 'high').count, 1)
  assert.equal(display.ovTrend.value.total, 1)
  assert.equal(display.ovTopHosts.value[0].hostname, 'fixture-host')
  assert.equal(display.recentThreats.value.length, 1)
  agents.value[1].online = true
  assert.equal(display.onlineCount.value, 2)
  assert.equal(allEvents.value[0].status, 'open')
  // 已删除终端的告警不得继续计入概览
  allEvents.value = [
    { agent_id: 'fixture', hostname: 'fixture-host', severity: 'high', status: 'open', created_at: day },
    { agent_id: 'gone', hostname: 'deleted-host', severity: 'critical', status: 'open', created_at: day },
  ]
  assert.equal(display.recentThreats.value.length, 1)
  assert.equal(display.ovStatus.value.open, 1)
  assert.equal(display.ovTopHosts.value.some((h) => h.agent_id === 'gone'), false)
})

test('error toast timer expires, supports manual dismissal and is disposed with its scope', async () => {
  const scope = Vue.effectScope()
  const error = Vue.ref('')
  const { clearErrorToast } = scope.run(() => useErrorToast(error, 20))
  error.value = 'fixture'
  await Vue.nextTick()
  await new Promise(resolve => setTimeout(resolve, 40))
  assert.equal(error.value, '')
  error.value = 'manual'
  await Vue.nextTick()
  clearErrorToast()
  assert.equal(error.value, '')
  error.value = 'disposed'
  await Vue.nextTick()
  scope.stop()
  await new Promise(resolve => setTimeout(resolve, 40))
  assert.equal(error.value, 'disposed')
})

test('expanded health panel renders the supplied status and runtime evidence', async () => {
  const quality = templateComponent('./HostCaptureQuality.vue', () => ({}), {}, ['health', 'moduleLabel'])
  const panel = templateComponent('./HostHealthPanel.vue', () => ({
    panel: { score: 0, level: 'poor', pipeline: 'fixture', advise: ['需要检查'] },
    componentChips: [{ k: 'inventory', state: 'OK' }], runtimeChips: [{ k: 'queue', v: 0 }],
    health: undefined, drift: '版本状态', moduleLabel: x => x,
  }), { HostCaptureQuality: quality })
  const html = await renderToString(Vue.createSSRApp(panel))
  for (const label of ['fixture', 'inventory OK', 'queue 0', '需要检查', '版本状态']) assert.ok(html.includes(label))
})

test('storage retention distinguishes absent configuration from disabled dual writing', async () => {
  const component = templateComponent('./StorageRetentionSummary.vue', () => ({}), {}, ['retention'])
  for (const [retention, expected] of [[undefined, '未知'], [{ mysql_dual_write: false, timeline_days: 0 }, '关'], [{ mysql_dual_write: true }, '开']]) {
    const html = await renderToString(Vue.createSSRApp(component, { retention }))
    assert.ok(html.includes(`<b>${expected}</b>`))
    if (retention?.timeline_days === 0) assert.ok(html.includes('<b>0</b>'))
  }
})

test('terminal list renders empty, filtered, loading and populated states', async () => {
  const statusTag = templateComponent('./ConsoleStatusTag.vue', () => ({}), {}, ['status', 'label'])
  const component = templateComponent('./HostListTable.vue', () => ({}), { ConsoleStatusTag: statusTag }, ['agents', 'total', 'loading', 'short', 'fmtTime', 'alertCount'])
  const common = { agents: [], total: 0, loading: false, short: x => x, fmtTime: x => x, alertCount: () => 0 }
  for (const [overrides, expected] of [[{}, '暂无终端'], [{ total: 3 }, '没有符合当前筛选条件'], [{ loading: true }, '正在加载终端'], [{ agents: [{ agent_id: 'fixture', hostname: 'fixture-host', online: true, os_family: 'Linux' }] }, 'fixture-host']]) {
    const html = await renderToString(Vue.createSSRApp(component, { ...common, ...overrides }))
    assert.ok(html.includes(expected))
  }
})

test('read-only table renders values, columns and empty state without interpreting HTML', async () => {
  const component = templateComponent('./ConsoleReadOnlyTable.vue', () => ({}), {}, ['rows', 'columns', 'emptyText'])
  const columns = [{ label: '状态', value: row => row.value, title: row => row.detail }]
  const empty = await renderToString(Vue.createSSRApp(component, { rows: [], columns, emptyText: '暂无记录' }))
  assert.match(empty, /暂无记录/)
  const html = await renderToString(Vue.createSSRApp(component, { rows: [{ id: 1, value: '<fixture>', detail: '详情' }, { id: 2, value: 0 }], columns }))
  assert.match(html, /状态/)
  assert.match(html, /&lt;fixture&gt;/)
  assert.match(html, /title="详情"/)
  assert.match(html, />0<\/td>/)
})

test('group and notification views render empty and populated results', async () => {
  const header = { props: ['title', 'description'], render() { return Vue.h('h1', this.title) } }
  const group = templateComponent('./GroupPage.vue', () => ({}), { ConsolePageHeader: header }, ['items'])
  const empty = await renderToString(Vue.createSSRApp(group, { items: [] }))
  assert.match(empty, /暂无分组/)
  const populated = await renderToString(Vue.createSSRApp(group, { items: [{ id: 1, name: '测试分组', agent_ids: ['a', 'b'] }] }))
  assert.match(populated, /测试分组/)
  assert.match(populated, /2 台/)
  const notice = templateComponent('./NotificationPage.vue', () => ({}), { ConsolePageHeader: header }, ['result'])
  const result = await renderToString(Vue.createSSRApp(notice, { result: { results: [{ channel: 'feishu', ok: true, status: 200 }, { channel: 'webhook', ok: false, error: 'fixture-error' }] } }))
  assert.match(result, /成功（HTTP 200）/)
  assert.match(result, /失败：fixture-error/)
})

test('overview cards render actual counters including zero and the collapsed state', async () => {
  const stats = { agents: { va: 0, online: 2 }, timeline_24h: { display: '12' }, dns_24h: { display: '3' }, threats: { alerted_hosts: 1, endpoint_total: 5 } }
  const fleet = templateComponent('./OverviewFleetStrip.vue', () => ({ emit: () => {} }), {}, ['ovAgentTotal', 'onlineCount', 'overviewStats', 'overviewSparkTl', 'overviewSparkDns', 'ovFleetCollapsed'])
  const html = await renderToString(Vue.createSSRApp(fleet, { ovAgentTotal: 2, onlineCount: 2, overviewStats: stats, ovFleetCollapsed: true }))
  assert.match(html, /已接入终端/)
  assert.match(html, /Agent 2/)
  assert.match(html, /VA 0/)
  assert.match(html, /aria-expanded="false"/)
  const cards = templateComponent('./OverviewThreatCards.vue', () => ({ emit: () => {} }), {}, ['overviewStats', 'onlineCount'])
  const threats = await renderToString(Vue.createSSRApp(cards, { overviewStats: stats, onlineCount: 2 }))
  assert.match(threats, /告警主机/)
  assert.match(threats, /<strong>5<\/strong>/)
})

test('overview summary panels preserve trends and conditional ranking labels', async () => {
  const panels = templateComponent('./OverviewSummaryPanels.vue', () => ({ emit: () => {} }), {}, ['focusCats', 'ovStatus', 'ovSevDist', 'ovTrend', 'overviewTopMalware', 'ovTopHosts'])
  const common = { focusCats: [], ovStatus: { open: 0, closed: 2 }, ovSevDist: [], ovTrend: { total: 2, days: [] }, overviewTopMalware: [], ovTopHosts: [] }
  const empty = await renderToString(Vue.createSSRApp(panels, common))
  assert.match(empty, /近 7 天告警趋势/)
  assert.match(empty, /未处置 0/)
  assert.match(empty, /风险终端 Top 5/)
  assert.match(empty, /暂无数据/)
  const populated = await renderToString(Vue.createSSRApp(panels, { ...common, overviewTopMalware: [{ title: 'fixture', count: 2 }] }))
  assert.match(populated, /TOP5 恶意文件/)
  assert.match(populated, /fixture/)
})

test('overview activity preserves empty, timeline fallback and formal alert states', async () => {
  const props = ['recentThreats', 'recentRiskTimeline', 'agents', 'onlineCount', 'sevLabel', 'short', 'modLabel', 'fmtTime', 'cleanSummary', 'etypeLabel', 'alertCount']
  const activity = templateComponent('./OverviewActivity.vue', () => ({ emit: () => {} }), {}, props)
  const label = value => value || '—'
  const common = { recentThreats: [], recentRiskTimeline: [], agents: [], onlineCount: 0, sevLabel: label, short: label, modLabel: label, fmtTime: label, cleanSummary: label, etypeLabel: label, alertCount: () => 0 }
  const empty = await renderToString(Vue.createSSRApp(activity, common))
  assert.match(empty, /暂无威胁事件/)
  assert.match(empty, /尚未接入终端/)
  const fallback = await renderToString(Vue.createSSRApp(activity, { ...common, recentRiskTimeline: [{ id: 1, summary: 'fixture-timeline', agent_id: 'fixture', severity: 'high' }] }))
  assert.match(fallback, /暂无正式威胁事件/)
  assert.match(fallback, /fixture-timeline/)
  const populated = await renderToString(Vue.createSSRApp(activity, { ...common, recentThreats: [{ id: 2, title: 'fixture-alert', severity: 'high', agent_id: 'fixture' }], agents: [{ agent_id: 'fixture', hostname: 'fixture-host', online: true }], onlineCount: 1 }))
  assert.match(populated, /fixture-alert/)
  assert.match(populated, /fixture-host/)
  assert.doesNotMatch(populated, /暂无正式威胁事件/)
})
