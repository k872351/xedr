import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { useResponseOps } from './composables/useResponseOps.js'
import { graphParentChain } from './graphParentChain.js'
import { NAV_PAGES, NAV_SECTIONS, NAV_STORE_KEY, menuMap, sectionTitleFor, visibleMenuGroups, defaultPageForSection, encodeNavState, decodeNavState } from './consoleNavigation.js'

const app = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
const extras = readFileSync(new URL('./PlatformExtras.vue', import.meta.url), 'utf8')
const storage = readFileSync(new URL('./StoragePage.vue', import.meta.url), 'utf8')
const audit = readFileSync(new URL('./AuditPage.vue', import.meta.url), 'utf8')
const hosts = readFileSync(new URL('./HostsPage.vue', import.meta.url), 'utf8')
const groups = readFileSync(new URL('./GroupPage.vue', import.meta.url), 'utf8')
const notify = readFileSync(new URL('./NotificationPage.vue', import.meta.url), 'utf8')

test('restored analysis pages have menu, renderer and refresh-safe navigation', () => {
  for (const id of ['lineage-risk', 'network-awareness', 'abnormal-files', 'archive']) {
    assert.ok(Object.values(menuMap).flatMap(groups => groups.flatMap(group => group.items)).some(item => item.id === id), `missing menu: ${id}`)
    assert.ok(app.match(/<PlatformExtras\s+v-else-if="\[([^\]]+)\]/)?.[1].includes(`'${id}'`), `missing dispatch: ${id}`)
    assert.ok(NAV_PAGES.has(id), `missing persisted navigation: ${id}`)
    assert.ok(extras.includes(`page === '${id}'`), `missing renderer: ${id}`)
  }
})

test('navigation configuration preserves section defaults and administrator-only menu visibility', () => {
  const expected = { overview: 'overview', detect: 'events', intel: 'ioc', rules: 'rules', asset: 'hosts', deploy: 'deploy', config: 'settings' }
  for (const [section, page] of Object.entries(expected)) assert.equal(defaultPageForSection(section), page)
  assert.equal(defaultPageForSection('unknown'), null)
  assert.equal(sectionTitleFor('asset'), '终端资产')
  assert.equal(sectionTitleFor('unknown'), '')
  const ids = groups => groups.flatMap(group => group.items.map(item => item.id))
  assert.ok(!ids(visibleMenuGroups('config', false)).includes('accounts'))
  assert.ok(ids(visibleMenuGroups('config', true)).includes('accounts'))
  assert.ok(!ids(visibleMenuGroups('config', false)).includes('accounts'))
  assert.deepEqual(visibleMenuGroups('unknown', true), [])
  assert.equal(NAV_STORE_KEY, 'edr_admin_nav')
  assert.ok(!NAV_PAGES.has('unknown'))
})

test('navigation storage keeps valid pages and carries event context only for the detail page', () => {
  const common = { section: 'detect', eventListReturnPage: 'events', activeEventId: 7, rulesSection: 'rules' }
  const detail = decodeNavState(encodeNavState({ ...common, page: 'threat-view' }))
  assert.equal(detail.threatEventId, 7)
  assert.equal(detail.eventListReturnPage, 'events')
  assert.equal(decodeNavState(encodeNavState({ ...common, page: 'events' })).threatEventId, null)
  assert.equal(decodeNavState('{"page":"unknown"}'), null)
  assert.equal(decodeNavState(null), null)
  assert.throws(() => decodeNavState('invalid'), SyntaxError)
})

test('navigation storage normalizes stale sections instead of dropping the page', () => {
  // AI 模块删除后旧缓存残留 section:'ai'；归一到 overview 但保留 page，避免二级菜单空白
  const decoded = decodeNavState(JSON.stringify({ section: 'ai', page: 'events', eventListReturnPage: 'events' }))
  assert.equal(decoded.section, 'overview')
  assert.equal(decoded.page, 'events')
  assert.equal(decodeNavState(JSON.stringify({ section: 'detect', page: 'events' })).section, 'detect')
  assert.ok(NAV_SECTIONS.has('detect'))
  assert.ok(!NAV_SECTIONS.has('ai'))
  assert.equal(decodeNavState('{"page":"unknown"}'), null)
})

test('stale threat-view state falls back to the event list and unknown pages render a fallback', () => {
  // 无 threatEventId 时不再把 page 直接恢复成 detail（详情要求 activeEvent，会白屏）
  assert.match(app, /page\.value = raw\.eventListReturnPage === 'malware' \? 'malware' : 'events'/)
  assert.match(app, /if \(raw\.threatEventId\) pendingThreatRestoreId\.value/)
  assert.match(app, /<ConsoleExceptionPage/)
  assert.match(app, /@home="goMenu\('overview'\)"/)
  assert.match(app, /rulesSection === 'abfile'/)
  assert.match(app, /startCreateAbfileRule/)
})

test('navigation shell leaves state and actions with the parent', () => {
  const shell = readFileSync(new URL('./ConsoleNavigationShell.vue', import.meta.url), 'utf8')
  assert.match(app, /<ConsoleNavigationShell\b/)
  // 概览为单页直达：不在该分区浮出二级菜单，也不留固定菜单占位
  assert.match(app, /@section="setSection\(\$event\)" @page="goMenu"/)
  assert.match(app, /:menu-visible="menuVisible && section !== 'overview'"/)
  assert.match(app, /:class="\{ 'menu-pinned': menuPinned && section !== 'overview' \}"/)
  assert.match(app, /menuHover\.value = id !== 'overview'/)
  assert.match(app, /@toggle-pin="menuPinned = !menuPinned"/)
  assert.match(shell, /v-if="isAdmin"[^>]*@click="emit\('accounts'\)"/)
  assert.match(app, /<ConsoleToastStack[^>]*@clear-error="clearErrorToast" @dismiss="dismissRespToast"/)
})

test('overview is a single-page destination with an ATT&CK entry preserved in the header', () => {
  assert.equal(defaultPageForSection('overview'), 'overview')
  const ids = menuMap.overview.flatMap(g => g.items.map(i => i.id))
  assert.deepEqual(ids, ['overview'])
  // 精简掉唯一入口后，必须由总览页头按钮补回 ATT&CK 看板
  assert.match(app, /@click="goMenu\('attck'\)">ATT&CK 看板/)
  assert.ok(NAV_PAGES.has('attck'))
})

test('independent non-home views are loaded on demand with explicit failure handling', () => {
  for (const page of ['HostsPage', 'StoragePage', 'AuditPage', 'GroupPage', 'NotificationPage', 'AccountsPage']) assert.ok(app.includes(`const ${page} = deferredConsolePage(() => import('./${page}.vue'))`))
  const helper = readFileSync(new URL('./deferredConsolePage.js', import.meta.url), 'utf8')
  assert.match(helper, /loadingComponent: LoadingPage, errorComponent: FailedPage/)
  assert.match(helper, /role: 'alert'/)
})

test('overview board preserves parent-owned selection handlers', () => {
  assert.match(app, /<AttckOverviewBoard\b/)
  assert.match(app, /@clear-selection="clearAttckSel" @select-tactic="selectAttckTactic" @select-technique="selectAttckTech"/)
  assert.match(app, /@clear-host="attckAgent = ''; loadAttckBoard\(\)" @select-host="filterAttckByHost"/)
  assert.doesNotMatch(app, /class="ak-board"/)
})

test('shared summary cards are reused for endpoint and storage statistics', () => {
  const cards = readFileSync(new URL('./SummaryCards.vue', import.meta.url), 'utf8')
  assert.match(hosts, /<SummaryCards\b/)
  assert.match(storage, /<SummaryCards\b/)
  assert.match(cards, /v-for="item in items"/)
  assert.match(cards, /\{\{ item\.value \}\}/)
})

test('shared page header keeps parent-owned filters and refresh actions', () => {
  const header = readFileSync(new URL('./ConsolePageHeader.vue', import.meta.url), 'utf8')
  assert.match(header, /<slot\s*\/>/)
  assert.match(app, /<HostsPage v-else-if="page === 'hosts' && !selected"[\s\S]*?v-model="q"[\s\S]*?@click="refresh"[\s\S]*?<\/HostsPage>/)
  assert.match(hosts, /<ConsolePageHeader title="终端列表"/)
  assert.match(groups, /<ConsolePageHeader title="终端分组"/)
  assert.match(notify, /<ConsolePageHeader title="通知渠道"/)
  assert.match(storage, /<ConsolePageHeader title="存储与保留"/)
  assert.match(audit, /<ConsolePageHeader title="审计日志"/)
  assert.equal((app.match(/<ConsolePageHeader\b/g) || []).length, 13)
  assert.doesNotMatch(app, /<header class="page-hd">/)
  assert.match(app, /<ConsolePageHeader title="主机时间线"[^>]*\$\{filteredTimeline\.length\}/)
  assert.match(app, /<ConsolePageHeader title="EDR 策略"[^>]*\$\{policyRev\}/)
})

test('host list, groups and notification pages preserve parent form ownership', () => {
  assert.match(app, /<GroupPage v-else-if="page === 'groups'"/)
  assert.match(app, /<NotificationPage v-else-if="page === 'notify'"/)
  assert.match(app, /v-model="groupName"/)
  assert.match(app, /@click="saveGroup"/)
  assert.match(app, /v-model="notifyForm\.enabled"/)
  assert.match(app, /@click="saveNotify"/)
  assert.match(groups, /<slot name="form"/)
  assert.match(notify, /<slot name="form"/)
  assert.match(hosts, /<slot name="actions" :agent="agent"/)
  assert.match(app, /page === 'hosts' && selected/)
})

test('host detail retains original asset selection and parent controls', () => {
  const page = readFileSync(new URL('./HostDetailPage.vue', import.meta.url), 'utf8')
  assert.match(app, /<HostDetailPage v-else-if="page === 'hosts' && selected"[^>]*@view-change="snapView = \$event"/)
  for (const slot of ['header', 'navigation', 'list', 'detail']) assert.ok(page.includes(`<slot name="${slot}"`))
  assert.match(app, /<HostDetailHeader\b/)
  assert.match(app, /<template #back>\s*<button[^>]*@click="backFromHost"/)
  assert.match(app, /<HostInventoryNav[\s\S]*?@group="selectHostGroup" @module="loadSnap"/)
  const list = readFileSync(new URL('./HostSnapshotList.vue', import.meta.url), 'utf8')
  assert.match(list, /<HostSystemInfo v-else-if="currentModule === 'sysinfo'"/)
  assert.match(list, /<HostSnapshotTable[\s\S]*?@select="emit\('select', \$event\)"/)
  assert.match(list, /<ConsoleListPager[\s\S]*?@page-change="emit\('page-change', \$event\)"/)
  assert.match(app, /<HostSnapshotList[\s\S]*?@select="snapRow = \$event"[\s\S]*?@page-change="snapPage = \$event"/)
  assert.match(app, /<HostSnapshotSummary[^>]*@select="snapRow = \$event"/)
  assert.match(app, /<HostSnapshotDetail[\s\S]*?@close="snapRow = null"/)
  assert.match(app, /<HostProcessDetails[\s\S]*?@pid="jumpToPid" @select-row="snapRow = \$event"/)
})

test('shared pagination keeps each existing page size and page ownership', () => {
  assert.equal((app.match(/<ConsoleListPager\b/g) || []).length, 4)
  for (const prefix of ['inv', 'dns', 'bh', 'evt']) {
    assert.ok(app.includes(`:page-size="${prefix}PageSize" :page-sizes="[10, 20, 50]" @size-change="${prefix}PageSize = $event; ${prefix}Page = 1" @page-change="${prefix}Page = $event"`))
  }
})

test('accounts page keeps existing self-account protections and parent controls', () => {
  const accounts = readFileSync(new URL('./AccountsPage.vue', import.meta.url), 'utf8')
  assert.match(app, /<AccountsPage v-else-if="page === 'accounts'"/)
  assert.match(app, /<template #role="\{ account: u \}">[\s\S]*?:disabled="u.id === user\?\.id"/)
  assert.match(app, /<template #actions="\{ account: u \}">[\s\S]*?v-if="u.id !== user\?\.id"/)
  assert.match(accounts, /<slot name="role" :account="u"/)
  assert.match(accounts, /<slot name="actions" :account="u"/)
  assert.match(accounts, /三角色权限/)
  assert.match(accounts, /ROLE_MATRIX/)
})

test('threat view splits intelligent analysis from attack story', () => {
  assert.match(app, />智能分析</)
  assert.match(app, /openThreatAi/)
  assert.match(app, /threatTab === 'ai'/)
  assert.match(app, /canRespond/)
  assert.doesNotMatch(app, /智能分析 \/ 攻击故事/)
})

test('overview uses standalone cards with the original navigation and collapse handlers', () => {
  const overview = readFileSync(new URL('./OverviewPage.vue', import.meta.url), 'utf8')
  assert.match(app, /<OverviewPage v-if="page === 'overview'"/)
  assert.match(overview, /<OverviewFleetStrip v-bind="fleet"/)
  assert.match(app, /@navigate="goPage" @network="openOverviewNetworkView" @toggle="ovFleetCollapsed = !ovFleetCollapsed"/)
  assert.match(overview, /<OverviewThreatCards\b/)
  assert.match(overview, /<OverviewSummaryPanels v-bind="summary"/)
  assert.match(overview, /<OverviewActivity v-bind="activity"/)
  assert.match(overview, /@host="\(agent, origin\) => emit\('host', agent, origin\)"/)
  assert.match(app, /@menu="goMenu" @event="openEvent" @timeline="openTimelineFor" @host="openHost"/)
  assert.doesNotMatch(app, /class="ov-fleet-strip"|class="ov-threat-rail"|class="ov-bottom-grid"|class="ov-body"/)
})

test('audit and storage pages retain routing and parent-owned controls', () => {
  assert.match(app, /<AuditPage v-else-if="page === 'audit'"/)
  assert.match(app, /<StoragePage v-else-if="page === 'storage'"/)
  assert.match(app, /<template #refresh>\s*<button[^>]*@click="loadAudit"/)
  assert.match(app, /<template #refresh>\s*<button[^>]*@click="loadStorage"/)
  assert.match(app, /<template #retention-actions>\s*<button[^>]*@click="doPurge"/)
  assert.match(app, /<template #search>\s*<div class="hunt-bar">\s*<input v-model="storeQ"/)
  assert.match(audit, /class="audit-table"/)
  assert.match(audit, /登录、策略、处置指令/)
  assert.match(storage, /<ConsoleReadOnlyTable :rows="hits"/)
})

test('response toast state remains owned by its composable', () => {
  const ops = useResponseOps()
  assert.doesNotThrow(() => ops.resetRespToastKey())
  assert.doesNotThrow(() => ops.stopRespPoll())
  assert.doesNotMatch(app, /\brespToastCmdKey\b|\brespPollTimer\b/)
  const open = app.split('async function openEvent(e) {')[1].split('function closeThreat()')[0]
  assert.ok(open.indexOf("page.value = 'threat-view'") < open.indexOf('await getEvent(e.id)'))
})

test('cyclic and missing parent links cannot hang the threat view', () => {
  const nodes = { a: { id: 'a', parent_id: 'b' }, b: { id: 'b', parent_id: 'a' }, c: { id: 'c', parent_id: 'missing' } }
  assert.deepEqual(graphParentChain(nodes, 'a').map(x => x.id), ['a', 'b'])
  assert.deepEqual(graphParentChain(nodes, 'c').map(x => x.id), ['c'])
  assert.deepEqual(graphParentChain(nodes, 'missing'), [])
  assert.match(app, /graphParentChain\(byId, hitId\)/)
  assert.match(app, /r\?\.item\?\.items \|\| r\?\.items/)
})
