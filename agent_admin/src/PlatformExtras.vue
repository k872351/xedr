<script setup>
import { computed, defineAsyncComponent, h, onMounted, ref, watch } from 'vue'
import {
  listResponseApprovals, decideResponseApproval,
  listAlertCases, mergeAlertCases, setAlertCaseStatus,
  listHuntJobs, upsertHuntJob, runHuntJob, tickHuntJobs, buildInvestigationPack,
  getHostBaseline, getFleetPrevalence,
  searchTelemetryArchive,
  runPersistDaily, explainPersistDiff,
  createAiRuleDraft, listAiRuleDrafts, reviewAiRuleDraft,
  runAiInvestigate, listAgents,
} from './api'
const loadPage = loader => defineAsyncComponent({ loader, delay: 150, timeout: 30000,
  loadingComponent: { render: () => h('section', { class: 'panel pad', role: 'status' }, '正在加载分析模块…') },
  errorComponent: { render: () => h('section', { class: 'panel pad', role: 'alert' }, [
    h('p', '分析模块加载失败，请检查服务与静态资源版本。'),
    h('button', { type: 'button', class: 'btn', onClick: () => window.location.reload() }, '刷新重试'),
  ]) },
})
const LineageRiskPage = loadPage(() => import('./LineageRiskPage.vue'))
const NetworkAwarenessPage = loadPage(() => import('./NetworkAwarenessPage.vue'))
const AbnormalFilesPage = loadPage(() => import('./AbnormalFilesPage.vue'))


const props = defineProps({
  page: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
})
const emit = defineEmits(['goto', 'open-host'])
const blOpen = ref('') // e.g. process:0 / inv:service:3
const blInvTab = ref('service')
/** 基线主分区：行为画像 | 资产清单 | 全网流行度 —— 避免一屏堆叠 */
const blSec = ref('behavior')

function invLabel(k) {
  return ({
    software: '已装软件', service: '服务', startup: '启动项', listen: '监听',
    driver: '驱动', netif: '网卡', user: '用户', task: '计划任务',
  })[k] || k
}

function blKey(kind, i) {
  return `${kind}:${i}`
}

function toggleBl(kind, i) {
  const k = blKey(kind, i)
  blOpen.value = blOpen.value === k ? '' : k
}

function openInvHost(mod) {
  const aid = baselineAgent.value
  if (!aid) return
  emit('open-host', { agentId: aid, module: mod || blInvTab.value || 'service' })
}

const blInvMods = computed(() => {
  const samples = baseline.value?.inventory_samples || {}
  const counts = baseline.value?.inventory_counts || {}
  const order = ['service', 'startup', 'task', 'software', 'listen', 'driver', 'user', 'netif']
  return order.filter((m) => samples[m]?.length || counts[m]).map((m) => ({
    id: m,
    label: invLabel(m),
    count: counts[m]?.count ?? counts[m] ?? (samples[m] || []).length,
    items: samples[m] || [],
    collected_at: counts[m]?.collected_at || '',
  }))
})

const blInvActive = computed(() => blInvMods.value.find((m) => m.id === blInvTab.value) || blInvMods.value[0] || null)

const busy = ref(false)
const err = ref('')
const ok = ref('')
const agents = ref([])

const approvals = ref([])
const apprStatus = ref('pending')
const cases = ref([])
const caseStatus = ref('open')
const huntJobs = ref([])
const huntForm = ref({ name: '', query: '', cron_min: 60 })
const baselineAgent = ref('')
const baselineDays = ref(7)
const baseline = ref(null)
const prevalenceQ = ref('')
const prevalence = ref(null)
const archive = ref({ q: '', agent_id: '', etype: '', hours: 24, items: [] })
const persistResult = ref(null)
const drafts = ref([])
const draftPrompt = ref('')
const invAgent = ref('')
const invQuestion = ref('')
const invReport = ref(null)
const invHours = ref(24)

const title = computed(() => ({
  cases: '告警案件',
  approvals: '处置审批',
  'hunt-jobs': '定时狩猎',
  baseline: '主机基线',
  archive: '遥测归档',
  'persist-daily': '持久化日对比',
  'ai-investigate': 'AI 调查',
  'ai-rule-drafts': 'AI 规则草案',
}[props.page] || '新能力'))

const desc = computed(() => ({
  cases: '将同主机短窗口内的开放告警归并为案件，便于统一处置。',
  approvals: '高危处置先审批再下发；批准后写入终端指令队列。',
  'hunt-jobs': '保存狩猎关键字并按间隔执行；可导出调查包。',
  baseline: '按「行为 / 资产 / 流行度」分区查看；行为看时间线频次，资产看服务启动项等清单。',
  archive: '查询已写入 Elasticsearch 的长期原始遥测。',
  'persist-daily': '对比服务 / 计划任务 / 启动项日快照差异。',
  'ai-investigate': '按工具编排拉取证据并生成结构化调查报告。',
  'ai-rule-drafts': '根据自然语言生成检测规则草案，人工审核后上线。',
}[props.page] || ''))

function flash(msg, isErr = false) {
  ok.value = isErr ? '' : msg
  err.value = isErr ? msg : ''
}

async function ensureAgents() {
  if (agents.value.length) return
  try {
    const r = await listAgents()
    agents.value = r.items || r.agents || r || []
    if (!Array.isArray(agents.value)) agents.value = []
    if (!baselineAgent.value && agents.value[0]) {
      baselineAgent.value = agents.value[0].agent_id || agents.value[0].id || ''
    }
    if (!invAgent.value && agents.value[0]) {
      invAgent.value = agents.value[0].agent_id || agents.value[0].id || ''
    }
  } catch { /* ignore */ }
}

async function loadApprovals() {
  busy.value = true
  try {
    const r = await listResponseApprovals({ status: apprStatus.value })
    approvals.value = r.items || []
    flash(`已加载 ${approvals.value.length} 条`)
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function decide(id, approve) {
  if (!props.isAdmin) return flash('需要管理员', true)
  busy.value = true
  try {
    const r = await decideResponseApproval(id, { approve, note: approve ? '批准' : '驳回' })
    await loadApprovals()
    if (!approve) flash('已驳回')
    else if (r?.skipped_dispatch || r?.message) flash(r.message || '已批准（终端已不在册，未再下发）')
    else flash('已批准并下发')
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function loadCases() {
  busy.value = true
  try {
    const r = await listAlertCases({ status: caseStatus.value })
    cases.value = r.items || []
    flash(`已加载 ${cases.value.length} 个案件`)
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function doMergeCases() {
  if (!props.isAdmin) return flash('需要管理员', true)
  busy.value = true
  try {
    const r = await mergeAlertCases({ window_min: 60 })
    flash(`归并完成：新建 ${r.created || 0}，更新 ${r.updated || 0}`)
    await loadCases()
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function setCase(id, status) {
  if (!props.isAdmin) return flash('需要管理员', true)
  try {
    await setAlertCaseStatus(id, { status })
    await loadCases()
  } catch (e) {
    flash(e.message || String(e), true)
  }
}

async function loadHuntJobs() {
  busy.value = true
  try {
    const r = await listHuntJobs()
    huntJobs.value = r.items || []
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function saveHuntJob() {
  if (!props.isAdmin) return flash('需要管理员', true)
  if (!huntForm.value.query.trim()) return flash('请填写查询关键字', true)
  busy.value = true
  try {
    await upsertHuntJob(huntForm.value)
    huntForm.value = { name: '', query: '', cron_min: 60 }
    await loadHuntJobs()
    flash('任务已保存')
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function runJob(id) {
  if (!props.isAdmin) return flash('需要管理员', true)
  busy.value = true
  try {
    const r = await runHuntJob(id)
    flash(`执行完成，命中 ${r.hit_count || 0}`)
    await loadHuntJobs()
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function tickJobs() {
  if (!props.isAdmin) return flash('需要管理员', true)
  busy.value = true
  try {
    const r = await tickHuntJobs()
    flash(`已扫描到期任务 ${ (r.ran || []).length } 个`)
    await loadHuntJobs()
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function makePack() {
  await ensureAgents()
  const aid = baselineAgent.value || invAgent.value
  if (!aid) return flash('请选择终端', true)
  busy.value = true
  try {
    const r = await buildInvestigationPack(aid, { hours: 24 })
    flash(r.path ? `调查包已生成：${r.path}` : '已生成')
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function loadBaseline() {
  await ensureAgents()
  if (!baselineAgent.value) return flash('请选择终端', true)
  busy.value = true
  try {
    blOpen.value = ''
    baseline.value = await getHostBaseline(baselineAgent.value, { days: baselineDays.value || 7 })
    const mods = Object.keys(baseline.value?.inventory_samples || {})
    if (mods.length && !mods.includes(blInvTab.value)) blInvTab.value = mods.includes('service') ? 'service' : mods[0]
    flash(`基线已生成：${baseline.value.event_count || 0} 条事件样本`)
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function loadPrevalence() {
  if (prevalenceQ.value.trim().length < 3) return flash('关键字至少 3 个字符', true)
  busy.value = true
  try {
    prevalence.value = await getFleetPrevalence(prevalenceQ.value.trim())
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function loadArchive() {
  busy.value = true
  try {
    const r = await searchTelemetryArchive({
      q: archive.value.q,
      agent_id: archive.value.agent_id,
      etype: archive.value.etype,
      hours: archive.value.hours,
      limit: 50,
    })
    if (!r.ok) flash(r.error || '查询失败', true)
    archive.value = { ...archive.value, items: r.items || [] }
    if (r.ok) flash(`命中 ${ (r.items || []).length } 条`)
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function runPersist() {
  if (!props.isAdmin) return flash('需要管理员', true)
  busy.value = true
  try {
    persistResult.value = await runPersistDaily({})
    flash(`已对比 ${persistResult.value.agents || 0} 台终端，差异 ${ (persistResult.value.diffs || []).length } 条`)
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function explainDiff(id) {
  busy.value = true
  try {
    const r = await explainPersistDiff(id)
    flash(r.ai_note || '已生成解释')
    if (persistResult.value?.diffs) {
      const hit = persistResult.value.diffs.find((d) => d.diff_id === id)
      if (hit) hit.ai_note = r.ai_note
    }
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function loadDrafts() {
  busy.value = true
  try {
    const r = await listAiRuleDrafts({ status: 'pending' })
    drafts.value = r.items || []
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function createDraft() {
  if (!props.isAdmin) return flash('需要管理员', true)
  if (draftPrompt.value.trim().length < 4) return flash('请描述检测意图', true)
  busy.value = true
  try {
    await createAiRuleDraft({ prompt: draftPrompt.value.trim() })
    draftPrompt.value = ''
    await loadDrafts()
    flash('草案已创建')
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function reviewDraft(id, approve) {
  if (!props.isAdmin) return flash('需要管理员', true)
  busy.value = true
  try {
    await reviewAiRuleDraft(id, { approve })
    await loadDrafts()
    flash(approve ? '已批准并写入规则' : '已驳回')
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function runInvestigate() {
  await ensureAgents()
  if (!invAgent.value) return flash('请选择终端', true)
  busy.value = true
  invReport.value = null
  try {
    const r = await runAiInvestigate(invAgent.value, {
      hours: invHours.value,
      question: invQuestion.value,
      allow_active: false,
    })
    invReport.value = r.report || r
    flash('调查完成')
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function refresh() {
  err.value = ''
  ok.value = ''
  if (props.page === 'lineage-risk' || props.page === 'network-awareness' || props.page === 'abnormal-files') return
  await ensureAgents()
  if (props.page === 'approvals') return loadApprovals()
  if (props.page === 'cases') return loadCases()
  if (props.page === 'hunt-jobs') return loadHuntJobs()
  if (props.page === 'ai-rule-drafts') return loadDrafts()
  if (props.page === 'baseline') return
  if (props.page === 'ai-investigate') return
}

watch(() => props.page, () => refresh(), { immediate: true })
onMounted(() => ensureAgents())

function fmt(t) {
  return String(t || '').replace('T', ' ').slice(0, 19) || '—'
}
function draftObj(row) {
  try { return JSON.parse(row.draft_json || '{}') } catch { return {} }
}
function shortId(id) {
  const s = String(id || '')
  return s.length > 10 ? s.slice(0, 8) + '…' : (s || '—')
}
function agentHost(rowOrId) {
  if (rowOrId && typeof rowOrId === 'object') {
    if (rowOrId.hostname) return rowOrId.hostname
    const aid = rowOrId.agent_id
    const a = agents.value.find((x) => (x.agent_id || x.id) === aid)
    return a?.hostname || aid || '—'
  }
  const a = agents.value.find((x) => (x.agent_id || x.id) === rowOrId)
  return a?.hostname || rowOrId || '—'
}
function actionLabel(act) {
  return ({
    isolate_network: '隔离主机网络',
    unisolate_network: '解除网络隔离',
    kill_process: '结束进程树',
    quarantine_file: '隔离文件',
    uninstall_agent: '卸载 Agent',
    disable_service: '禁用服务',
    stop_service: '停止服务',
    delete_task: '删除计划任务',
    clear_persistence: '清理持久化',
  })[String(act || '')] || act || '—'
}
function statusLabel(s) {
  return ({ pending: '待审批', dispatching: '待核实下发状态', approved: '已批准（不代表执行成功）', rejected: '已驳回', verification_required: '待核实' })[String(s || '')] || s || '—'
}
function caseStatusLabel(s) {
  return ({ open: '开放', investigating: '调查中', closed: '已关闭' })[String(s || '')] || s || '—'
}
function caseSevLabel(s) {
  return ({ critical: '危急', high: '高危', medium: '中危', low: '低危' })[String(s || '').toLowerCase()] || s || '—'
}
function caseEventCount(c) {
  try {
    const ids = typeof c.event_ids_json === 'string' ? JSON.parse(c.event_ids_json || '[]') : (c.event_ids || [])
    return Array.isArray(ids) ? ids.length : 0
  } catch {
    return 0
  }
}
function caseSummaryParts(c) {
  return String(c.summary || '')
    .split(/[；;\n]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, 6)
}
const caseStats = computed(() => {
  const list = cases.value || []
  return {
    total: list.length,
    critical: list.filter((c) => String(c.severity || '').toLowerCase() === 'critical').length,
    high: list.filter((c) => String(c.severity || '').toLowerCase() === 'high').length,
    alerts: list.reduce((n, c) => n + caseEventCount(c), 0),
  }
})
function paramsPreview(a) {
  try {
    const p = typeof a.params_json === 'string' ? JSON.parse(a.params_json || '{}') : (a.params || {})
    if (!p || typeof p !== 'object') return ''
    const bits = []
    if (p.pid != null) bits.push(`PID ${p.pid}`)
    if (p.process_guid) bits.push(`实体 ${String(p.process_guid).slice(0, 10)}…`)
    if (p.path) bits.push(String(p.path).slice(0, 60))
    if (p.tree) bits.push('含进程树')
    return bits.join(' · ')
  } catch {
    return ''
  }
}
</script>

<template>
  <LineageRiskPage v-if="page === 'lineage-risk'" :is-admin="isAdmin" @goto="emit('goto', $event)" />
  <NetworkAwarenessPage v-else-if="page === 'network-awareness'" />
  <AbnormalFilesPage v-else-if="page === 'abnormal-files'" />
  <section
    v-else
    class="page extras-page"
    :class="{ 'mod-shell': page === 'approvals' || page === 'cases' }"
  >
    <header class="page-hd">
      <div>
        <h1>{{ title }}</h1>
        <p class="desc">{{ desc }}</p>
      </div>
      <div class="hd-right">
        <button type="button" class="btn sm" :disabled="busy" @click="refresh">{{ busy ? '加载中…' : '刷新' }}</button>
      </div>
    </header>

    <p v-if="err" class="banner err">{{ err }}</p>
    <p v-else-if="ok" class="banner ok">{{ ok }}</p>

    <!-- 处置审批 -->
    <div v-if="page === 'approvals'" class="mod-page">
      <div class="panel mod-filters">
        <select v-model="apprStatus" class="search" @change="loadApprovals">
          <option value="pending">状态：待审批</option>
          <option value="approved">状态：已批准</option>
          <option value="rejected">状态：已驳回</option>
          <option value="verification_required">状态：待核实</option>
          <option value="dispatching">状态：下发待核实</option>
          <option value="">状态：全部</option>
        </select>
        <span class="mod-filter-hint">分析员提交的高危处置进入本队列；管理员免审直接下发</span>
      </div>

      <div class="mod-stats">
        <div class="panel mod-stat" data-s="pending">
          <em>待审批</em>
          <b>{{ approvals.filter(x => x.status === 'pending').length || (apprStatus === 'pending' ? approvals.length : 0) }}</b>
          <small>需人工确认后下发</small>
        </div>
        <div class="panel mod-stat">
          <em>本页记录</em>
          <b>{{ approvals.length }}</b>
          <small>当前筛选结果</small>
        </div>
        <div class="panel mod-stat tip">
          <em>说明</em>
          <p>隔离网络 / 结束进程 / 卸载 Agent 等对分析员需审批。</p>
        </div>
      </div>

      <div class="panel mod-list-panel">
        <div class="panel-hd bare">
          <h3>处置审批列表 <em>（{{ approvals.length }}）</em></h3>
        </div>
        <div class="mod-list" v-if="approvals.length">
          <article
            v-for="a in approvals" :key="a.id"
            class="appr-card"
            :data-s="a.status"
            :class="{ missing: a.agent_missing }"
          >
            <div class="appr-card-main">
              <div class="appr-card-top">
                <span class="pill" :data-s="a.status">{{ statusLabel(a.status) }}</span>
                <strong class="appr-title">{{ actionLabel(a.action) }}</strong>
                <span v-if="paramsPreview(a)" class="appr-param" :title="paramsPreview(a)">{{ paramsPreview(a) }}</span>
                <time class="appr-time mono">{{ fmt(a.created_at) }}</time>
              </div>
              <div class="appr-meta">
                <span><em>终端</em><b>{{ agentHost(a) }}</b><code class="mono">{{ shortId(a.agent_id) }}</code></span>
                <span><em>申请人</em>{{ a.requested_by || '—' }}</span>
                <span v-if="a.reviewed_by"><em>审批人</em>{{ a.reviewed_by }} · {{ a.review_note || '无备注' }}</span>
                <span class="grow" :title="a.reason || ''"><em>原因</em>{{ a.reason || '—' }}</span>
                <span v-if="a.agent_missing" class="warn-chip">已不在册</span>
              </div>
              <p v-if="a.agent_missing && a.action !== 'uninstall_agent' && a.status === 'pending'" class="warn-text">
                终端已不在主机列表，批准可能失败；可先驳回。
              </p>
            </div>
            <div class="appr-card-side" v-if="a.status === 'pending' && isAdmin">
              <button
                type="button" class="btn sm primary" :disabled="busy"
                :title="a.agent_missing && a.action === 'uninstall_agent' ? '终端已不在册，将关闭此单' : ''"
                @click="decide(a.id, true)"
              >{{ a.agent_missing && a.action === 'uninstall_agent' ? '确认关闭' : '批准下发' }}</button>
              <button type="button" class="btn sm ghost" :disabled="busy" @click="decide(a.id, false)">驳回</button>
            </div>
            <div class="appr-card-side muted" v-else>
              <template v-if="a.command_id">指令 {{ shortId(a.command_id) }} · {{ ({pending:'待领取',sent:'已领取／待回执',done:'已回执成功',failed:'已回执失败',expired:'已过期',verification_required:'执行结果待核实',unknown:'状态未知'})[a.command_status] || '状态未知' }}</template>
              <template v-else-if="a.reviewed_by">{{ a.reviewed_by }}{{ a.review_note ? ' · ' + a.review_note : '' }}</template>
              <template v-else>—</template>
            </div>
          </article>
        </div>
        <div v-else class="mod-empty">
          <h3>暂无{{ apprStatus === 'pending' ? '待审' : '' }}审批单</h3>
          <p>分析员在「异常进程」点隔离/结束进程后会出现在这里。</p>
        </div>
      </div>
    </div>

    <!-- 告警案件：已下线，保留路由避免旧书签白屏 -->
    <div v-else-if="page === 'cases'" class="panel pad">
      <h3>告警案件已下线</h3>
      <p class="hint">该聚合页信息密度低、与威胁事件重复，已从菜单移除。请直接使用「威胁事件」查看与处置告警。</p>
      <button type="button" class="btn primary" @click="emit('goto', 'events')">前往威胁事件</button>
    </div>
    <div v-else-if="false && page === 'cases'" class="mod-page">
      <div class="panel mod-filters">
        <select v-model="caseStatus" class="search" @change="loadCases">
          <option value="open">状态：开放</option>
          <option value="investigating">状态：调查中</option>
          <option value="closed">状态：已关闭</option>
          <option value="">状态：全部</option>
        </select>
        <button v-if="isAdmin" type="button" class="btn sm primary" :disabled="busy" @click="doMergeCases">
          {{ busy ? '归并中…' : '归并近期告警' }}
        </button>
        <span class="mod-filter-hint">默认归并近 60 分钟内开放告警；同一主机追加进未关闭案件</span>
      </div>

      <div class="mod-stats cases-stats">
        <div class="panel mod-stat" data-s="critical">
          <em>危急</em>
          <b>{{ caseStats.critical }}</b>
          <small>需优先处置</small>
        </div>
        <div class="panel mod-stat" data-s="high">
          <em>高危</em>
          <b>{{ caseStats.high }}</b>
          <small>重点关注</small>
        </div>
        <div class="panel mod-stat">
          <em>本页案件</em>
          <b>{{ caseStats.total }}</b>
          <small>当前筛选</small>
        </div>
        <div class="panel mod-stat">
          <em>关联告警</em>
          <b>{{ caseStats.alerts }}</b>
          <small>已归并条数</small>
        </div>
      </div>

      <div class="panel mod-list-panel">
        <div class="panel-hd bare">
          <h3>告警案件列表 <em>（{{ cases.length }}）</em></h3>
        </div>
        <div class="mod-list" v-if="cases.length">
          <article
            v-for="c in cases" :key="c.id"
            class="case-card"
            :data-sev="String(c.severity || '').toLowerCase()"
            :data-s="c.status"
          >
            <header class="case-card-hd">
              <div class="case-title-row">
                <span class="sev-pill" :data-s="String(c.severity || '').toLowerCase()">{{ caseSevLabel(c.severity) }}</span>
                <span class="status-pill" :data-s="c.status">{{ caseStatusLabel(c.status) }}</span>
                <h3>{{ c.title || '未命名案件' }}</h3>
              </div>
              <time class="mono muted">{{ fmt(c.updated_at) }}</time>
            </header>

            <div class="case-meta">
              <div class="kv">
                <em>终端</em>
                <b>{{ c.hostname || shortId(c.agent_id) }}</b>
                <code class="mono muted sm" v-if="c.hostname">{{ shortId(c.agent_id) }}</code>
              </div>
              <div class="kv">
                <em>告警数</em>
                <b>{{ caseEventCount(c) }}</b>
              </div>
              <div class="kv">
                <em>创建</em>
                <span class="mono">{{ fmt(c.created_at) }}</span>
              </div>
            </div>

            <div class="case-summary" v-if="caseSummaryParts(c).length">
              <em>近期告警</em>
              <ul>
                <li v-for="(line, i) in caseSummaryParts(c)" :key="i">{{ line }}</li>
              </ul>
            </div>
            <p v-else class="muted sm">暂无摘要</p>

            <footer class="case-card-ft" v-if="isAdmin && c.status !== 'closed'">
              <button
                v-if="c.status === 'open'"
                type="button" class="btn sm"
                :disabled="busy"
                @click="setCase(c.id, 'investigating')"
              >标为调查中</button>
              <button
                v-if="c.status === 'investigating'"
                type="button" class="btn sm"
                :disabled="busy"
                @click="setCase(c.id, 'open')"
              >重新开放</button>
              <button type="button" class="btn sm ghost" :disabled="busy" @click="setCase(c.id, 'closed')">关闭案件</button>
            </footer>
            <footer class="case-card-ft muted" v-else-if="c.status === 'closed'">
              已关闭 · 更新于 {{ fmt(c.updated_at) }}
            </footer>
          </article>
        </div>
        <div v-else class="mod-empty">
          <h3>暂无{{ caseStatus ? caseStatusLabel(caseStatus) : '' }}案件</h3>
          <p>点「归并近期告警」，把同主机短窗口内的开放告警收成可跟进的案件。</p>
          <button v-if="isAdmin" type="button" class="btn sm primary" :disabled="busy" @click="doMergeCases">立即归并</button>
        </div>
      </div>
    </div>

    <!-- 定时狩猎 -->
    <div v-else-if="page === 'hunt-jobs'" class="stack">
      <div class="panel pad" v-if="isAdmin">
        <h3>新建任务</h3>
        <div class="form-row">
          <input v-model="huntForm.name" class="search" placeholder="名称（可选）" />
          <input v-model="huntForm.query" class="search grow" placeholder="狩猎关键字" />
          <input v-model.number="huntForm.cron_min" class="search narrow" type="number" min="5" title="间隔分钟" />
          <button type="button" class="btn sm" :disabled="busy" @click="saveHuntJob">保存</button>
          <button type="button" class="btn sm ghost" :disabled="busy" @click="tickJobs">扫描到期</button>
        </div>
        <div class="form-row">
          <select v-model="baselineAgent" class="search">
            <option value="">导出调查包 · 选择终端</option>
            <option v-for="a in agents" :key="a.agent_id || a.id" :value="a.agent_id || a.id">
              {{ a.hostname || a.agent_id || a.id }}
            </option>
          </select>
          <button type="button" class="btn sm" :disabled="busy" @click="makePack">生成调查包</button>
        </div>
      </div>
      <div class="panel pad">
        <table class="tbl" v-if="huntJobs.length">
          <thead><tr><th>名称</th><th>查询</th><th>间隔(分)</th><th>上次</th><th>命中</th><th></th></tr></thead>
          <tbody>
            <tr v-for="j in huntJobs" :key="j.id">
              <td>{{ j.name || j.id.slice(0,8) }}</td>
              <td class="mono">{{ j.query }}</td>
              <td>{{ j.cron_min }}</td>
              <td class="muted">{{ fmt(j.last_run_at) }}</td>
              <td>{{ j.last_hits }}</td>
              <td><button v-if="isAdmin" type="button" class="btn-text" @click="runJob(j.id)">立即跑</button></td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty sm">暂无定时狩猎任务</p>
      </div>
    </div>

    <!-- 基线：分区（行为 / 资产 / 流行度） -->
    <div v-else-if="page === 'baseline'" class="stack baseline-page">
      <div class="panel pad bl-hero">
        <div class="bl-hero-top">
          <div>
            <h3>主机基线</h3>
            <p class="hint">一次只看一类：行为频次、资产清单或全网流行度。列表可点开明细。</p>
          </div>
          <div class="form-row" style="margin:0">
            <select v-model="baselineAgent" class="search grow">
              <option v-for="a in agents" :key="a.agent_id || a.id" :value="a.agent_id || a.id">
                {{ a.hostname || a.agent_id || a.id }}
              </option>
            </select>
            <select v-model.number="baselineDays" class="search narrow" title="统计天数">
              <option :value="3">3 天</option>
              <option :value="7">7 天</option>
              <option :value="14">14 天</option>
              <option :value="30">30 天</option>
            </select>
            <button type="button" class="btn primary sm" :disabled="busy" @click="loadBaseline">{{ busy ? '生成中…' : '生成基线' }}</button>
          </div>
        </div>

        <nav class="bl-sec-tabs" aria-label="基线分区">
          <button type="button" class="bl-sec" :class="{ on: blSec === 'behavior' }" @click="blSec = 'behavior'">行为画像</button>
          <button type="button" class="bl-sec" :class="{ on: blSec === 'inventory' }" @click="blSec = 'inventory'">
            资产清单 <em v-if="blInvMods.length">{{ blInvMods.reduce((s, m) => s + (Number(m.count) || 0), 0) }}</em>
          </button>
          <button type="button" class="bl-sec" :class="{ on: blSec === 'prevalence' }" @click="blSec = 'prevalence'">全网流行度</button>
        </nav>

        <template v-if="baseline?.ok">
          <div class="bl-kpis">
            <div class="bl-kpi"><em>事件样本</em><b>{{ baseline.event_count || 0 }}</b><small>{{ baseline.since }} → 今</small></div>
            <div class="bl-kpi"><em>进程种类</em><b>{{ baseline.unique_processes || 0 }}</b><small>Top {{ (baseline.top_processes||[]).length }}</small></div>
            <div class="bl-kpi"><em>外联目的地</em><b>{{ baseline.unique_destinations || 0 }}</b><small>端口 {{ baseline.unique_ports || 0 }}</small></div>
            <div class="bl-kpi"><em>涉及用户</em><b>{{ baseline.unique_users || 0 }}</b><small>{{ (baseline.busy_hours||[]).slice(0,3).join(' · ') || '—' }}</small></div>
          </div>
          <div class="bl-meta">
            <span>{{ baseline.host?.hostname || baseline.agent_id }}</span>
            <span>{{ baseline.host?.os_family || '—' }}</span>
            <span>{{ baseline.host?.ip || '—' }}</span>
            <span>Agent {{ baseline.host?.version || '—' }}</span>
            <span>{{ baseline.first_event_at || '—' }} ~ {{ baseline.last_event_at || '—' }}</span>
            <span>生成 {{ baseline.built_at }}</span>
            <span v-if="baseline.signed_stats?.unsigned" class="pill warn">未签名 {{ baseline.signed_stats.unsigned }}</span>
            <span v-if="baseline.signed_stats?.signed" class="pill">已签名 {{ baseline.signed_stats.signed }}</span>
          </div>
        </template>
        <p v-else-if="!busy && blSec !== 'prevalence'" class="empty sm" style="margin-top:12px">选择终端后点「生成基线」。</p>

        <!-- 行为画像 -->
        <div v-if="blSec === 'behavior' && baseline?.ok" class="bl-sec-body">
          <div class="bl-grid">
            <div class="bl-card">
              <h4>常见进程 <small>时间线 · 点击展开</small></h4>
              <ul class="bl-list clickable">
                <li
                  v-for="([n,c],i) in (baseline.top_processes||[]).slice(0,20)"
                  :key="'p'+i"
                  :class="{ open: blOpen === blKey('p', i) }"
                  @click="toggleBl('p', i)"
                >
                  <div class="bl-row"><code>{{ n }}</code><em>{{ c }}</em></div>
                  <div v-if="blOpen === blKey('p', i)" class="bl-detail" @click.stop>
                    <div><span>出现次数</span><b>{{ c }}</b></div>
                    <div><span>说明</span><b>近 {{ baseline.days }} 天进程创建类事件中的频次</b></div>
                  </div>
                </li>
              </ul>
              <p v-if="!(baseline.top_processes||[]).length" class="empty sm">暂无进程事件</p>
            </div>
            <div class="bl-card">
              <h4>父 → 子进程链</h4>
              <ul class="bl-list clickable">
                <li
                  v-for="([n,c],i) in (baseline.top_parent_child||[]).slice(0,16)"
                  :key="'pc'+i"
                  :class="{ open: blOpen === blKey('pc', i) }"
                  @click="toggleBl('pc', i)"
                >
                  <div class="bl-row"><code>{{ n }}</code><em>{{ c }}</em></div>
                  <div v-if="blOpen === blKey('pc', i)" class="bl-detail" @click.stop>
                    <div><span>链</span><b class="mono">{{ n }}</b></div>
                    <div><span>次数</span><b>{{ c }}</b></div>
                  </div>
                </li>
              </ul>
              <p v-if="!(baseline.top_parent_child||[]).length" class="empty sm">暂无父子链</p>
            </div>
            <div class="bl-card">
              <h4>常见外联端口</h4>
              <ul class="bl-list clickable">
                <li
                  v-for="([n,c],i) in (baseline.top_ports||[]).slice(0,16)"
                  :key="'pt'+i"
                  :class="{ open: blOpen === blKey('pt', i) }"
                  @click="toggleBl('pt', i)"
                >
                  <div class="bl-row"><code>:{{ n }}</code><em>{{ c }}</em></div>
                  <div v-if="blOpen === blKey('pt', i)" class="bl-detail" @click.stop>
                    <div><span>端口</span><b>{{ n }}</b></div>
                    <div><span>外联次数</span><b>{{ c }}</b></div>
                  </div>
                </li>
              </ul>
              <p v-if="!(baseline.top_ports||[]).length" class="empty sm">暂无网络事件</p>
            </div>
            <div class="bl-card">
              <h4>常见外联目的地</h4>
              <ul class="bl-list clickable">
                <li
                  v-for="([n,c],i) in (baseline.top_destinations||[]).slice(0,16)"
                  :key="'d'+i"
                  :class="{ open: blOpen === blKey('d', i) }"
                  @click="toggleBl('d', i)"
                >
                  <div class="bl-row"><code>{{ n }}</code><em>{{ c }}</em></div>
                  <div v-if="blOpen === blKey('d', i)" class="bl-detail" @click.stop>
                    <div><span>目的地</span><b class="mono">{{ n }}</b></div>
                    <div><span>次数</span><b>{{ c }}</b></div>
                  </div>
                </li>
              </ul>
              <p v-if="!(baseline.top_destinations||[]).length" class="empty sm">暂无外联目的地</p>
            </div>
            <div class="bl-card">
              <h4>常触达文件 / 注册表</h4>
              <ul class="bl-list clickable">
                <li
                  v-for="([n,c],i) in (baseline.top_files||[]).slice(0,14)"
                  :key="'f'+i"
                  :class="{ open: blOpen === blKey('f', i) }"
                  @click="toggleBl('f', i)"
                >
                  <div class="bl-row"><code>{{ n }}</code><em>{{ c }}</em></div>
                  <div v-if="blOpen === blKey('f', i)" class="bl-detail" @click.stop>
                    <div><span>对象</span><b class="mono">{{ n }}</b></div>
                    <div><span>触达</span><b>{{ c }}</b></div>
                  </div>
                </li>
              </ul>
              <p v-if="!(baseline.top_files||[]).length" class="empty sm">暂无文件类事件</p>
            </div>
            <div class="bl-card">
              <h4>事件类型 · 用户 · 运行中</h4>
              <ul class="bl-list clickable">
                <li
                  v-for="([n,c],i) in (baseline.etype_breakdown||[]).slice(0,8)"
                  :key="'e'+i"
                  :class="{ open: blOpen === blKey('e', i) }"
                  @click="toggleBl('e', i)"
                >
                  <div class="bl-row"><code>{{ n }}</code><em>{{ c }}</em></div>
                  <div v-if="blOpen === blKey('e', i)" class="bl-detail" @click.stop>
                    <div><span>etype</span><b class="mono">{{ n }}</b></div>
                    <div><span>条数</span><b>{{ c }}</b></div>
                  </div>
                </li>
                <li
                  v-for="([n,c],i) in (baseline.top_users||[]).slice(0,6)"
                  :key="'u'+i"
                  :class="{ open: blOpen === blKey('u', i) }"
                  @click="toggleBl('u', i)"
                >
                  <div class="bl-row"><code>用户 {{ n }}</code><em>{{ c }}</em></div>
                </li>
                <li
                  v-for="(p,i) in (baseline.live_processes||[]).slice(0,8)"
                  :key="'lp'+i"
                  :class="{ open: blOpen === blKey('lp', i) }"
                  @click="toggleBl('lp', i)"
                >
                  <div class="bl-row">
                    <code>{{ p.name || '—' }}</code>
                    <em>PID {{ p.pid ?? '—' }}</em>
                  </div>
                  <div v-if="blOpen === blKey('lp', i)" class="bl-detail" @click.stop>
                    <div><span>路径</span><b class="mono">{{ p.path || '—' }}</b></div>
                    <div><span>用户</span><b>{{ p.user || '—' }}</b></div>
                    <button type="button" class="btn-text" @click="openInvHost('process')">在终端进程中查看 →</button>
                  </div>
                </li>
              </ul>
              <p v-if="!(baseline.etype_breakdown||[]).length && !(baseline.live_processes||[]).length" class="empty sm">暂无补充数据</p>
            </div>
          </div>
        </div>

        <!-- 资产清单 -->
        <div v-else-if="blSec === 'inventory'" class="bl-sec-body">
          <section class="bl-inv-panel" v-if="baseline?.ok && blInvMods.length">
            <header>
              <div>
                <h4>资产清单</h4>
                <p class="hint" style="margin:0">来自终端最近一次采集；点条目展开，或跳到终端详情看完整表。</p>
              </div>
              <button type="button" class="btn sm" @click="openInvHost(blInvActive?.id)">在终端中打开</button>
            </header>
            <div class="bl-inv-tabs">
              <button
                v-for="m in blInvMods"
                :key="m.id"
                type="button"
                class="bl-inv-tab"
                :class="{ on: (blInvActive && blInvActive.id) === m.id }"
                @click="blInvTab = m.id"
              >{{ m.label }} <em>{{ m.count }}</em></button>
            </div>
            <div v-if="blInvActive" class="bl-inv-body">
              <p class="muted sm" v-if="blInvActive.collected_at">采集于 {{ blInvActive.collected_at }}</p>
              <ul class="bl-list clickable">
                <li
                  v-for="(it, i) in blInvActive.items"
                  :key="'inv'+i"
                  :class="{ open: blOpen === blKey('inv-'+blInvActive.id, i) }"
                  @click="toggleBl('inv-'+blInvActive.id, i)"
                >
                  <div class="bl-row">
                    <code>{{ it.name || '—' }}</code>
                    <em>{{ it.status || it.extra || '详情' }}</em>
                  </div>
                  <div v-if="blOpen === blKey('inv-'+blInvActive.id, i)" class="bl-detail" @click.stop>
                    <div><span>路径 / 命令</span><b class="mono">{{ it.path || '—' }}</b></div>
                    <div><span>用户 / 位置</span><b>{{ it.user || '—' }}</b></div>
                    <div><span>状态</span><b>{{ it.status || '—' }}</b></div>
                    <div v-if="it.extra"><span>附加</span><b>{{ it.extra }}</b></div>
                    <button type="button" class="btn-text" @click="openInvHost(blInvActive.id)">在终端资产中查看 →</button>
                  </div>
                </li>
              </ul>
              <p v-if="!blInvActive.items.length" class="empty sm">有计数但样例为空，请到终端页点「刷新采集」。</p>
            </div>
          </section>
          <p v-else-if="baseline?.ok" class="bl-inv-empty">暂无服务/启动项等资产清单。请到「终端资产」对该主机点「刷新采集」（约 1～3 分钟后到齐）。</p>
          <p v-else-if="!busy" class="empty sm">先生成基线后再查看资产清单。</p>
        </div>

        <!-- 全网流行度 -->
        <div v-else-if="blSec === 'prevalence'" class="bl-sec-body bl-prev">
          <h4>全网流行度</h4>
          <p class="hint" style="margin:0 0 10px">查询路径 / 进程 / 域名 / Hash 在舰队中出现过多少台主机，判断「是否常见」。</p>
          <div class="form-row">
            <input v-model="prevalenceQ" class="search grow" placeholder="路径 / 进程名 / 域名 / Hash 片段" @keyup.enter="loadPrevalence" />
            <button type="button" class="btn sm" :disabled="busy" @click="loadPrevalence">查询</button>
          </div>
          <p v-if="prevalence?.ok" class="muted">
            时间线命中主机 {{ prevalence.hosts_in_timeline }} / 舰队 {{ prevalence.fleet_agents }}
            · 进程表主机 {{ prevalence.hosts_in_process_table }}
          </p>
          <ul v-if="prevalence?.hosts?.length" class="list">
            <li v-for="h in prevalence.hosts" :key="h.agent_id">
              <code>{{ h.hostname || h.agent_id }}</code> · {{ h.n }} 次 · 首次 {{ fmt(h.first_ts) }}
            </li>
          </ul>
        </div>
      </div>
    </div>

    <!-- ES 归档 -->
    <div v-else-if="page === 'archive'" class="panel pad">
      <div class="form-row">
        <input v-model="archive.q" class="search grow" placeholder="关键字" />
        <input v-model="archive.etype" class="search" placeholder="etype" />
        <input v-model.number="archive.hours" class="search narrow" type="number" min="1" />
        <button type="button" class="btn sm" :disabled="busy" @click="loadArchive">查询</button>
      </div>
      <table class="tbl" v-if="archive.items?.length">
        <thead><tr><th>时间</th><th>主机</th><th>类型</th><th>摘要</th></tr></thead>
        <tbody>
          <tr v-for="it in archive.items" :key="it.id">
            <td class="mono muted">{{ fmt(it.ts) }}</td>
            <td>{{ it.hostname || it.agent_id }}</td>
            <td class="mono">{{ it.etype }}</td>
            <td>{{ it.summary }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="empty sm">输入条件后查询（需 ES 可用）</p>
    </div>

    <!-- 持久化日对比 -->
    <div v-else-if="page === 'persist-daily'" class="panel pad">
      <button v-if="isAdmin" type="button" class="btn sm" :disabled="busy" @click="runPersist">立即对比全网</button>
      <div v-if="persistResult?.diffs?.length" class="stack mt">
        <article v-for="d in persistResult.diffs" :key="d.diff_id" class="diff-card">
          <header>
            <strong class="mono">{{ d.agent_id }}</strong>
            <button type="button" class="btn-text" @click="explainDiff(d.diff_id)">AI 解释</button>
          </header>
          <pre class="mono sm">{{ JSON.stringify(d.diff, null, 2) }}</pre>
          <p v-if="d.ai_note" class="muted">{{ d.ai_note }}</p>
        </article>
      </div>
      <p v-else class="empty sm mt">尚无差异结果</p>
    </div>

    <!-- AI 调查 -->
    <div v-else-if="page === 'ai-investigate'" class="stack">
      <div class="panel pad">
        <div class="form-row">
          <select v-model="invAgent" class="search grow">
            <option v-for="a in agents" :key="a.agent_id || a.id" :value="a.agent_id || a.id">
              {{ a.hostname || a.agent_id || a.id }}
            </option>
          </select>
          <input v-model.number="invHours" class="search narrow" type="number" min="1" max="168" title="回溯小时" />
          <input v-model="invQuestion" class="search grow" placeholder="调查问题（可选）" />
          <button type="button" class="btn sm" :disabled="busy" @click="runInvestigate">开始调查</button>
        </div>
      </div>
      <div v-if="invReport" class="panel pad">
        <h3>执行摘要</h3>
        <p>{{ invReport.executive_summary }}</p>
        <h4>发现</h4>
        <ul class="list"><li v-for="(f,i) in (invReport.findings||[])" :key="i">{{ f }}</li></ul>
        <h4>建议</h4>
        <ul class="list"><li v-for="(f,i) in (invReport.recommendations||[])" :key="i">{{ f }}</li></ul>
        <h4>工具审计</h4>
        <ul class="list mono sm">
          <li v-for="(c,i) in (invReport.tool_audit||[])" :key="i">{{ c.ts }} · {{ c.tool }} · {{ c.ok ? 'ok' : c.error }}</li>
        </ul>
      </div>
    </div>

    <!-- AI 规则草案 -->
    <div v-else-if="page === 'ai-rule-drafts'" class="stack">
      <div class="panel pad" v-if="isAdmin">
        <textarea v-model="draftPrompt" rows="3" class="ta" placeholder="用自然语言描述要检测的行为，例如：检测从 Temp 目录启动的 powershell 外联" />
        <button type="button" class="btn sm" :disabled="busy" @click="createDraft">生成草案</button>
      </div>
      <div class="panel pad">
        <table class="tbl" v-if="drafts.length">
          <thead><tr><th>时间</th><th>标题</th><th>草案</th><th></th></tr></thead>
          <tbody>
            <tr v-for="d in drafts" :key="d.id">
              <td class="mono muted">{{ fmt(d.created_at) }}</td>
              <td>{{ d.title }}</td>
              <td class="mono sm">{{ (draftObj(d).patterns || []).join(', ') }} · {{ (draftObj(d).modules || []).join(',') }}</td>
              <td class="actions" v-if="isAdmin">
                <button type="button" class="btn sm" @click="reviewDraft(d.id, true)">批准上线</button>
                <button type="button" class="btn sm ghost" @click="reviewDraft(d.id, false)">驳回</button>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty sm">暂无待审草案</p>
      </div>
    </div>

  </section>
</template>

<style scoped>
.extras-page.mod-shell {
  overflow: hidden;
  display: flex; flex-direction: column; gap: 12px; min-height: 0;
  background: #e8edf5 !important;
  padding: 16px 18px 14px;
  box-sizing: border-box;
}
.extras-page.mod-shell > .page-hd {
  flex-shrink: 0; margin-bottom: 0;
  display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;
  background: #fff;
  border: 1px solid #d7dee8;
  border-radius: 14px;
  padding: 16px 20px;
  box-shadow: 0 1px 3px rgba(15, 23, 42, .06);
}
.extras-page.mod-shell > .page-hd h1 {
  margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -.02em; color: #101828;
}
.extras-page.mod-shell > .page-hd .desc {
  margin: 6px 0 0; color: #667085; font-size: 13px; line-height: 1.5;
}
.extras-page.mod-shell > .page-hd .hd-right {
  display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
}
.extras-page.mod-shell > .banner {
  flex-shrink: 0; margin: 0;
  background: #fff;
  border: 1px solid #d7dee8;
  border-radius: 12px;
  padding: 10px 14px;
  box-shadow: 0 1px 2px rgba(15, 23, 42, .04);
}
.extras-page.mod-shell > .banner.ok {
  background: #f3faf6;
  border-color: #b7e4c7;
  color: #146c2e;
}
.extras-page.mod-shell > .banner.err {
  background: #fff5f5;
  border-color: #f5c2c0;
  color: #a1281d;
}
.extras-page.mod-shell > .mod-page { flex: 1; min-height: 0; }
.extras-page .panel {
  background: #fff;
  border: 1px solid #d7dee8;
  border-radius: 14px;
  box-shadow: 0 1px 3px rgba(15, 23, 42, .06);
}
.extras-page .panel.pad { padding: 18px 20px; }
.extras-page .panel-hd {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 12px 16px; border-bottom: 1px solid #e8eef6;
}
.extras-page .panel-hd.bare { border: 0; padding: 0; }
.extras-page .panel-hd h3 { margin: 0; font-size: 14px; font-weight: 650; color: #101828; }
.extras-page .toolbar, .form-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }
.extras-page .search.grow { flex: 1; min-width: 160px; }
.extras-page .search.narrow { width: 88px; }
.extras-page .stack { display: flex; flex-direction: column; gap: 12px; }
.extras-page .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; }
.extras-page .list { margin: 8px 0 0; padding-left: 18px; }
.extras-page .list li { margin: 4px 0; }
.baseline-page .bl-hero-top {
  display: flex; flex-wrap: wrap; justify-content: space-between; gap: 14px; align-items: flex-start;
}
.baseline-page .bl-hero-top h3 { margin: 0 0 4px; font-size: 18px; }
.baseline-page .bl-sec-tabs {
  display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; padding: 4px;
  background: #f2f5f8; border-radius: 12px; width: fit-content; max-width: 100%;
}
.baseline-page .bl-sec {
  border: 0; background: transparent; border-radius: 9px; padding: 7px 14px;
  font-size: 13px; font-weight: 650; color: #475467; cursor: pointer;
}
.baseline-page .bl-sec em { font-style: normal; margin-left: 4px; color: #98a2b3; font-weight: 700; }
.baseline-page .bl-sec.on { background: #fff; color: #101828; box-shadow: 0 1px 3px rgba(15,23,42,.08); }
.baseline-page .bl-sec.on em { color: #667085; }
.baseline-page .bl-sec-body { margin-top: 14px; }
.baseline-page .bl-prev h4 { margin: 0 0 6px; font-size: 14px; color: #101828; }
.baseline-page .bl-kpis {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-top: 16px;
}
.baseline-page .bl-kpi {
  padding: 14px 16px; border-radius: 12px; background: linear-gradient(165deg, #ffffff, #f3f7fb);
  border: 1px solid #dce5ef; border-top: 3px solid #7a9eb8;
  display: flex; flex-direction: column; gap: 4px;
  box-shadow: 0 1px 2px rgba(15, 23, 42, .04);
}
.baseline-page .bl-kpi:nth-child(2) { border-top-color: #2f6fad; }
.baseline-page .bl-kpi:nth-child(3) { border-top-color: #0f766e; }
.baseline-page .bl-kpi:nth-child(4) { border-top-color: #b54708; }
.baseline-page .bl-kpi em { font-style: normal; font-size: 12px; color: #667085; font-weight: 650; }
.baseline-page .bl-kpi b { font-size: 24px; letter-spacing: -.04em; color: #101828; line-height: 1.15; }
.baseline-page .bl-kpi small { color: #98a2b3; font-size: 11px; }
.baseline-page .bl-meta {
  display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; align-items: center;
  font-size: 12px; color: #667085;
}
.baseline-page .bl-meta > span:not(.pill) {
  padding: 3px 8px; border-radius: 6px; background: #f2f5f8;
}
.baseline-page .bl-inv-panel {
  margin-top: 0; border: 1px solid #dce5ef; border-radius: 14px; overflow: hidden; background: #fbfcfe;
}
.baseline-page .bl-inv-panel > header {
  display: flex; justify-content: space-between; gap: 12px; align-items: flex-start;
  padding: 12px 14px; border-bottom: 1px solid #e8eef6; background: #fff;
}
.baseline-page .bl-inv-panel h4 { margin: 0 0 4px; font-size: 14px; color: #101828; }
.baseline-page .bl-inv-tabs {
  display: flex; flex-wrap: wrap; gap: 6px; padding: 10px 12px; background: #fff; border-bottom: 1px solid #eef2f6;
}
.baseline-page .bl-inv-tab {
  border: 1px solid #d0d5dd; background: #fff; border-radius: 999px; padding: 5px 12px;
  font-size: 12.5px; font-weight: 600; color: #344054; cursor: pointer;
}
.baseline-page .bl-inv-tab em { font-style: normal; margin-left: 4px; color: #667085; }
.baseline-page .bl-inv-tab.on { background: #122033; color: #fff; border-color: #122033; }
.baseline-page .bl-inv-tab.on em { color: #cbd5e1; }
.baseline-page .bl-inv-body { padding: 4px 0 8px; background: #fff; max-height: 340px; overflow: auto; }
.baseline-page .bl-inv-empty {
  margin: 14px 0 0; padding: 12px 14px; border-radius: 10px; background: #fff8eb; color: #b54708;
  border: 1px solid #f5d0a8; font-size: 12.5px;
}
.baseline-page .bl-grid {
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-top: 0;
}
.baseline-page .bl-card {
  border: 1px solid #dce5ef; border-radius: 14px; padding: 0; background: #fff;
  overflow: hidden; min-height: 180px; display: flex; flex-direction: column;
  box-shadow: 0 1px 2px rgba(15, 23, 42, .04);
}
.baseline-page .bl-card h4 {
  margin: 0; padding: 11px 14px; font-size: 13px; color: #243e54;
  background: linear-gradient(180deg, #f8fafc, #f3f6fa); border-bottom: 1px solid #e8eef6;
}
.baseline-page .bl-card h4 small { color: #98a2b3; font-weight: 500; margin-left: 6px; }
.baseline-page .bl-list { list-style: none; margin: 0; padding: 4px 0; max-height: 300px; overflow: auto; flex: 1; }
.baseline-page .bl-list li {
  padding: 0; border-bottom: 1px solid #f2f5f8; font-size: 12.5px;
}
.baseline-page .bl-list li:nth-child(even) { background: #fafbfc; }
.baseline-page .bl-list.clickable li { cursor: pointer; }
.baseline-page .bl-list.clickable li:hover { background: #f0f6ff; }
.baseline-page .bl-list.clickable li.open { background: #eef6ff; }
.baseline-page .bl-row {
  display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px 12px; align-items: start;
  padding: 8px 14px;
}
.baseline-page .bl-list code { color: #1d2939; word-break: break-all; font-size: 12px; }
.baseline-page .bl-list em {
  font-style: normal; color: #344054; font-variant-numeric: tabular-nums; font-weight: 700;
  background: #eef2f7; border-radius: 999px; padding: 1px 8px; font-size: 11.5px;
}
.baseline-page .bl-detail {
  display: grid; gap: 6px; padding: 0 14px 10px 14px; border-top: 1px dashed #e4ebf3;
  background: #f8fbff;
}
.baseline-page .bl-detail > div {
  display: grid; grid-template-columns: 88px minmax(0, 1fr); gap: 8px; font-size: 12px;
}
.baseline-page .bl-detail span { color: #667085; }
.baseline-page .bl-detail b { font-weight: 600; color: #101828; word-break: break-all; }
.baseline-page .bl-detail .btn-text { justify-self: start; margin-top: 4px; }
.baseline-page .empty.sm { padding: 18px 14px; margin: 0; }
.baseline-page .pill.warn { background: #fff1f0; color: #b42318; }
@media (max-width: 900px) {
  .baseline-page .bl-kpis, .baseline-page .bl-grid { grid-template-columns: 1fr; }
}
.extras-page .tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.extras-page .tbl th, .extras-page .tbl td { text-align: left; padding: 8px 10px; border-bottom: 1px solid rgba(0,0,0,.06); vertical-align: top; }
.extras-page .actions { white-space: nowrap; }
.extras-page .banner { margin: 0 0 12px; padding: 8px 12px; border-radius: 8px; }
.extras-page .banner.ok { background: #e8f7ee; color: #146c2e; }
.extras-page .banner.err { background: #fdecea; color: #a1281d; }
.extras-page .ta { width: 100%; margin-bottom: 8px; padding: 10px; border-radius: 8px; border: 1px solid rgba(0,0,0,.12); font: inherit; }
.extras-page .diff-card { border: 1px solid rgba(0,0,0,.08); border-radius: 10px; padding: 12px; margin-top: 10px; }
.extras-page .diff-card header { display: flex; justify-content: space-between; align-items: center; }
.extras-page .mt { margin-top: 12px; }
.extras-page pre.sm { font-size: 12px; overflow: auto; max-height: 220px; }
.extras-page .metrics { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 8px; }
.extras-page .metric { min-width: 88px; padding: 8px 12px; border-radius: 10px; background: rgba(0,0,0,.03); }
.extras-page .metric b { display: block; font-size: 18px; }
.extras-page .metric span { color: #667; font-size: 12px; }
.extras-page .chk { display: inline-flex; align-items: center; gap: 4px; font-size: 13px; color: #445; }
.extras-page .spark-row { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px; align-items: flex-end; }
.extras-page .spark-block.grow { flex: 1; min-width: 160px; }
.extras-page .spark { display: flex; align-items: flex-end; gap: 2px; height: 44px; }
.extras-page .spark i { display: block; width: 6px; border-radius: 2px 2px 0 0; background: #3b82f6; }
.extras-page .tags { display: flex; flex-wrap: wrap; gap: 6px; }
.extras-page .sm { font-size: 12px; }
.extras-page .break { word-break: break-word; max-width: 280px; }
.extras-page .pill { display: inline-flex; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; background: #eef2f7; color: #475467; }
.extras-page .pill[data-s="pending"] { background: #fef0c7; color: #b54708; }
.extras-page .pill[data-s="approved"] { background: #e8f7ee; color: #146c2e; }
.extras-page .pill[data-s="rejected"] { background: #fdecea; color: #a1281d; }
.mod-page {
  display: flex; flex-direction: column; gap: 12px;
  flex: 1; min-height: 0; overflow: hidden;
}
.mod-filters {
  flex-shrink: 0;
  display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
  padding: 12px 16px;
  background: #fff;
}
.mod-filters .search {
  min-width: 160px; padding: 8px 10px; border: 1px solid #d0d5dd; border-radius: 8px;
  font: inherit; background: #fff; color: #101828;
}
.mod-filter-hint { color: #667085; font-size: 12px; margin-left: 4px; }

.mod-stats {
  flex-shrink: 0;
  display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px;
}
.mod-stats.cases-stats { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.mod-stat {
  padding: 16px 18px; min-height: 102px;
  display: flex; flex-direction: column; gap: 6px;
  background: #fff;
}
.mod-stat em {
  font-style: normal; font-size: 12px; color: #98a2b3; font-weight: 650;
}
.mod-stat b {
  font-size: 28px; letter-spacing: -.04em; line-height: 1;
  font-variant-numeric: tabular-nums; color: #101828;
}
.mod-stat small { color: #98a2b3; font-size: 12px; }
.mod-stat[data-s="pending"] b { color: #b54708; }
.mod-stat[data-s="critical"] b { color: #b42318; }
.mod-stat[data-s="high"] b { color: #b54708; }
.mod-stat.tip p {
  margin: 0; color: #475467; font-size: 13px; line-height: 1.5;
}

.mod-list-panel {
  flex: 1; min-height: 0; overflow: hidden;
  display: flex; flex-direction: column; padding: 0;
  background: #fff;
}
.mod-list-panel > .panel-hd {
  flex-shrink: 0; padding: 14px 16px; border-bottom: 1px solid #e8eef6;
  display: flex; align-items: center; justify-content: space-between;
  background: #fff;
}
.mod-list-panel > .panel-hd h3 {
  margin: 0; font-size: 14px; color: #101828; font-weight: 700;
}
.mod-list-panel > .panel-hd h3 em {
  font-style: normal; color: #98a2b3; font-weight: 600; font-size: 13px;
}
.mod-list {
  flex: 1; min-height: 0; overflow: auto;
  display: flex; flex-direction: column; gap: 10px;
  padding: 14px 16px 18px;
  background: #f5f7fb;
  -webkit-overflow-scrolling: touch;
}
.mod-empty {
  padding: 48px 24px; text-align: center; color: #667085;
  display: flex; flex-direction: column; gap: 10px; align-items: center;
}
.mod-empty h3 { margin: 0; color: #101828; font-size: 16px; }
.mod-empty p { margin: 0; max-width: 420px; line-height: 1.55; font-size: 13px; }

.appr-card {
  display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px 16px; align-items: center;
  padding: 12px 14px; border-radius: 12px; border: 1px solid #d7dee8;
  border-left: 3px solid #98a2b3; background: #fff;
  box-shadow: 0 1px 2px rgba(15, 23, 42, .04);
}
.appr-card[data-s="pending"] { border-left-color: #f79009; }
.appr-card[data-s="approved"] { border-left-color: #12b76a; }
.appr-card[data-s="rejected"] { border-left-color: #f04438; }
.appr-card.missing { background: #fffaf9; }
.appr-card-main { min-width: 0; display: flex; flex-direction: column; gap: 6px; }
.appr-card-top { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.appr-title { font-size: 14px; color: #101828; font-weight: 700; }
.appr-param {
  max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-size: 12px; color: #667085;
}
.appr-time { margin-left: auto; font-size: 12px; color: #98a2b3; }
.appr-meta {
  display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: center;
  font-size: 12px; color: #344054;
}
.appr-meta > span { display: inline-flex; align-items: center; gap: 6px; min-width: 0; }
.appr-meta > span.grow { flex: 1; min-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.appr-meta em { font-style: normal; color: #98a2b3; font-weight: 650; font-size: 11px; }
.appr-meta b { color: #101828; font-weight: 650; }
.appr-meta code { font-size: 11px; color: #98a2b3; }
.appr-card-side {
  display: flex; flex-direction: column; gap: 6px; align-items: stretch;
  min-width: 108px;
}
.appr-card-side.muted { font-size: 12px; color: #667085; text-align: right; max-width: 160px; }
.warn-chip {
  display: inline-flex; padding: 1px 7px; border-radius: 6px; font-size: 11px; font-weight: 700;
  background: #fee4e2; color: #b42318;
}
.warn-text { margin: 0; color: #b54708; font-size: 12px; }

.case-card {
  padding: 14px 16px; border-radius: 12px; border: 1px solid #d7dee8;
  border-left: 3px solid #98a2b3; display: flex; flex-direction: column; gap: 10px;
  background: #fff;
  box-shadow: 0 1px 2px rgba(15, 23, 42, .04);
}
.case-card[data-sev="critical"] { border-left-color: #f04438; }
.case-card[data-sev="high"] { border-left-color: #f79009; }
.case-card[data-sev="medium"] { border-left-color: #fdb022; }
.case-card[data-s="closed"] { opacity: .9; }
.case-card-hd { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
.case-title-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; min-width: 0; }
.case-title-row h3 { margin: 0; font-size: 14px; color: #101828; font-weight: 700; line-height: 1.35; }
.sev-pill, .status-pill {
  display: inline-flex; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700;
}
.sev-pill { background: #f2f4f7; color: #475467; }
.sev-pill[data-s="critical"] { background: #fee4e2; color: #b42318; }
.sev-pill[data-s="high"] { background: #fef0c7; color: #b54708; }
.sev-pill[data-s="medium"] { background: #fffaeb; color: #b54708; }
.sev-pill[data-s="low"] { background: #eef2f7; color: #667085; }
.status-pill { background: #eef4ff; color: #2f6fed; }
.status-pill[data-s="open"] { background: #eef4ff; color: #2f6fed; }
.status-pill[data-s="investigating"] { background: #f4f3ff; color: #6941c6; }
.status-pill[data-s="closed"] { background: #eef2f7; color: #667085; }

.case-meta {
  display: grid; grid-template-columns: 1.4fr .7fr 1fr; gap: 10px 16px;
  padding: 10px 12px; border-radius: 8px; background: #f8fafc; border: 1px solid #e8eef6;
}
.case-meta .kv { display: flex; flex-direction: column; gap: 3px; min-width: 0; font-size: 13px; color: #344054; }
.case-meta .kv em { font-style: normal; font-size: 11px; color: #98a2b3; font-weight: 650; }
.case-meta .kv b { color: #101828; }

.case-summary em {
  display: block; font-style: normal; font-size: 11px; color: #98a2b3; font-weight: 650; margin-bottom: 6px;
}
.case-summary ul {
  list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px;
}
.case-summary li {
  position: relative; padding: 8px 10px 8px 14px; border-radius: 8px;
  background: #fff; border: 1px solid #eef2f7; color: #344054; font-size: 12px; line-height: 1.45;
  word-break: break-word;
}
.case-summary li::before {
  content: ''; position: absolute; left: 0; top: 8px; bottom: 8px; width: 3px; border-radius: 2px; background: #f04438;
}
.case-card-ft { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }

@media (max-width: 1100px) {
  .mod-stats, .mod-stats.cases-stats { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 900px) {
  .extras-page .grid2 { grid-template-columns: 1fr; }
  .mod-stats, .mod-stats.cases-stats { grid-template-columns: 1fr; }
  .appr-card { grid-template-columns: 1fr; }
  .appr-card-side { flex-direction: row; min-width: 0; }
  .appr-time { margin-left: 0; width: 100%; }
  .case-meta { grid-template-columns: 1fr; }
}
.extras-page.mod-shell { background: var(--bg, #f4f1ef) !important; }
.extras-page.mod-shell > .page-hd {
  background: linear-gradient(120deg, #fff 48%, #fdf3ef);
  border: 1px solid var(--line);
  border-left: 4px solid var(--accent, #e2562c);
  border-radius: 10px;
  box-shadow: var(--shadow);
}
.extras-page.mod-shell > .page-hd h1 { color: #2b2320; font-size: 24px; font-weight: 750; }
.extras-page .panel { border-color: var(--line); border-radius: 10px; box-shadow: var(--shadow); }
.extras-page .tbl th { background: linear-gradient(180deg, #faf7f5, #f3ede9); color: #5a4b42; font-weight: 700; }
.extras-page .tbl td { border-bottom-color: #f0eae5; }
.mod-stats.cases-stats .mod-stat { border-top: 3px solid #d18c72; }
.case-card { border-color: var(--line); border-radius: 9px; }
.case-meta { background: #fdf7f4; border-color: #efe0d8; }
.case-meta .kv em, .case-summary em { color: #806b5f; }
.case-summary li { border-color: #f0e6e0; }

/* Keep operational lists legible and usable across the full set of extra pages. */
.extras-page .tbl { border-collapse: separate; border-spacing: 0; }
.extras-page .tbl th { position: sticky; top: 0; z-index: 1; }
.extras-page .tbl tbody tr:nth-child(even) { background: #fdfaf8; }
.extras-page .tbl tbody tr:hover { background: #fdf2ec; }
.extras-page :is(button, input, select, textarea, a):focus-visible { outline: 2px solid var(--accent, #e2562c); outline-offset: 2px; }
.extras-page .mod-stat, .extras-page .case-card, .extras-page .appr-card { min-width: 0; }
.extras-page .appr-param, .extras-page .case-title-row h3 { overflow-wrap: anywhere; }
@media (max-width: 640px) {
  .extras-page.mod-shell { padding: 10px; gap: 9px; }
  .extras-page.mod-shell > .page-hd { padding: 12px; flex-wrap: wrap; }
  .extras-page .mod-filters { padding: 10px; }
  .extras-page .mod-filter-hint { flex-basis: 100%; margin-left: 0; }
  .extras-page .mod-list { padding: 10px; }
  .extras-page .appr-card-side { flex-wrap: wrap; }
}
</style>
