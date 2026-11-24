<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { listAgents, listLineageRisk, getLineageDetail, createAgentCommand, runAiInvestigate } from './api'

const props = defineProps({ isAdmin: { type: Boolean, default: false } })
const emit = defineEmits(['goto'])

const busy = ref(false)
const actBusy = ref(false)
const err = ref('')
const tip = ref('')
const agents = ref([])
const agentId = ref('')
const hours = ref(72)
const minScore = ref(10)
const scanned = ref(0)
const stats = ref(null)
const items = ref([])
const selectedKey = ref('')
const detail = ref(null)
const hoverNode = ref('')
const focusNode = ref('')
const sevFilter = ref('')
const listQ = ref('')

function matchListItem(it, q) {
  if (!q) return true
  const pid = it?.root?.pid != null ? String(it.root.pid) : ''
  const blob = [
    it?.root?.name, it?.root?.path, it?.hostname, it?.agent_id, pid,
    ...(it?.tactic_names || []),
    it?.top_signals?.[0]?.title,
  ].map((x) => String(x || '').toLowerCase()).join(' ')
  return q.split(/\s+/).filter(Boolean).every((tok) => blob.includes(tok))
}

const filteredItems = computed(() => {
  const f = sevFilter.value
  const q = listQ.value.trim().toLowerCase()
  let list = items.value || []
  if (f) list = list.filter((x) => String(x.severity || '').toLowerCase() === f)
  if (q) list = list.filter((x) => matchListItem(x, q))
  return list
})
const selected = computed(() => filteredItems.value.find((x) => keyOf(x) === selectedKey.value) || null)

function keyOf(it) { return `${it.agent_id}:${it.root?.entity_id || ''}` }
function fmt(t) { return String(t || '').replace('T', ' ').slice(0, 19) || '—' }
function fmtTime(t) { const s = fmt(t); return s.length >= 19 ? s.slice(11) : s }
function sevLabel(s) {
  return ({ critical: '危急', high: '高危', medium: '中危', low: '低危' })[String(s || '').toLowerCase()] || s || '—'
}
function signedLabel(s) {
  const v = String(s || '').toLowerCase()
  if (!v) return '—'
  if (v === 'valid' || v === 'signed' || v === 'trusted') return '签名有效'
  if (v === 'notsigned' || v === 'unsigned') return '无签名'
  if (v === 'hashmismatch') return '哈希不匹配'
  if (v === 'nottrusted') return '不可信'
  return s
}
function shortName(n, nMax = 22) {
  const s = String(n || '未知进程')
  return s.length > nMax ? s.slice(0, nMax - 1) + '…' : s
}
function nodeSev(n) {
  const s = Math.max(Number(n?.own_score || 0), Number(n?.propagated_score || 0))
  if (s >= 80) return 'critical'
  if (s >= 40 || n?.has_signal) return 'high'
  if (s >= 15) return 'medium'
  return 'low'
}
function nodeById(id) {
  return (detail.value?.nodes || []).find((n) => n.entity_id === id) || null
}

function syncSelectionToFilter() {
  const list = filteredItems.value
  if (!list.length) { selectedKey.value = ''; detail.value = null; return }
  if (!list.find((x) => keyOf(x) === selectedKey.value)) openDetail(list[0])
}

function applySevFilter(next) {
  sevFilter.value = next
  syncSelectionToFilter()
}
function toggleSev(s) { applySevFilter(sevFilter.value === s ? '' : s) }

watch(listQ, () => { syncSelectionToFilter() })

async function loadAgents() {
  try {
    const r = await listAgents()
    agents.value = r.items || []
    if (!agentId.value && agents.value[0]) agentId.value = agents.value[0].agent_id || agents.value[0].id || ''
  } catch { /* ignore */ }
}

async function score() {
  busy.value = true
  err.value = ''
  tip.value = ''
  detail.value = null
  focusNode.value = ''
  try {
    const r = await listLineageRisk({
      agent_id: agentId.value || '', hours: hours.value, min_score: minScore.value, limit: 100,
    })
    scanned.value = r.scanned_signals || 0
    stats.value = r.stats || null
    items.value = r.items || []
    if (sevFilter.value && !items.value.some((x) => String(x.severity || '').toLowerCase() === sevFilter.value)) {
      sevFilter.value = ''
    }
    await nextTick()
    const list = filteredItems.value
    if (list.length) await openDetail(list[0])
    else { selectedKey.value = ''; detail.value = null }
  } catch (e) {
    err.value = e.message || String(e)
  } finally {
    busy.value = false
  }
}

async function openDetail(it) {
  selectedKey.value = keyOf(it)
  focusNode.value = ''
  busy.value = true
  try {
    detail.value = await getLineageDetail(it.agent_id, it.root.entity_id, { hours: hours.value })
    focusNode.value = it.root?.entity_id || detail.value?.summary?.root?.entity_id || ''
  } catch (e) {
    err.value = e.message || String(e)
  } finally {
    busy.value = false
  }
}

const pendingApprovalId = ref('')

async function runRec(r) {
  if (!selected.value?.agent_id || !r?.action) return
  const aid = selected.value.agent_id
  const params = { ...(r.params || {}) }
  actBusy.value = true
  tip.value = ''
  err.value = ''
  pendingApprovalId.value = ''
  try {
    if (r.action === 'investigate') {
      await runAiInvestigate(aid, {
        focus: selected.value.root?.name || '',
        entity_id: selected.value.root?.entity_id || '',
        hours: hours.value,
      })
      tip.value = '已发起 AI 调查'
    } else {
      const needApprHint = props.isAdmin
        ? '管理员将直接下发到终端。'
        : '高危动作会先进入「处置审批」，管理员批准后才下发到终端。'
      if (!window.confirm(`确认执行：${r.label}？\n\n${needApprHint}`)) return
      const reason = `异常进程分析 · ${selected.value.root?.name || ''} pid=${selected.value.root?.pid || ''} · 分 ${Math.round(Number(selected.value.score) || 0)}`
      const res = await createAgentCommand(aid, r.action, params, { reason })
      if (res?.needs_approval || res?.approval_id) {
        pendingApprovalId.value = res.approval_id || ''
        tip.value = `${r.label}已提交审批（待管理员批准后才会隔离/结束进程）`
      } else {
        tip.value = `${r.label}已下发${res?.id ? ' · 指令 ' + res.id : ''}`
      }
    }
  } catch (e) {
    err.value = e.message || String(e)
  } finally {
    actBusy.value = false
  }
}

function goApprovals() {
  emit('goto', 'approvals')
}

const treeLayout = computed(() => {
  const nodes = detail.value?.nodes || []
  const edges = detail.value?.edges || []
  if (!nodes.length) return { width: 0, height: 0, positions: {}, paths: [], NODE_W: 0, NODE_H: 0, layers: 0 }
  const byId = Object.fromEntries(nodes.map((n) => [n.entity_id, n]))
  const kids = {}
  for (const e of edges) (kids[e.from] ||= []).push(e.to)
  const rootId = detail.value?.summary?.root?.entity_id || nodes.find((n) => n.is_root)?.entity_id || nodes[0].entity_id
  const layers = []
  const seen = new Set()
  let cur = [rootId]
  while (cur.length && layers.length < 10) {
    const layer = cur.filter((id) => byId[id] && !seen.has(id))
    layer.forEach((id) => seen.add(id))
    if (!layer.length) break
    layers.push(layer)
    const next = []
    for (const id of layer) for (const c of kids[id] || []) if (!seen.has(c)) next.push(c)
    cur = next
  }
  for (const n of nodes) {
    if (!seen.has(n.entity_id)) {
      if (!layers.length) layers.push([])
      layers[layers.length - 1].push(n.entity_id)
    }
  }
  const COL_W = 228
  const NODE_W = 188
  const NODE_H = 72
  const GAP = 18
  const PAD = 28
  const positions = {}
  layers.forEach((col, ci) => {
    const colH = col.length * (NODE_H + GAP) - GAP
    const maxH = Math.max(...layers.map((c) => c.length * (NODE_H + GAP) - GAP), colH)
    const offsetY = PAD + Math.max(0, (maxH - colH) / 2)
    col.forEach((id, ri) => {
      positions[id] = {
        x: PAD + ci * COL_W, y: offsetY + ri * (NODE_H + GAP),
        w: NODE_W, h: NODE_H,
        cx: PAD + ci * COL_W + NODE_W / 2,
        cy: offsetY + ri * (NODE_H + GAP) + NODE_H / 2,
      }
    })
  })
  const height = Math.max(
    PAD * 2 + Math.max(...layers.map((c) => c.length * (NODE_H + GAP) - GAP), NODE_H) + 8,
    280,
  )
  const width = PAD * 2 + Math.max(layers.length, 1) * COL_W
  const paths = edges.map((e) => {
    const a = positions[e.from], b = positions[e.to]
    if (!a || !b) return null
    const x1 = a.x + a.w
    const y1 = a.cy
    const x2 = b.x
    const y2 = b.cy
    const mx = x1 + (x2 - x1) * 0.45
    return {
      d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`,
      hot: !!(byId[e.to]?.has_signal || byId[e.from]?.has_signal),
      midX: (x1 + x2) / 2,
      midY: (y1 + y2) / 2,
    }
  }).filter(Boolean)
  return { width, height, positions, paths, NODE_W, NODE_H, layers: layers.length }
})

const scorePct = computed(() => Math.max(6, Math.min(100, Math.round((Number(selected.value?.score || 0) / 200) * 100))))

const storyGrouped = computed(() => (detail.value?.storyline || []).map((s) => {
  const title = String(s.title || '')
  let kind = 'signal'
  if (/外联|网络|connect|http|解析|dns/i.test(title)) kind = 'net'
  else if (/进程|创建|落地|文件|注入|执行/i.test(title)) kind = 'proc'
  else if (/持久|注册表|任务|启动/i.test(title)) kind = 'persist'
  return { ...s, kind }
}))

const storyByNode = computed(() => {
  const id = focusNode.value
  if (!id) return storyGrouped.value
  const hit = storyGrouped.value.filter((s) => String(s.entity_id || '') === id)
  return hit.length ? hit : []
})

const topSignals = computed(() => (selected.value?.top_signals || []).slice(0, 6))
/** 点击选中优先；悬停仅作树高亮，详情面板只跟 focus */
const focusInfo = computed(() => nodeById(focusNode.value) || null)
const childNodes = computed(() => {
  if (!focusInfo.value || !detail.value?.edges) return []
  const ids = detail.value.edges
    .filter((e) => e.from === focusInfo.value.entity_id)
    .map((e) => e.to)
  return ids.map((id) => nodeById(id)).filter(Boolean)
})
const childCount = computed(() => childNodes.value.length)
const focusActions = computed(() => {
  const id = focusNode.value
  if (!id) return []
  const seen = new Set()
  const out = []
  for (const s of storyGrouped.value) {
    if (String(s.entity_id || '') !== id) continue
    const cmd = String(s.command_line || '').trim()
    const remote = String(s.remote || '').trim()
    const target = String(s.target || '').trim()
    const line = cmd || (remote ? `→ ${remote}` : '') || (target ? `目标 ${target}` : '') || String(s.title || '')
    const key = `${s.etype || ''}|${line}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ ...s, action_line: line })
  }
  return out.slice(0, 12)
})
const copiedCmd = ref('')

function selectNode(id) { focusNode.value = id }
async function copyText(text, key = 'cmd') {
  const t = String(text || '').trim()
  if (!t) return
  try {
    await navigator.clipboard.writeText(t)
    copiedCmd.value = key
    setTimeout(() => { if (copiedCmd.value === key) copiedCmd.value = '' }, 1400)
  } catch { /* ignore */ }
}

onMounted(async () => { await loadAgents(); await score() })
watch(agentId, () => score())
</script>

<template>
  <section class="page lr">
    <header class="lr-top">
      <div class="lr-title">
        <p class="eyebrow">进程狩猎</p>
        <h1>异常进程</h1>
      </div>
      <div class="lr-toolbar">
        <label><span>终端</span>
          <select v-model="agentId" class="field">
            <option value="">全部终端</option>
            <option v-for="a in agents" :key="a.agent_id || a.id" :value="a.agent_id || a.id">{{ a.hostname || a.agent_id || a.id }}</option>
          </select>
        </label>
        <label><span>回溯</span>
          <span class="num-wrap">
            <input v-model.number="hours" class="field narrow" type="number" min="1" max="336" />
            <em>小时</em>
          </span>
        </label>
        <label><span>最低分</span>
          <input v-model.number="minScore" class="field narrow plain" type="number" min="0" max="200" />
        </label>
        <button type="button" class="btn primary sm" :disabled="busy" @click="score">{{ busy ? '计算中…' : '评分' }}</button>
        <div class="lr-meta">
          <span>信号 <b>{{ scanned }}</b></span>
          <span>家族 <b>{{ items.length }}</b></span>
        </div>
      </div>
    </header>

    <p v-if="err" class="banner err">{{ err }}</p>
    <p v-if="tip" class="banner ok">
      {{ tip }}
      <button v-if="pendingApprovalId || /审批/.test(tip)" type="button" class="btn-text" style="margin-left:10px" @click="goApprovals">
        去处置审批 →
      </button>
    </p>

    <div class="lr-kpis" v-if="stats">
      <button
        v-for="k in [{id:'critical',label:'危急'},{id:'high',label:'高危'},{id:'medium',label:'中危'},{id:'low',label:'低危'}]"
        :key="k.id" type="button" class="kpi" :data-s="k.id" :class="{ on: sevFilter === k.id }"
        @click="toggleSev(k.id)"
      >
        <em>{{ k.label }}</em>
        <b>{{ stats[k.id] || 0 }}</b>
      </button>
    </div>

    <div v-if="!items.length" class="lr-empty panel">
      <div class="empty-art" aria-hidden="true">
        <svg viewBox="0 0 200 90" width="200" height="90">
          <rect x="78" y="8" width="44" height="22" rx="6" fill="#eef4ff" stroke="#93b4f5" />
          <rect x="28" y="52" width="44" height="22" rx="6" fill="#fff8f6" stroke="#f7a39a" />
          <rect x="128" y="52" width="44" height="22" rx="6" fill="#fffaeb" stroke="#f5c06a" />
          <path d="M100 30 V42 M100 42 L50 52 M100 42 L150 52" fill="none" stroke="#c5cedb" stroke-width="2" />
        </svg>
      </div>
      <h3>暂无达标进程家族</h3>
      <p>终端上线并上报信号后点「评分」。可适当降低「最低分」。</p>
    </div>

    <div v-else class="lr-body">
      <aside class="lr-list">
        <div class="list-search">
          <input
            v-model="listQ"
            class="field"
            type="search"
            placeholder="搜索进程名 / PID / 主机…"
            autocomplete="off"
          />
          <button v-if="listQ" type="button" class="btn-text" @click="listQ = ''">清除</button>
        </div>
        <div v-if="sevFilter || listQ.trim()" class="list-filter">
          <span>
            <template v-if="sevFilter">仅看 {{ sevLabel(sevFilter) }}</template>
            <template v-if="sevFilter && listQ.trim()"> · </template>
            <template v-if="listQ.trim()">「{{ listQ.trim() }}」</template>
            · {{ filteredItems.length }}
          </span>
          <button
            type="button"
            class="btn-text"
            @click="listQ = ''; applySevFilter('')"
          >清空筛选</button>
        </div>
        <p v-if="!filteredItems.length" class="list-empty">无匹配进程，试试其它关键词或清除筛选</p>
        <button
          v-for="it in filteredItems" :key="keyOf(it)" type="button" class="lr-card"
          :class="[{ on: keyOf(it) === selectedKey }, it.severity]" @click="openDetail(it)"
        >
          <div class="lr-card-main">
            <span class="score-n" :data-s="it.severity">{{ Math.round(Number(it.score) || 0) }}</span>
            <div class="lr-card-body">
              <div class="lr-card-top">
                <code>{{ shortName(it.root?.name || '未知进程', 18) }}</code>
                <span class="sev" :data-s="it.severity">{{ sevLabel(it.severity) }}</span>
              </div>
              <p class="host">{{ it.hostname || shortName(it.agent_id, 16) }}<template v-if="it.root?.pid"> · PID {{ it.root.pid }}</template></p>
              <footer>
                <span>{{ it.member_count }} 进程</span>
                <span>{{ it.signal_count }} 信号</span>
                <span>{{ fmtTime(it.last_ts) }}</span>
              </footer>
            </div>
          </div>
        </button>
      </aside>

      <div class="lr-detail panel" v-if="selected && detail?.ok">
        <header class="detail-hd">
          <div>
            <div class="name-row">
              <code class="proc">{{ selected.root?.name || '未知进程' }}</code>
              <span class="sev" :data-s="selected.severity">{{ sevLabel(selected.severity) }}</span>
              <span v-if="selected.root?.pid" class="pid">PID {{ selected.root.pid }}</span>
            </div>
            <p class="sub">
              {{ selected.hostname || selected.agent_id }}
              · {{ (selected.tactic_names || []).join(' · ') || '未映射战术' }}
              · {{ selected.member_count }} 进程 / {{ selected.signal_count }} 信号
              · 深度 {{ treeLayout.layers }}
            </p>
          </div>
          <div class="score-box" :data-s="selected.severity">
            <strong>{{ Math.round(Number(selected.score) || 0) }}</strong>
            <span>风险分</span>
            <i class="bar"><i :style="{ width: scorePct + '%' }" /></i>
            <small>基础 {{ Math.round(selected.base_score || 0) }} + 加成 {{ Math.round(selected.bonus || 0) }}</small>
          </div>
        </header>

        <p v-if="!selected.recommended?.length" class="lr-readonly-note" role="status">当前分析结果没有返回处置建议。风险评分和进程关联仅用于分析展示，不代表已执行处置。</p>
        <div class="recs" v-if="selected.recommended?.length">
          <span class="recs-label">处置操作</span>
          <button
            v-for="(r, i) in selected.recommended" :key="i" type="button" class="rec-btn"
            :class="{ danger: r.action === 'kill_process' || r.action === 'isolate_network', primary: r.action === 'investigate' }"
            :disabled="actBusy" @click="runRec(r)"
          >{{ r.label }}</button>
          <small class="recs-hint">操作将针对当前终端提交；平台会按当前账号权限和处置审批策略处理。</small>
        </div>

        <div class="lr-main">
          <section class="tree-pane">
            <header class="pane-hd">
              <div>
                <h4>进程派生树</h4>
                <span>左→右为父子关系 · 点节点看命令行 · 红点表示有信号</span>
              </div>
            </header>
            <div class="tree-scroll">
              <svg v-if="treeLayout.width" class="tree-svg"
                :viewBox="`0 0 ${treeLayout.width} ${treeLayout.height}`"
                :width="treeLayout.width" :height="treeLayout.height">
                <defs>
                  <linearGradient id="lrEdgeHot" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stop-color="#f7b27a" />
                    <stop offset="100%" stop-color="#f04438" />
                  </linearGradient>
                  <filter id="lrGlow" x="-40%" y="-40%" width="180%" height="180%">
                    <feGaussianBlur stdDeviation="2.2" result="b" />
                    <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
                  </filter>
                </defs>
                <path
                  v-for="(p, i) in treeLayout.paths" :key="'p'+i" :d="p.d"
                  class="tree-edge" :class="{ hot: p.hot }"
                />
                <g
                  v-for="n in detail.nodes" :key="n.entity_id" class="tree-g"
                  :class="{
                    hover: hoverNode === n.entity_id,
                    focus: focusNode === n.entity_id,
                  }"
                  :transform="`translate(${treeLayout.positions[n.entity_id]?.x || 0},${treeLayout.positions[n.entity_id]?.y || 0})`"
                  @mouseenter="hoverNode = n.entity_id"
                  @mouseleave="hoverNode = ''"
                  @click="selectNode(n.entity_id)"
                >
                  <rect
                    class="tree-node" :class="[{ root: n.is_root, hit: n.has_signal }, nodeSev(n)]"
                    :width="treeLayout.NODE_W" :height="treeLayout.NODE_H" rx="12"
                  />
                  <rect class="sev-strip" :class="nodeSev(n)" x="0" y="0" width="5" :height="treeLayout.NODE_H" rx="2" />
                  <text x="16" y="26" class="tn-name">{{ shortName(n.name || n.entity_id, 18) }}</text>
                  <text x="16" y="46" class="tn-meta">
                    pid {{ n.pid ?? '—' }} · 自有 {{ Math.round(n.own_score || 0) }} · 传播 {{ Math.round(n.propagated_score || 0) }}
                  </text>
                  <text x="16" y="62" class="tn-tag">{{ n.is_root ? '家族根' : (n.has_signal ? '有告警信号' : '派生节点') }}</text>
                  <circle v-if="n.has_signal" class="hit-dot" :cx="treeLayout.NODE_W - 16" cy="16" r="5" filter="url(#lrGlow)" />
                </g>
              </svg>
            </div>

            <div class="node-panel" v-if="focusInfo">
              <header class="node-hd">
                <div class="node-title">
                  <span class="sev" :data-s="nodeSev(focusInfo)">{{ sevLabel(nodeSev(focusInfo)) }}</span>
                  <code class="node-name">{{ focusInfo.name || '未知进程' }}</code>
                  <span class="pid">PID {{ focusInfo.pid ?? '—' }}</span>
                  <span v-if="focusInfo.is_root" class="tag-root">家族根</span>
                  <span v-if="!focusInfo.known" class="tag-miss">进程表无完整记录</span>
                </div>
                <div class="focus-meta">
                  <span>自有 <b>{{ Math.round(focusInfo.own_score || 0) }}</b></span>
                  <span>传播 <b>{{ Math.round(focusInfo.propagated_score || 0) }}</b></span>
                  <span>子进程 <b>{{ childCount }}</b></span>
                  <span>信号 <b>{{ storyByNode.length }}</b></span>
                </div>
              </header>

              <div class="node-grid">
                <div class="kv wide"><em>路径</em><code :title="focusInfo.path">{{ focusInfo.path || '—' }}</code></div>
                <div class="kv"><em>用户</em><span>{{ focusInfo.user || '—' }}</span></div>
                <div class="kv">
                  <em>父进程</em>
                  <button
                    v-if="focusInfo.parent_entity_id && nodeById(focusInfo.parent_entity_id)"
                    type="button" class="linkish"
                    @click="selectNode(focusInfo.parent_entity_id)"
                  >
                    {{ focusInfo.parent_name || '父进程' }}
                    <small v-if="focusInfo.parent_pid">#{{ focusInfo.parent_pid }}</small>
                  </button>
                  <span v-else>{{ focusInfo.parent_name || '—' }}<template v-if="focusInfo.ppid"> · PPID {{ focusInfo.ppid }}</template></span>
                </div>
                <div class="kv"><em>签名状态</em><span>{{ signedLabel(focusInfo.signed) }}</span></div>
                <div class="kv"><em>签名者</em><span :title="focusInfo.signer || focusInfo.company">{{ focusInfo.signer || focusInfo.company || '—' }}</span></div>
                <div class="kv"><em>完整性</em><span>{{ focusInfo.integrity || '—' }}</span></div>
                <div class="kv wide"><em>SHA256</em><code class="mono sm-break" :title="focusInfo.sha256">{{ focusInfo.sha256 || '—' }}</code></div>
                <div class="kv"><em>MD5</em><code class="mono" :title="focusInfo.md5">{{ focusInfo.md5 || '—' }}</code></div>
                <div class="kv"><em>创建</em><span class="mono">{{ fmt(focusInfo.create_time) }}</span></div>
                <div class="kv"><em>退出</em><span class="mono">{{ focusInfo.exit_time ? fmt(focusInfo.exit_time) : '仍在运行 / 未知' }}</span></div>
                <div class="kv"><em>实体</em><span class="mono sm-break">{{ focusInfo.entity_id || '—' }}</span></div>
              </div>

              <div class="cmd-block">
                <div class="cmd-hd">
                  <h5>启动命令行</h5>
                  <button
                    v-if="focusInfo.command_line"
                    type="button" class="btn-text"
                    @click="copyText(focusInfo.command_line, 'proc')"
                  >{{ copiedCmd === 'proc' ? '已复制' : '复制' }}</button>
                </div>
                <pre v-if="focusInfo.command_line">{{ focusInfo.command_line }}</pre>
                <p v-else class="empty-inline">该进程暂无采集到 command_line（常见于短生命周期或非创建事件补齐）。</p>
              </div>

              <div class="cmd-block" v-if="childNodes.length">
                <div class="cmd-hd"><h5>拉起的子进程</h5></div>
                <ul class="child-list">
                  <li v-for="c in childNodes" :key="c.entity_id">
                    <button type="button" class="child-btn" @click="selectNode(c.entity_id)">
                      <code>{{ c.name || '—' }}</code>
                      <span class="muted">PID {{ c.pid ?? '—' }}</span>
                      <span class="sev" :data-s="nodeSev(c)">{{ sevLabel(nodeSev(c)) }}</span>
                    </button>
                    <pre v-if="c.command_line" class="child-cmd" :title="c.command_line">{{ c.command_line }}</pre>
                    <p v-else class="empty-inline sm">无命令行</p>
                  </li>
                </ul>
              </div>

              <div class="cmd-block" v-if="focusActions.length">
                <div class="cmd-hd"><h5>相关行为 / 命令</h5><span class="muted">{{ focusActions.length }} 条</span></div>
                <ul class="act-list">
                  <li v-for="(a, i) in focusActions" :key="i">
                    <div class="act-top">
                      <time>{{ fmt(a.first_ts || a.last_ts) }}</time>
                      <span class="sev" :data-s="a.severity">{{ sevLabel(a.severity) }}</span>
                      <span v-if="a.tactic_name" class="tac">{{ a.tactic_name }}</span>
                    </div>
                    <b>{{ a.title }}</b>
                    <pre v-if="a.action_line && a.action_line !== a.title" class="act-line">{{ a.action_line }}</pre>
                    <button
                      v-if="a.command_line"
                      type="button" class="btn-text"
                      @click="copyText(a.command_line, 'act'+i)"
                    >{{ copiedCmd === 'act'+i ? '已复制' : '复制命令' }}</button>
                  </li>
                </ul>
              </div>
            </div>

            <div class="sig-cards" v-if="topSignals.length && !focusNode">
              <h4>关键信号</h4>
              <div class="sig-grid">
                <article v-for="(s, i) in topSignals" :key="i" class="sig-card" :data-s="s.severity">
                  <span class="sev" :data-s="s.severity">{{ sevLabel(s.severity) }}</span>
                  <b>{{ s.title || s.summary || '信号' }}</b>
                  <em>{{ fmt(s.ts || s.first_ts) }}</em>
                </article>
              </div>
            </div>
          </section>

          <section class="story-pane">
            <header class="pane-hd">
              <div>
                <h4>故事线</h4>
                <span>{{ storyGrouped.length }} 步<template v-if="focusInfo"> · {{ shortName(focusInfo.name, 12) }}</template></span>
              </div>
            </header>
            <ol class="story" v-if="storyGrouped.length">
              <li
                v-for="(s, i) in storyGrouped" :key="i"
                :data-k="s.kind" :data-s="s.severity"
                class="story-item"
                :class="{ on: focusNode && s.entity_id === focusNode }"
                @click="s.entity_id && selectNode(s.entity_id)"
              >
                <div class="st-rail">
                  <div class="st-dot" :data-k="s.kind" />
                </div>
                <div class="st-body">
                  <div class="st-top">
                    <time>{{ fmtTime(s.first_ts) }}</time>
                    <span class="kind-tag" :data-k="s.kind">
                      {{ ({ net: '网络', proc: '进程', persist: '持久化', signal: '信号' })[s.kind] || '事件' }}
                    </span>
                    <span class="sev" :data-s="s.severity">{{ sevLabel(s.severity) }}</span>
                  </div>
                  <b>{{ shortName(s.process_name || '—', 16) }}</b>
                  <p>{{ s.title }}<em v-if="s.count > 1"> ×{{ s.count }}</em></p>
                  <pre v-if="s.command_line" class="st-cmd">{{ s.command_line }}</pre>
                  <p v-else-if="s.remote" class="st-extra">→ {{ s.remote }}</p>
                </div>
              </li>
            </ol>
            <p v-else class="empty-sm">无故事节点</p>
          </section>
        </div>
      </div>
      <div v-else class="lr-detail panel empty-box">选择左侧家族查看派生树与故事线</div>
    </div>
  </section>
</template>

<style scoped>
.lr {
  display: flex; flex-direction: column; gap: 14px;
  flex: 1; min-height: 0; height: 100%; max-height: none; overflow: hidden;
  box-sizing: border-box;
}

.lr-top {
  flex: 0 0 auto;
  display: flex; flex-wrap: wrap; align-items: flex-end; justify-content: space-between;
  gap: 12px 20px; padding: 14px 18px; border-radius: 14px;
  background: #fff; border: 1px solid #e8eef6;
}
.lr-title { min-width: 0; }
.eyebrow {
  margin: 0 0 2px; font-size: 11px; font-weight: 700; letter-spacing: .08em;
  text-transform: uppercase; color: #2f6fed;
}
.lr-title h1 { margin: 0; font-size: 20px; letter-spacing: -.03em; color: var(--ink, #101828); }

.lr-toolbar {
  display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: flex-end;
}
.lr-toolbar label {
  display: flex; flex-direction: column; gap: 3px; font-size: 11px; color: #98a2b3;
}
.num-wrap {
  position: relative; display: inline-flex; align-items: center;
}
.num-wrap em {
  position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
  font-style: normal; font-size: 11px; color: #98a2b3; pointer-events: none;
}
.field {
  padding: 7px 10px; border: 1px solid #d0d5dd; border-radius: 8px; font: inherit;
  min-width: 140px; background: #fff; color: var(--ink, #101828);
}
.field.narrow { width: 78px; min-width: 78px; }
.num-wrap .field.narrow { padding-right: 36px; }
.field.plain { padding-right: 10px; }
.lr-meta {
  margin-left: 4px; display: flex; gap: 14px; align-items: center;
  color: #98a2b3; font-size: 12px; padding-bottom: 6px;
}
.lr-meta b { color: #101828; font-variant-numeric: tabular-nums; }

.lr-kpis {
  flex: 0 0 auto; display: flex; flex-wrap: wrap; gap: 8px;
}
.kpi {
  text-align: left; font: inherit; cursor: pointer;
  display: inline-flex; align-items: baseline; gap: 8px;
  padding: 8px 14px; border-radius: 999px; background: #fff; border: 1px solid #e8eef6;
  transition: border-color .15s, background .15s, box-shadow .15s;
}
.kpi:hover { border-color: #c7d7f5; }
.kpi.on { box-shadow: 0 0 0 2px rgba(47,111,237,.12); }
.kpi[data-s="critical"].on, .kpi[data-s="high"].on { background: #fef3f2; border-color: #fecdca; }
.kpi[data-s="medium"].on { background: #fffaeb; border-color: #fedf89; }
.kpi[data-s="low"].on { background: #f8fafc; border-color: #d0d5dd; }
.kpi em { font-style: normal; color: #98a2b3; font-size: 12px; }
.kpi b { font-size: 16px; letter-spacing: -.02em; line-height: 1; font-variant-numeric: tabular-nums; color: #101828; }
.kpi[data-s="critical"] b, .kpi[data-s="high"] b { color: #b42318; }
.kpi[data-s="medium"] b { color: #b54708; }

.banner { flex: 0 0 auto; margin: 0; padding: 8px 12px; border-radius: 8px; font-size: 13px; }
.banner.err { background: #fdecea; color: #a1281d; }
.banner.ok { background: #ecfdf3; color: #027a48; }
.lr-empty { flex: 1; min-height: 0; overflow: auto; padding: 48px 24px; text-align: center; color: #667085; }
.lr-empty h3 { margin: 8px 0 6px; color: #101828; }
.lr-empty p { margin: 0 auto; max-width: 420px; line-height: 1.55; }
.empty-art { display: flex; justify-content: center; }

.lr-body {
  display: grid; grid-template-columns: 268px minmax(0, 1fr); gap: 16px;
  flex: 1; min-height: 0; overflow: hidden;
}
.lr-list {
  display: flex; flex-direction: column; gap: 8px; overflow: auto;
  min-height: 0; height: 100%; padding: 2px 4px 2px 0;
}
.list-search {
  flex: 0 0 auto; display: flex; align-items: center; gap: 8px;
  position: sticky; top: 0; z-index: 2; padding: 2px 0 4px; background: var(--bg, #f4f6fa);
}
.list-search .field {
  flex: 1; min-width: 0; padding: 8px 10px; border: 1px solid #d0d5dd; border-radius: 8px;
  font: inherit; font-size: 12px; background: #fff;
}
.list-search .field:focus { outline: none; border-color: #93b4f5; box-shadow: 0 0 0 2px rgba(47,111,237,.12); }
.list-filter {
  flex: 0 0 auto; display: flex; justify-content: space-between; align-items: center; gap: 8px;
  padding: 7px 10px; font-size: 12px; color: #667085; background: #f5f8ff; border-radius: 10px; border: 1px solid #e4ebf5;
}
.list-empty {
  margin: 12px 4px; padding: 16px 12px; text-align: center;
  color: #98a2b3; font-size: 12px; line-height: 1.45;
  background: #fff; border: 1px dashed #e4ebf5; border-radius: 10px;
}

.lr-card {
  text-align: left; border: 1px solid #e8eef6; background: #fff; border-radius: 12px; padding: 10px 12px;
  cursor: pointer; font: inherit; transition: border-color .15s, box-shadow .15s, background .15s;
}
.lr-card:hover { border-color: #c7d7f5; }
.lr-card.on { border-color: #93b4f5; background: #f7faff; box-shadow: 0 6px 18px rgba(47,111,237,.08); }
.lr-card-main { display: flex; gap: 10px; align-items: flex-start; }
.score-n {
  flex: 0 0 auto; min-width: 36px; height: 36px; padding: 0 6px; border-radius: 10px;
  display: grid; place-items: center; font-size: 13px; font-weight: 750;
  font-variant-numeric: tabular-nums; background: #f2f4f7; color: #344054;
}
.score-n[data-s="critical"], .score-n[data-s="high"] { background: #fee4e2; color: #b42318; }
.score-n[data-s="medium"] { background: #fef0c7; color: #b54708; }
.lr-card-body { flex: 1; min-width: 0; }
.lr-card-top {
  display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 2px;
}
.lr-card-top code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px; font-weight: 700; color: #101828;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.host { margin: 0 0 6px; color: #667085; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.lr-card footer {
  display: flex; flex-wrap: wrap; gap: 8px; color: #98a2b3; font-size: 11px;
}

.lr-detail {
  padding: 16px 18px; display: flex; flex-direction: column; gap: 12px;
  min-height: 0; height: 100%; overflow: hidden; border-radius: 14px;
  background: #fff; border: 1px solid #e8eef6;
}
.detail-hd { flex: 0 0 auto; display: flex; justify-content: space-between; gap: 14px; align-items: flex-start; }
.recs { flex: 0 0 auto; }
.name-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 4px; }
.proc { font-size: 17px; font-weight: 750; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: -.02em; }
.pid { padding: 2px 8px; border-radius: 7px; background: #f2f4f7; color: #475467; font-size: 12px; font-weight: 650; }
.sub { margin: 0; color: #667085; font-size: 12px; line-height: 1.5; }
.score-box {
  min-width: 108px; padding: 8px 12px; border-radius: 12px;
  background: #f8fafc; border: 1px solid #e8eef6; text-align: right;
}
.score-box[data-s="critical"], .score-box[data-s="high"] { background: #fef3f2; border-color: #fecdca; }
.score-box[data-s="medium"] { background: #fffaeb; border-color: #fedf89; }
.score-box strong { display: block; font-size: 24px; line-height: 1; letter-spacing: -.04em; }
.score-box[data-s="critical"] strong, .score-box[data-s="high"] strong { color: #b42318; }
.score-box[data-s="medium"] strong { color: #b54708; }
.score-box span { font-size: 11px; color: #98a2b3; }
.score-box .bar { display: block; height: 4px; border-radius: 99px; background: #e4e7ec; margin: 6px 0 4px; overflow: hidden; }
.score-box .bar > i { display: block; height: 100%; background: linear-gradient(90deg, #6b9aff, #2f6fed); border-radius: inherit; }
.score-box[data-s="critical"] .bar > i, .score-box[data-s="high"] .bar > i { background: linear-gradient(90deg, #fda29b, #f04438); }
.score-box[data-s="medium"] .bar > i { background: linear-gradient(90deg, #fec84b, #f79009); }
.score-box small { color: #98a2b3; font-size: 10px; }

.recs {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  padding: 8px 12px; border-radius: 10px;
  background: #f8fafc; border: 1px solid #eef2f7;
}
.recs-label { font-size: 12px; color: #98a2b3; font-weight: 650; }
.rec-btn {
  border: 1px solid #d0d5dd; background: #fff; color: #344054; border-radius: 8px;
  padding: 6px 11px; font: inherit; font-size: 12px; font-weight: 650; cursor: pointer;
  transition: transform .12s, box-shadow .12s;
}
.rec-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(16,24,40,.06); }
.rec-btn:disabled { opacity: .55; cursor: wait; }
.rec-btn.danger { border-color: #fecdca; background: #fef3f2; color: #b42318; }
.rec-btn.primary { border-color: #b7c9f0; background: #eef4ff; color: #2f6fed; }

.lr-main {
  display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(260px, .7fr); gap: 16px;
  flex: 1; min-height: 0; overflow: hidden;
}
.pane-hd { flex: 0 0 auto; display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 8px; }
.pane-hd h4 { margin: 0 0 2px; font-size: 13px; font-weight: 700; color: #101828; }
.pane-hd span { color: #98a2b3; font-size: 11px; }

.tree-pane { display: flex; flex-direction: column; gap: 12px; min-width: 0; min-height: 0; height: 100%; overflow: hidden; }
.tree-scroll {
  flex: 1 1 auto; min-height: 180px; overflow: auto; border: 1px solid #e4ebf5; border-radius: 12px;
  background:
    radial-gradient(500px 180px at 10% 0%, rgba(47,111,237,.05), transparent 55%),
    radial-gradient(circle at 1px 1px, #e4ebf5 1px, transparent 0) 0 0 / 18px 18px,
    #f8fafc;
}
.tree-svg { display: block; }
.tree-edge { fill: none; stroke: #b8c5d8; stroke-width: 1.8; opacity: .9; }
.tree-edge.hot { stroke: url(#lrEdgeHot); stroke-width: 2.2; opacity: 1; }
.tree-node {
  fill: #fff; stroke: #d0d5dd; stroke-width: 1.4;
  filter: drop-shadow(0 4px 10px rgba(16,24,40,.05));
  transition: stroke .12s, stroke-width .12s;
}
.tree-node.root { stroke: #2f6fed; stroke-width: 2.2; fill: #f7faff; }
.tree-node.high, .tree-node.critical { fill: #fff8f6; stroke: #f7a39a; }
.tree-node.medium { fill: #fffaf0; stroke: #f5c06a; }
.tree-g { cursor: pointer; }
.tree-g.hover .tree-node, .tree-g.focus .tree-node { stroke: #2f6fed; stroke-width: 2.4; }
.tree-g.focus .tree-node { filter: drop-shadow(0 8px 18px rgba(47,111,237,.18)); }
.sev-strip { fill: #98a2b3; }
.sev-strip.critical, .sev-strip.high { fill: #f04438; }
.sev-strip.medium { fill: #f79009; }
.sev-strip.low { fill: #98a2b3; }
.tn-name { font-size: 12.5px; font-weight: 750; fill: #101828; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.tn-meta { font-size: 10px; fill: #667085; }
.tn-tag { font-size: 9.5px; fill: #98a2b3; letter-spacing: .02em; }
.hit-dot { fill: #f04438; }

.node-panel {
  flex: 0 1 38%; min-height: 120px; max-height: 42%; overflow: auto;
  padding: 12px 14px; border-radius: 12px; background: #fff; border: 1px solid #e8eef6;
  display: flex; flex-direction: column; gap: 10px;
}
.sig-cards { flex: 0 0 auto; overflow: auto; max-height: 40%; }
.node-hd { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; align-items: flex-start; }
.node-title { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.node-name {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 15px; font-weight: 750; color: #101828;
}
.tag-root, .tag-miss {
  padding: 2px 7px; border-radius: 6px; font-size: 11px; font-weight: 650;
}
.tag-root { background: #eef4ff; color: #2f6fed; }
.tag-miss { background: #fef0c7; color: #b54708; }
.focus-meta { display: flex; gap: 14px; color: #98a2b3; font-size: 12px; flex-wrap: wrap; }
.focus-meta b { color: #101828; font-variant-numeric: tabular-nums; }
.node-grid {
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 14px;
  padding: 10px 12px; border-radius: 10px; background: #f8fafc; border: 1px solid #eef2f7;
}
.kv { display: flex; flex-direction: column; gap: 3px; min-width: 0; font-size: 12px; color: #344054; }
.kv.wide { grid-column: 1 / -1; }
.kv em { font-style: normal; color: #98a2b3; font-size: 11px; font-weight: 650; }
.kv code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
.sm-break { font-size: 11px; word-break: break-all; color: #667085; }
.linkish {
  border: 0; background: transparent; padding: 0; font: inherit; color: #2f6fed;
  cursor: pointer; text-align: left; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.linkish:hover { text-decoration: underline; }
.linkish small { color: #98a2b3; margin-left: 4px; }
.cmd-block { display: flex; flex-direction: column; gap: 8px; }
.cmd-hd { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.cmd-hd h5 { margin: 0; font-size: 12px; color: #667085; font-weight: 700; letter-spacing: .02em; }
.cmd-block > pre, .child-cmd, .act-line, .st-cmd {
  margin: 0; white-space: pre-wrap; word-break: break-all;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
  background: #0f1724; color: #e4e7ec; padding: 10px 12px; border-radius: 10px; line-height: 1.45;
}
.child-cmd, .act-line, .st-cmd { background: #111827; padding: 8px 10px; border-radius: 8px; }
.empty-inline { margin: 0; color: #98a2b3; font-size: 12px; line-height: 1.45; }
.empty-inline.sm { font-size: 11px; }
.child-list, .act-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
.child-list li, .act-list li {
  padding: 8px 10px; border-radius: 10px; border: 1px solid #eef2f7; background: #fbfcfe;
}
.child-btn {
  width: 100%; display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  border: 0; background: transparent; padding: 0; font: inherit; cursor: pointer; text-align: left;
}
.child-btn code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 700; color: #101828; }
.act-top { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 4px; }
.act-top time { color: #98a2b3; font-size: 11px; font-variant-numeric: tabular-nums; }
.act-list b { display: block; font-size: 12px; color: #344054; margin-bottom: 4px; }
.story-item { cursor: pointer; }
.story-item.on .st-body { border-color: #93b4f5; background: #f5f8ff; }
.st-extra { margin: 4px 0 0; font-size: 11px; color: #667085; }
.muted { color: #98a2b3; font-size: 12px; }

.sig-cards h4 { margin: 0 0 8px; font-size: 12px; color: #667085; font-weight: 650; }
.sig-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.sig-card {
  padding: 10px 12px; border-radius: 10px; background: #fff; border: 1px solid #eef2f7;
  display: flex; flex-direction: column; gap: 5px; min-width: 0;
  border-left: 3px solid #d0d5dd;
}
.sig-card[data-s="critical"], .sig-card[data-s="high"] { border-left-color: #f04438; background: #fffaf9; }
.sig-card[data-s="medium"] { border-left-color: #f79009; background: #fffdf7; }
.sig-card b { font-size: 12px; color: #344054; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sig-card em { font-style: normal; font-size: 11px; color: #98a2b3; }

.story-pane {
  min-width: 0; min-height: 0; overflow: hidden;
  display: flex; flex-direction: column;
  padding: 12px 14px; border-radius: 12px; background: #f8fafc; border: 1px solid #e8eef6;
}
.story { list-style: none; margin: 0; padding: 0 2px 0 0; overflow: auto; flex: 1; min-height: 0; }
.story li {
  display: grid; grid-template-columns: 16px 1fr; gap: 10px; padding: 0 0 12px; position: relative;
}
.st-rail { position: relative; }
.story li:not(:last-child) .st-rail::after {
  content: ''; position: absolute; left: 7px; top: 16px; bottom: -10px; width: 2px;
  background: linear-gradient(180deg, #d0d5dd, #eef2f7);
}
.st-dot {
  width: 14px; height: 14px; margin-top: 2px; border-radius: 50%;
  border: 2px solid #98a2b3; background: #fff; position: relative; z-index: 1;
  box-shadow: 0 0 0 3px #fff;
}
.st-dot[data-k="net"] { border-color: #2f6fed; background: #eef4ff; }
.st-dot[data-k="proc"] { border-color: #f79009; background: #fffaeb; }
.st-dot[data-k="persist"] { border-color: #7a5af8; background: #f4f3ff; }
.st-body {
  padding: 8px 10px; border-radius: 10px; background: #fff; border: 1px solid #eef2f7;
  transition: border-color .12s, box-shadow .12s; min-width: 0;
}
.story li:hover .st-body { border-color: #c7d7f5; box-shadow: 0 4px 14px rgba(47,111,237,.06); }
.st-top { display: flex; flex-wrap: wrap; gap: 5px; align-items: center; margin-bottom: 3px; }
.st-top time { color: #98a2b3; font-size: 11px; font-variant-numeric: tabular-nums; }
.tac { padding: 1px 6px; border-radius: 5px; background: #f2f4f7; color: #475467; font-size: 11px; }
.kind-tag {
  padding: 1px 6px; border-radius: 5px; font-size: 10px; font-weight: 700; letter-spacing: .02em;
  background: #f2f4f7; color: #667085;
}
.kind-tag[data-k="net"] { background: #eef4ff; color: #2f6fed; }
.kind-tag[data-k="proc"] { background: #fffaeb; color: #b54708; }
.kind-tag[data-k="persist"] { background: #f4f3ff; color: #6941c6; }
.st-body b {
  display: block; font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: #101828;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.st-body p { margin: 3px 0 0; font-size: 12px; color: #344054; line-height: 1.45; }
.st-body em { color: #98a2b3; font-style: normal; }
.st-cmd {
  margin-top: 6px; max-height: 72px; overflow: auto;
  font-size: 11px !important; padding: 7px 9px !important;
}

.sev {
  display: inline-flex; padding: 1px 7px; border-radius: 999px; font-size: 11px; font-weight: 700;
  background: #f2f4f7; color: #475467;
}
.sev[data-s="critical"], .sev[data-s="high"] { background: #fee4e2; color: #b42318; }
.sev[data-s="medium"] { background: #fef0c7; color: #b54708; }

.cmd summary { cursor: pointer; color: #667085; font-size: 12px; font-weight: 650; }
.cmd pre {
  margin: 8px 0 0; white-space: pre-wrap; word-break: break-all; font-size: 12px;
  background: #0f1724; color: #e4e7ec; padding: 12px 14px; border-radius: 10px;
}
.empty-box { display: grid; place-items: center; color: #98a2b3; }
.empty-sm { text-align: center; color: #98a2b3; margin: 24px 0; }

@media (max-width: 1200px) {
  .lr { overflow: auto; }
  .lr-body, .lr-main, .sig-grid { grid-template-columns: 1fr; }
  .lr-body { overflow: visible; height: auto; }
  .lr-list { max-height: 260px; height: auto; }
  .lr-detail { height: auto; overflow: visible; }
  .lr-main { overflow: visible; height: auto; }
  .tree-scroll { min-height: 240px; max-height: 420px; }
  .node-panel { max-height: 360px; flex-basis: auto; }
  .story { max-height: 320px; }
}
</style>
<style scoped src="./analysisPageTheme.css"></style>
