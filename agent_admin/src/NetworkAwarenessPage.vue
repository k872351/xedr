<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { listAgents, getNetworkAwareness } from './api'

const busy = ref(false)
const err = ref('')
const agents = ref([])
const agentId = ref('')
const hours = ref(24)
const baselineHours = ref(168)
const onlyNew = ref(true)
const onlyExternal = ref(true)
const onlyHttp = ref(false)
const protoFilter = ref('')
const geoFilter = ref('')      // overseas | domestic | cloud | ''
const riskFilter = ref('')     // watch | alert | ''
const q = ref('')
const data = ref(null)
const copied = ref('')
const portFilter = ref('')
const procFilter = ref('')
const focusId = ref('')
const tableEl = ref(null)

function fmt(t) { return String(t || '').replace('T', ' ').slice(0, 19) || '—' }
function procLabel(it) {
  const name = String(it?.process_name || '').trim()
  const pid = Number(it?.pid || 0)
  if (!name && !pid) return '—'
  if (!name) return `pid ${pid}`
  return pid ? `${name}  ·  ${pid}` : name
}
function isHotPort(port) {
  return !['443', '80', '53', '123', '0'].includes(String(port))
}
function destHost(it) {
  const k = String(it?.dest_key || '')
  const i = k.lastIndexOf(':')
  return i > 0 ? k.slice(0, i) : k
}
function destPort(it) {
  const k = String(it?.dest_key || '')
  const i = k.lastIndexOf(':')
  return i > 0 ? k.slice(i + 1) : (it?.remote_port || '')
}
function isHttpItem(it) {
  return it?.etype === 'http_request_etw' || String(it?.proto || '').toLowerCase() === 'http'
}
function respTone(code) {
  const n = Number(code)
  if (!n) return ''
  if (n >= 200 && n < 300) return 'ok'
  if (n >= 300 && n < 400) return 'warn'
  if (n >= 400) return 'err'
  return ''
}

async function loadAgents() {
  try {
    const r = await listAgents()
    agents.value = r.items || []
    if (!agentId.value && agents.value[0]) agentId.value = agents.value[0].agent_id || agents.value[0].id || ''
  } catch { /* ignore */ }
}

async function analyze() {
  busy.value = true
  err.value = ''
  try {
    data.value = await getNetworkAwareness({
      agent_id: agentId.value || '',
      hours: hours.value,
      baseline_hours: baselineHours.value,
      only_new: onlyNew.value,
      only_external: onlyExternal.value,
      only_http: onlyHttp.value,
      proto: onlyHttp.value ? 'http' : (protoFilter.value || ''),
      geo: geoFilter.value || '',
      cloud_only: geoFilter.value === 'cloud',
      risk: riskFilter.value || '',
      q: q.value,
      limit: 300,
    })
    // 切换筛选时保留 focus 若仍在结果中
    if (focusId.value && !(data.value?.items || []).some((x) => x.id === focusId.value)) {
      focusId.value = ''
    }
  } catch (e) {
    err.value = e.message || String(e)
  } finally {
    busy.value = false
  }
}

const stats = computed(() => data.value?.stats || {
  observed: 0, new: 0, http: 0, overseas: 0, cloud: 0, watch: 0, alert: 0,
})
const ipIntelMeta = computed(() => data.value?.ip_intel || null)

function ipLabels(it) {
  return Array.isArray(it?.ip_labels) ? it.ip_labels : []
}
function riskClass(it) {
  return String(it?.ip_risk || 'info')
}
async function clickGeo(kind) {
  geoFilter.value = geoFilter.value === kind ? '' : kind
  riskFilter.value = ''
  await analyze()
  await scrollToTable()
}
async function clickRisk(kind) {
  riskFilter.value = riskFilter.value === kind ? '' : kind
  await analyze()
  await scrollToTable()
}
const trend = computed(() => data.value?.trend || [])
const proto = computed(() => data.value?.proto_pie || [])
const topPorts = computed(() => data.value?.top_ports || [])
const topProcs = computed(() => data.value?.top_processes || [])
const rawItems = computed(() => data.value?.items || [])

const activeProto = computed(() => {
  if (onlyHttp.value || protoFilter.value === 'http') return 'http'
  return String(protoFilter.value || '').toLowerCase()
})

const items = computed(() => {
  let rows = rawItems.value
  // 前端再兜底一次协议筛选（避免旧后端忽略 only_http 参数时明细仍是全量 TCP）
  const ap = activeProto.value
  if (ap === 'http') rows = rows.filter((it) => isHttpItem(it))
  else if (ap) rows = rows.filter((it) => String(it.proto || '').toLowerCase() === ap)
  if (portFilter.value) {
    const p = String(portFilter.value)
    rows = rows.filter((it) => String(it.dest_key || '').endsWith(':' + p) || String(it.remote_port) === p)
  }
  if (procFilter.value) {
    const n = String(procFilter.value).toLowerCase()
    rows = rows.filter((it) => String(it.process_name || '').toLowerCase() === n)
  }
  return rows
})

const focusItem = computed(() => {
  const hit = items.value.find((x) => x.id === focusId.value)
  if (hit) return hit
  // 协议切换后旧 focus 可能不在列表：回退到 raw 里同 id（仍展示详情）
  return rawItems.value.find((x) => x.id === focusId.value) || null
})

function httpRequestLine(it) {
  if (!it) return ''
  const method = String(it.method || (isHttpItem(it) ? 'HTTP' : '')).trim()
  let url = String(it.url || '').trim()
  // 后端偶发只给 path（如 "/"），前端用 host/目的地拼完整请求行
  if (url && !url.includes('://')) {
    const path = url.startsWith('/') ? url : `/${url}`
    const host = String(it.host || destHost(it) || '').trim()
    const port = String(it.remote_port || destPort(it) || '').trim()
    if (host) {
      const scheme = port === '443' ? 'https' : 'http'
      const auth = port && port !== '80' && port !== '443' ? `${host}:${port}` : host
      url = `${scheme}://${auth}${path}`
    } else {
      url = ''
    }
  }
  if (url) return method ? `${method} ${url}` : url
  const path = String(it.url_path || '').trim() || (isHttpItem(it) ? '/' : '')
  const host = String(it.host || destHost(it) || '').trim()
  const port = String(it.remote_port || destPort(it) || '').trim()
  if (host && path) {
    const scheme = port === '443' ? 'https' : 'http'
    const auth = port && port !== '80' && port !== '443' ? `${host}:${port}` : host
    return `${method || 'GET'} ${scheme}://${auth}${path.startsWith('/') ? path : '/' + path}`
  }
  return [method, path].filter(Boolean).join(' ')
}

const newRatio = computed(() => {
  const o = Number(stats.value.observed || 0)
  const n = Number(stats.value.new || 0)
  return o ? Math.round((n / o) * 100) : 0
})

/** 柱状 + 折线趋势：观察窗内每小时都有桶 */
const trendSvg = computed(() => {
  const rows = trend.value
  if (!rows.length) return null
  const W = 560, H = 140, L = 10, R = 10, T = 14, B = 28
  const max = Math.max(1, ...rows.map((r) => Number(r.observed || 0)))
  const n = rows.length
  const plotW = W - L - R
  const plotH = H - T - B
  const gap = n > 40 ? 1 : 2
  const slot = plotW / n
  const barW = Math.max(2, slot - gap)
  const xAt = (i) => L + i * slot + slot / 2
  const yAt = (v) => T + plotH - (Number(v || 0) / max) * plotH
  const bars = rows.map((r, i) => {
    const h = Math.max(0, (Number(r.observed || 0) / max) * plotH)
    return {
      x: L + i * slot + (slot - barW) / 2,
      y: T + plotH - h,
      w: barW,
      h,
      newH: Math.max(0, (Number(r.new || 0) / max) * plotH),
      http: Number(r.http || 0),
    }
  })
  const newLine = rows.map((r, i) => `${i ? 'L' : 'M'}${xAt(i).toFixed(1)},${yAt(r.new).toFixed(1)}`).join(' ')
  const labels = rows.map((r, i) => ({
    x: xAt(i),
    text: String(r.hour || '').slice(11, 13) || String(i),
    show: n <= 18 || i % Math.ceil(n / 10) === 0 || i === n - 1,
  }))
  const totalObs = rows.reduce((s, r) => s + Number(r.observed || 0), 0)
  const totalNew = rows.reduce((s, r) => s + Number(r.new || 0), 0)
  return {
    W, H, baseY: T + plotH, bars, newLine, labels,
    tip: `共 ${totalObs} 次连接 · 新增 ${totalNew} · ${rows.length} 个时段`,
  }
})

const portMax = computed(() => Math.max(1, ...topPorts.value.map(([, n]) => Number(n || 0))))
const procMax = computed(() => Math.max(1, ...topProcs.value.map(([, n]) => Number(n || 0))))

const protoDonut = computed(() => {
  const rows = proto.value
  if (!rows.length) return null
  const total = Math.max(1, rows.reduce((s, p) => s + Number(p.value || 0), 0))
  const colors = ['#2f6fed', '#0e7c66', '#e97815', '#6941c6', '#dd2590']
  let angle = -Math.PI / 2
  const cx = 58, cy = 58, r = 42, ir = 26
  const arcs = rows.map((p, i) => {
    const v = Number(p.value || 0)
    const sweep = (v / total) * Math.PI * 2
    const a0 = angle, a1 = angle + sweep
    angle = a1
    const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0)
    const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1)
    const xi0 = cx + ir * Math.cos(a1), yi0 = cy + ir * Math.sin(a1)
    const xi1 = cx + ir * Math.cos(a0), yi1 = cy + ir * Math.sin(a0)
    const large = sweep > Math.PI ? 1 : 0
    return {
      name: p.name, value: v, color: colors[i % colors.length], pct: Math.round((v / total) * 100),
      d: `M${x0},${y0} A${r},${r} 0 ${large} 1 ${x1},${y1} L${xi0},${yi0} A${ir},${ir} 0 ${large} 0 ${xi1},${yi1} Z`,
    }
  })
  return { arcs, total, cx, cy }
})

function togglePort(port) { portFilter.value = portFilter.value === String(port) ? '' : String(port) }
function toggleProc(name) { procFilter.value = procFilter.value === name ? '' : name }
function clearLocalFilters() { portFilter.value = ''; procFilter.value = '' }

async function scrollToTable() {
  await nextTick()
  tableEl.value?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
}

async function applyProtoFilter(next) {
  // 切协议时清掉端口/进程局部筛选，避免「筛了 HTTP 却还钉着 waitfor/443」看起来像没生效
  portFilter.value = ''
  procFilter.value = ''
  focusId.value = ''
  const n = String(next || '').toLowerCase()
  if (!n) {
    onlyHttp.value = false
    protoFilter.value = ''
  } else if (n === 'http') {
    onlyHttp.value = true
    protoFilter.value = 'http'
  } else {
    onlyHttp.value = false
    protoFilter.value = n
  }
  await analyze()
  await scrollToTable()
}

async function clickKpi(kind) {
  if (kind === 'all') {
    onlyNew.value = false
    await applyProtoFilter('')
    return
  }
  if (kind === 'new') {
    onlyNew.value = true
    await applyProtoFilter('')
    return
  }
  if (kind === 'http') {
    await applyProtoFilter(activeProto.value === 'http' ? '' : 'http')
  }
}

async function clickProto(name) {
  const n = String(name || '').toLowerCase()
  if (!n) return
  await applyProtoFilter(activeProto.value === n ? '' : n)
}

async function onOnlyHttpToggle() {
  await applyProtoFilter(onlyHttp.value ? 'http' : '')
}

function selectRow(it) {
  focusId.value = focusId.value === it.id ? '' : it.id
}

async function copyDest(it) {
  const text = String(it?.dest_key || '').trim()
  if (!text) return
  try {
    await navigator.clipboard.writeText(text)
    copied.value = text
    setTimeout(() => { if (copied.value === text) copied.value = '' }, 1500)
  } catch { /* ignore */ }
}

onMounted(async () => { await loadAgents(); await analyze() })
watch([agentId, onlyNew, onlyExternal], () => analyze())
</script>

<template>
  <section class="page na">
    <header class="na-hero">
      <div class="na-hero-copy">
        <p class="eyebrow">网络狩猎</p>
        <h1>异常外联</h1>
        <p>对照历史基线标新增，并结合国内/境外/云厂商 IP 库打标签；境外或云 + 新增会提示关注，叠加可疑进程则抬升告警。</p>
      </div>
      <button type="button" class="btn sm" :disabled="busy" @click="analyze">{{ busy ? '分析中…' : '重新分析' }}</button>
    </header>

    <div class="na-card na-toolbar">
      <label class="na-f agent">
        <span>终端</span>
        <select v-model="agentId" class="field">
          <option value="">全部终端</option>
          <option v-for="a in agents" :key="a.agent_id || a.id" :value="a.agent_id || a.id">{{ a.hostname || a.agent_id || a.id }}</option>
        </select>
      </label>
      <label class="na-f num">
        <span>观察窗</span>
        <div class="na-num">
          <input v-model.number="hours" type="number" min="1" max="336" class="field" />
          <em>小时</em>
        </div>
      </label>
      <label class="na-f num">
        <span>基线窗</span>
        <div class="na-num">
          <input v-model.number="baselineHours" type="number" min="1" max="720" class="field" />
          <em>小时</em>
        </div>
      </label>
      <div class="na-checks">
        <label class="chk"><input type="checkbox" v-model="onlyNew" /><span>仅新增</span></label>
        <label class="chk"><input type="checkbox" v-model="onlyExternal" /><span>仅外网</span></label>
        <label class="chk"><input type="checkbox" v-model="onlyHttp" @change="onOnlyHttpToggle" /><span>仅 HTTP</span></label>
      </div>
      <label class="na-f">
        <span>地理</span>
        <select v-model="geoFilter" class="field" @change="analyze">
          <option value="">全部</option>
          <option value="overseas">仅境外</option>
          <option value="domestic">仅国内</option>
          <option value="cloud">仅云厂商</option>
        </select>
      </label>
      <label class="na-f">
        <span>风险</span>
        <select v-model="riskFilter" class="field" @change="analyze">
          <option value="">全部</option>
          <option value="watch">关注及以上</option>
          <option value="alert">仅告警</option>
        </select>
      </label>
      <label class="na-f grow">
        <span>搜索</span>
        <input v-model="q" class="field" placeholder="进程 / IP / 域名 / URL / 云厂商" @keyup.enter="analyze" />
      </label>
      <button type="button" class="btn primary sm na-analyze" :disabled="busy" @click="analyze">分析</button>
    </div>

    <p v-if="err" class="banner err">{{ err }}</p>
    <p v-else-if="ipIntelMeta?.ok" class="banner tip">
      IP 库已加载：国内段 {{ ipIntelMeta.domestic }} · 云段 {{ ipIntelMeta.cloud }}
      · 境外/云 + 新增会标「关注」；叠加可疑进程抬升「告警」
    </p>
    <p v-else-if="data && !ipIntelMeta?.ok" class="banner err">
      IP 库未加载（检查仓库 ip/guonei.txt、yun*.txt），归属将全部显示为未匹配。
    </p>

    <div class="na-main">
    <div class="na-upper">
    <div class="na-kpis na-kpis-6">
      <button type="button" class="na-card kpi" :class="{ on: !onlyNew && !activeProto && !geoFilter && !riskFilter }" @click="clickKpi('all')">
        <span class="kpi-lab">观察窗连接</span>
        <strong>{{ stats.observed || 0 }}</strong>
        <span class="kpi-sub">点击查看当前结果</span>
      </button>
      <button type="button" class="na-card kpi hot" :class="{ on: onlyNew && !activeProto }" @click="clickKpi('new')">
        <span class="kpi-lab">新增目的地</span>
        <strong>{{ stats.new || 0 }}</strong>
        <span class="kpi-sub">占比 {{ newRatio }}% · 点击仅看新增</span>
        <i class="ring" :style="{ '--p': newRatio + '%' }" />
      </button>
      <button type="button" class="na-card kpi http" :class="{ on: activeProto === 'http' }" @click="clickKpi('http')">
        <span class="kpi-lab">HTTP 请求</span>
        <strong>{{ stats.http || 0 }}</strong>
        <span class="kpi-sub">{{ activeProto === 'http' ? '筛选中 · 再点取消' : 'WinINet / WebIO · 点击筛选' }}</span>
      </button>
      <button type="button" class="na-card kpi overseas" :class="{ on: geoFilter === 'overseas' }" @click="clickGeo('overseas')">
        <span class="kpi-lab">境外 IP</span>
        <strong>{{ stats.overseas || 0 }}</strong>
        <span class="kpi-sub">{{ geoFilter === 'overseas' ? '筛选中 · 再点取消' : '点击仅看境外' }}</span>
      </button>
      <button type="button" class="na-card kpi cloud" :class="{ on: geoFilter === 'cloud' }" @click="clickGeo('cloud')">
        <span class="kpi-lab">云厂商</span>
        <strong>{{ stats.cloud || 0 }}</strong>
        <span class="kpi-sub">{{ geoFilter === 'cloud' ? '筛选中 · 再点取消' : '阿里云 / AWS 等' }}</span>
      </button>
      <button type="button" class="na-card kpi risk" :class="{ on: riskFilter === 'watch' || riskFilter === 'alert' }" @click="clickRisk(riskFilter === 'watch' ? '' : 'watch')">
        <span class="kpi-lab">关注 / 告警</span>
        <strong>{{ (stats.watch || 0) + (stats.alert || 0) }}</strong>
        <span class="kpi-sub">告警 {{ stats.alert || 0 }} · 关注 {{ stats.watch || 0 }}</span>
      </button>
    </div>

    <div v-if="!rawItems.length && !busy" class="na-card na-empty">
      <div class="empty-art" aria-hidden="true">
        <svg viewBox="0 0 240 100" width="240" height="100">
          <path d="M20 70 C60 20, 100 90, 140 40 S200 10, 220 55" fill="none" stroke="#c7d7f5" stroke-width="3" />
          <circle cx="60" cy="48" r="6" fill="#2f6fed" />
          <circle cx="140" cy="42" r="6" fill="#e97815" />
          <circle cx="200" cy="28" r="6" fill="#0e7c66" />
        </svg>
      </div>
      <h3>{{ onlyHttp ? '暂无 HTTP 请求' : '暂无网络事件' }}</h3>
      <p>
        <template v-if="onlyHttp">当前筛选下没有 WinINet/WebIO HTTP 事件；可取消「仅 HTTP」或扩大观察窗。</template>
        <template v-else>需要终端上报外联；也可取消「仅新增」扩大结果。</template>
      </p>
    </div>

    <template v-if="rawItems.length">
      <div class="na-viz">
        <div class="na-card viz-card">
          <header class="viz-hd">
            <div>
              <h3>连接趋势</h3>
              <p>{{ trendSvg?.tip || '按时段观察连接变化' }}</p>
            </div>
            <span class="legend"><i class="obs" />观测 <i class="nw" />新增</span>
          </header>
          <div v-if="trendSvg" class="trend-wrap">
            <svg class="trend-svg" :viewBox="`0 0 ${trendSvg.W} ${trendSvg.H}`" preserveAspectRatio="none">
              <line :x1="0" :x2="trendSvg.W" :y1="trendSvg.baseY" :y2="trendSvg.baseY" stroke="#e8eef6" />
              <g v-for="(b, i) in trendSvg.bars" :key="'b'+i">
                <rect :x="b.x" :y="b.y" :width="b.w" :height="b.h" rx="2" fill="#c7d7f5" />
                <rect
                  v-if="b.newH"
                  :x="b.x" :y="trendSvg.baseY - b.newH" :width="b.w" :height="b.newH" rx="2" fill="#e97815" opacity=".9"
                />
              </g>
              <path :d="trendSvg.newLine" fill="none" stroke="#b54708" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
              <text
                v-for="(lb, i) in trendSvg.labels" :key="'l'+i" v-show="lb.show"
                class="axis" :x="lb.x" :y="trendSvg.H - 8" text-anchor="middle"
              >{{ lb.text }}</text>
            </svg>
          </div>
          <p v-else class="empty-sm">暂无趋势数据</p>
        </div>

        <div class="na-card viz-card">
          <header class="viz-hd">
            <div>
              <h3>协议分布</h3>
              <p>
                <template v-if="activeProto">已筛 {{ activeProto.toUpperCase() }} · 再点取消</template>
                <template v-else>点击扇区 / 右侧名称筛选明细</template>
              </p>
            </div>
            <button v-if="activeProto" type="button" class="btn-text" @click="applyProtoFilter('')">清除</button>
          </header>
          <div class="proto-row" v-if="protoDonut">
            <svg width="116" height="116" viewBox="0 0 116 116">
              <path
                v-for="(a, i) in protoDonut.arcs" :key="i" :d="a.d" :fill="a.color"
                class="donut-arc" :class="{ on: activeProto === String(a.name).toLowerCase() }"
                @click.stop="clickProto(a.name)"
              />
              <circle cx="58" cy="58" r="24" fill="#fff" />
              <text x="58" y="55" text-anchor="middle" class="donut-n">{{ protoDonut.total }}</text>
              <text x="58" y="70" text-anchor="middle" class="donut-l">总计</text>
            </svg>
            <ul class="proto">
              <li
                v-for="a in protoDonut.arcs" :key="a.name"
                :class="{ on: activeProto === String(a.name).toLowerCase() }"
                @click="clickProto(a.name)"
              >
                <i :style="{ background: a.color }" />
                <span class="name">{{ a.name }}</span>
                <b>{{ a.value }}</b>
                <em>{{ a.pct }}%</em>
              </li>
            </ul>
          </div>
          <p v-else class="empty-sm">无协议数据</p>
        </div>

        <div class="na-card viz-card">
          <header class="viz-hd">
            <div><h3>端口 / 进程</h3><p>点击筛明细</p></div>
            <button v-if="portFilter || procFilter" type="button" class="btn-text" @click="clearLocalFilters">清除</button>
          </header>
          <div class="side-grid">
            <div>
              <h4>高频端口</h4>
              <button
                v-for="([port, n], i) in topPorts.slice(0, 7)" :key="'p'+i" type="button" class="rank"
                :class="{ on: portFilter === String(port), hot: isHotPort(port) }"
                @click="togglePort(port)"
              >
                <code>{{ port }}</code>
                <span class="track"><i :style="{ width: (100 * n / portMax) + '%' }" /></span>
                <em>{{ n }}</em>
              </button>
            </div>
            <div>
              <h4>活跃进程</h4>
              <button
                v-for="([name, n], i) in topProcs.slice(0, 7)" :key="'r'+i" type="button" class="rank"
                :class="{ on: procFilter === name }" :title="name" @click="toggleProc(name)"
              >
                <code class="proc">{{ name }}</code>
                <span class="track"><i :style="{ width: (100 * n / procMax) + '%' }" /></span>
                <em>{{ n }}</em>
              </button>
            </div>
          </div>
        </div>
      </div>
    </template>
    </div>

    <div v-if="rawItems.length" class="na-detail-grid" ref="tableEl">
        <div class="na-card table-card">
          <header class="viz-hd">
            <div>
              <h3>外联明细</h3>
              <p>
                {{ items.length }} 条
                <template v-if="activeProto"> · 协议 {{ activeProto.toUpperCase() }}</template>
                <template v-if="geoFilter"> · {{ ({ overseas: '境外', domestic: '国内', cloud: '云' })[geoFilter] }}</template>
                <template v-if="riskFilter"> · 风险 {{ riskFilter }}</template>
                <template v-if="portFilter"> · 端口 {{ portFilter }}</template>
                <template v-if="procFilter"> · {{ procFilter }}</template>
                · 点击行查看详情
              </p>
            </div>
            <button
              v-if="activeProto || portFilter || procFilter || geoFilter || riskFilter"
              type="button" class="btn-text"
              @click="geoFilter=''; riskFilter=''; applyProtoFilter(''); clearLocalFilters()"
            >清除筛选</button>
          </header>
          <div class="table-wrap">
            <table class="tbl">
              <thead>
                <tr>
                  <th>时间</th><th>进程</th><th>目的地 / 请求</th><th>协议</th><th>归属</th><th>标记</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="it in items" :key="it.id" class="row"
                  :class="[{ new: it.is_new, on: focusId === it.id, http: isHttpItem(it) }, 'risk-' + riskClass(it)]"
                  @click="selectRow(it)"
                >
                  <td class="mono muted">{{ fmt(it.ts) }}</td>
                  <td><span class="proc-cell">{{ procLabel(it) }}</span></td>
                  <td class="dest">
                    <div class="dest-main">
                      <span class="host">{{ destHost(it) }}</span>
                      <span v-if="destPort(it)" class="port">:{{ destPort(it) }}</span>
                    </div>
                    <div v-if="httpRequestLine(it)" class="muted sm http-line">{{ httpRequestLine(it) }}</div>
                  </td>
                  <td><span class="proto-tag" :data-p="it.proto">{{ it.proto || '—' }}</span></td>
                  <td>
                    <div class="tag-stack">
                      <span v-for="lb in ipLabels(it)" :key="lb" class="geo-tag" :data-t="lb">{{ lb }}</span>
                      <span v-if="!ipLabels(it).length" class="muted sm">—</span>
                    </div>
                  </td>
                  <td>
                    <div class="tag-stack">
                      <span v-if="it.ip_risk === 'alert'" class="pill alert">告警</span>
                      <span v-else-if="it.ip_risk === 'watch'" class="pill watch">关注</span>
                      <span v-if="it.is_new" class="pill new">新增</span>
                      <span v-else class="pill">基线内</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
            <p v-if="!items.length" class="empty-sm">当前筛选无明细（可点「清除筛选」或取消仅 HTTP）</p>
          </div>
        </div>

        <aside class="na-card focus-card" v-if="focusItem">
          <header class="viz-hd focus-hd">
            <div>
              <h3>连接详情</h3>
              <p>{{ fmt(focusItem.ts) }}</p>
            </div>
            <button type="button" class="btn-text" @click="focusId = ''">关闭</button>
          </header>
          <div class="focus-scroll">
            <div class="focus-grid">
              <div class="kv"><em>进程</em><code>{{ procLabel(focusItem) }}</code></div>
              <div class="kv" v-if="focusItem.process_path"><em>映像路径</em><code class="sm-break">{{ focusItem.process_path }}</code></div>
              <div class="kv"><em>主机</em><span>{{ focusItem.hostname || focusItem.agent_id || '—' }}</span></div>
              <div class="kv"><em>目的地</em>
                <button type="button" class="linkish" @click="copyDest(focusItem)">
                  {{ focusItem.dest_key || '—' }}
                  <small>{{ copied === focusItem.dest_key ? '已复制' : '复制' }}</small>
                </button>
              </div>
              <div class="kv" v-if="focusItem.remote_ip"><em>解析 IP</em><code>{{ focusItem.remote_ip }}</code></div>
              <div class="kv"><em>协议</em><span class="proto-tag" :data-p="focusItem.proto">{{ focusItem.proto || '—' }}</span></div>
              <div class="kv"><em>类型</em><span>{{ focusItem.etype || '—' }}</span></div>
              <div class="kv" v-if="focusItem.http_source"><em>采集源</em><span>{{ focusItem.http_source }}</span></div>
              <div class="kv"><em>IP 归属</em>
                <div class="tag-stack">
                  <span v-for="lb in ipLabels(focusItem)" :key="lb" class="geo-tag" :data-t="lb">{{ lb }}</span>
                  <span v-if="!ipLabels(focusItem).length" class="muted">未匹配 / 域名无解析 IP</span>
                </div>
              </div>
              <div class="kv"><em>风险</em>
                <span class="pill" :class="riskClass(focusItem)">{{ focusItem.ip_risk_label || '正常' }}</span>
                <span v-if="focusItem.is_new" class="pill new">新增目的地</span>
                <span v-else class="pill">基线内</span>
              </div>
              <div class="kv" v-if="focusItem.local"><em>本地端点</em><code>{{ focusItem.local }}</code></div>
              <div class="kv" v-if="focusItem.entity_id"><em>实体</em><code class="sm-break">{{ focusItem.entity_id }}</code></div>
            </div>
            <div class="cmd-block risk-block" v-if="(focusItem.ip_risk_reasons || []).length" :data-r="focusItem.ip_risk">
              <div class="cmd-hd"><h5>风险提示</h5></div>
              <ul class="risk-reasons">
                <li v-for="(r, i) in focusItem.ip_risk_reasons" :key="i">{{ r }}</li>
              </ul>
            </div>
            <div class="cmd-block summary-block" v-if="focusItem.summary">
              <div class="cmd-hd"><h5>摘要</h5></div>
              <p class="summary">{{ focusItem.summary }}</p>
            </div>
            <div class="cmd-block" v-if="isHttpItem(focusItem) || focusItem.method || focusItem.url || focusItem.url_path">
              <div class="cmd-hd">
                <h5>HTTP 请求</h5>
                <button v-if="httpRequestLine(focusItem)" type="button" class="btn-text" @click="copyDest({ dest_key: httpRequestLine(focusItem) })">
                  {{ copied === httpRequestLine(focusItem) ? '已复制' : '复制' }}
                </button>
              </div>
              <pre>{{ httpRequestLine(focusItem) || '（无完整 URL）' }}</pre>
              <div class="http-meta">
                <span v-if="focusItem.method"><b>方法</b> {{ focusItem.method }}</span>
                <span v-if="focusItem.host || destHost(focusItem)"><b>Host</b> {{ focusItem.host || destHost(focusItem) }}</span>
                <span v-if="focusItem.remote_port || destPort(focusItem)"><b>端口</b> {{ focusItem.remote_port || destPort(focusItem) }}</span>
                <span v-if="focusItem.url_path"><b>路径</b> {{ focusItem.url_path }}</span>
                <span v-if="focusItem.url && focusItem.url.includes('://')"><b>URL</b> {{ focusItem.url }}</span>
                <span v-if="focusItem.http_source"><b>源</b> {{ focusItem.http_source }}</span>
              </div>
            </div>
            <div class="cmd-block" v-if="isHttpItem(focusItem) || focusItem.method || focusItem.url || focusItem.url_path">
              <div class="cmd-hd"><h5>服务器响应</h5></div>
              <p
                v-if="focusItem.status_code || focusItem.status_text || focusItem.response_status"
                class="resp-line"
                :class="respTone(focusItem.status_code || focusItem.response_status)"
              >
                <template v-if="focusItem.status_code || focusItem.response_status">
                  HTTP {{ focusItem.status_code || focusItem.response_status }}
                </template>
                <template v-if="focusItem.status_text"> · {{ focusItem.status_text }}</template>
              </p>
              <p v-else class="resp-miss">
                当前 WinINet/WebIO ETW 以请求侧为主；未采到状态码时无法确认服务器是否应答。
                升级 Agent 后若命中响应事件，这里会显示例如 <code>HTTP 200</code>。
              </p>
            </div>
            <p v-if="isHttpItem(focusItem) && !focusItem.method && !focusItem.url && !focusItem.url_path" class="empty-inline">
              WinINet 类事件有时只有主机/端口，没有 method 与完整 URL。
            </p>
          </div>
        </aside>

        <aside class="na-card focus-card empty-focus" v-else>
          <h3>连接详情</h3>
          <p>在左侧明细中点击一行，查看进程、目的地、HTTP 方法与 URL。</p>
        </aside>
      </div>
    </div>
  </section>
</template>

<style scoped>
.na.page,
.page.na,
.na {
  display: flex; flex-direction: column; gap: 12px;
  flex: 1; min-height: 0; height: 100%;
  overflow: hidden !important;
  padding-bottom: 12px;
  box-sizing: border-box;
}
.na > .na-hero,
.na > .na-toolbar,
.na > .banner { flex-shrink: 0; }
.na-main {
  display: flex; flex-direction: column; gap: 12px;
  flex: 1; min-height: 0; overflow: hidden;
}
.na-upper {
  display: flex; flex-direction: column; gap: 12px;
  flex: 0 0 auto;
}

.na-card {
  background: #fff;
  border: 1px solid #e4ebf5;
  border-radius: 14px;
  box-shadow: 0 1px 2px rgba(16, 24, 40, .04);
}

.na-hero {
  display: flex; justify-content: space-between; gap: 16px; align-items: flex-end;
  padding: 18px 20px; border-radius: 16px; border: 1px solid #e4ebf5;
  background:
    radial-gradient(900px 180px at 0% 0%, rgba(47,111,237,.10), transparent 55%),
    linear-gradient(180deg, #f7faff 0%, #fff 70%);
}
.eyebrow {
  margin: 0 0 4px; font-size: 11px; font-weight: 700; letter-spacing: .08em;
  text-transform: uppercase; color: #2f6fed;
}
.na-hero h1 { margin: 0 0 6px; font-size: 22px; letter-spacing: -.03em; color: var(--ink, #101828); }
.na-hero-copy p:last-child { margin: 0; max-width: 560px; color: #667085; font-size: 13px; line-height: 1.55; }

.na-toolbar {
  display: flex; flex-wrap: wrap; gap: 10px 12px; align-items: flex-end;
  padding: 12px 14px;
}
.na-toolbar .na-f {
  display: flex; flex-direction: column; gap: 4px;
  font-size: 12px; color: #98a2b3; margin: 0; min-width: 0;
}
.na-toolbar .na-f.agent { min-width: 180px; }
.na-toolbar .na-f.agent .field { min-width: 180px; max-width: 240px; }
.na-toolbar .na-f.num { min-width: 0; }
.na-toolbar .na-f.grow { flex: 1; min-width: 200px; }
.na-toolbar .na-f > span { line-height: 1.2; }
.na-num {
  display: inline-flex; align-items: center; gap: 6px;
}
.na-num .field {
  width: 84px; min-width: 84px; max-width: 84px;
}
.na-num em {
  font-style: normal; font-size: 12px; color: #667085; white-space: nowrap;
  line-height: 1; padding-bottom: 1px;
}
.na-checks {
  display: inline-flex; flex-wrap: wrap; gap: 6px; align-items: center;
  padding-bottom: 2px;
}
.na-toolbar .chk {
  display: inline-flex; flex-direction: row; align-items: center; gap: 6px;
  margin: 0; padding: 0; color: #344054; font-size: 13px; cursor: pointer;
}
.na-toolbar .chk input { margin: 0; }
.na-toolbar .chk span {
  padding: 6px 10px; border-radius: 999px; border: 1px solid #e4ebf5; background: #f8fafc;
}
.na-toolbar .chk input:checked + span { background: var(--accent-soft); border-color: #f0b6a0; color: var(--accent-2); font-weight: 650; }
.na-analyze { align-self: flex-end; margin-bottom: 1px; }
.field {
  padding: 8px 10px; border: 1px solid #d0d5dd; border-radius: 9px; font: inherit;
  min-width: 120px; background: #fff; color: var(--ink, #101828); box-sizing: border-box;
}
.na-f.grow .field { width: 100%; min-width: 0; }

.na-kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.na-kpis-6 { grid-template-columns: repeat(6, minmax(0, 1fr)); }
.banner.tip {
  margin: 0; padding: 8px 12px; border-radius: 8px; font-size: 12px;
  background: #f5f8ff; color: #344054; border: 1px solid #e4ebf5;
}
.kpi.overseas strong { color: #b54708; }
.kpi.cloud strong { color: #6941c6; }
.kpi.risk strong { color: #b42318; }
.kpi.overseas.on, .kpi.cloud.on, .kpi.risk.on { border-color: #f7b27a; }
.kpi {
  position: relative; overflow: hidden; text-align: left; font: inherit;
  padding: 16px 16px 14px;
  transition: border-color .15s, box-shadow .15s, transform .15s;
}
button.kpi { cursor: pointer; }
button.kpi:hover, button.kpi.on {
  border-color: #93b4f5; box-shadow: 0 8px 24px rgba(47,111,237,.10); transform: translateY(-1px);
}
.kpi.hot { background: linear-gradient(160deg, #fff8f0, #fff); }
.kpi.http.on, .kpi.http:hover { border-color: #7ad3b8; box-shadow: 0 8px 24px rgba(14,124,102,.10); }
.kpi-lab { display: block; color: #98a2b3; font-size: 12px; margin-bottom: 8px; }
.kpi strong {
  display: block; font-size: 30px; letter-spacing: -.04em; line-height: 1;
  font-variant-numeric: tabular-nums; color: var(--ink, #101828);
}
.kpi.hot strong { color: #b54708; }
.kpi.http.on strong { color: #0e7c66; }
.kpi-sub { display: block; margin-top: 8px; color: #98a2b3; font-size: 11px; }
.kpi .ring {
  position: absolute; right: 14px; top: 16px; width: 36px; height: 36px; border-radius: 50%;
  background: conic-gradient(#e97815 var(--p), #f2f4f7 0);
  -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 5px), #000 calc(100% - 4px));
  mask: radial-gradient(farthest-side, transparent calc(100% - 5px), #000 calc(100% - 4px));
}

.banner.err { margin: 0; padding: 8px 12px; border-radius: 8px; background: #fdecea; color: #a1281d; }
.na-empty { padding: 48px 24px; text-align: center; color: #667085; }
.na-empty h3 { margin: 8px 0 6px; color: #101828; }
.na-empty p { margin: 0 auto; max-width: 420px; line-height: 1.55; }
.empty-art { display: flex; justify-content: center; }

.na-viz { display: grid; grid-template-columns: 1.35fr .85fr .95fr; gap: 12px; }
.viz-card, .table-card, .focus-card { padding: 14px 16px; }
.viz-hd { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; margin-bottom: 12px; }
.viz-hd h3 { margin: 0 0 2px; font-size: 14px; font-weight: 650; color: #101828; }
.viz-hd p { margin: 0; color: #98a2b3; font-size: 12px; }
.legend { display: flex; gap: 12px; align-items: center; color: #667085; font-size: 12px; white-space: nowrap; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 4px; vertical-align: -1px; }
.legend i.obs { background: #c7d7f5; }
.legend i.nw { background: #e97815; }

.trend-wrap { height: 140px; }
.trend-svg { width: 100%; height: 140px; display: block; }
.axis { fill: #98a2b3; font-size: 10px; }

.proto-row { display: flex; gap: 14px; align-items: center; }
.donut-arc { cursor: pointer; transition: opacity .12s; }
.donut-arc:hover, .donut-arc.on { opacity: .85; filter: brightness(1.05); }
.donut-n { font-size: 15px; font-weight: 750; fill: #101828; }
.donut-l { font-size: 10px; fill: #98a2b3; }
.proto { list-style: none; margin: 0; padding: 0; flex: 1; display: flex; flex-direction: column; gap: 6px; }
.proto li {
  display: grid; grid-template-columns: 10px 1fr 34px 36px; gap: 6px; align-items: center;
  font-size: 12px; padding: 5px 6px; border-radius: 8px; cursor: pointer;
}
.proto li:hover, .proto li.on { background: #f5f8ff; }
.proto li i { width: 8px; height: 8px; border-radius: 2px; }
.proto .name { color: #344054; font-weight: 650; text-transform: uppercase; overflow: hidden; text-overflow: ellipsis; }
.proto b, .proto em, .rank em {
  text-align: right; font-style: normal; font-variant-numeric: tabular-nums; font-weight: 700; color: #344054;
}
.proto em { color: #98a2b3; font-weight: 500; }

.side-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.side-grid h4 { margin: 0 0 8px; font-size: 11px; letter-spacing: .04em; text-transform: uppercase; color: #98a2b3; }
.rank {
  width: 100%; display: grid; grid-template-columns: minmax(48px, 78px) 1fr 28px; gap: 6px; align-items: center;
  margin-bottom: 5px; padding: 5px 6px; border: 0; background: transparent; border-radius: 8px;
  font: inherit; font-size: 12px; cursor: pointer; text-align: left; transition: background .12s;
}
.rank:hover, .rank.on { background: #f5f8ff; }
.rank code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11px; color: #344054; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.rank.hot code { color: #b54708; font-weight: 700; }
.rank .track { height: 7px; background: #eef2f7; border-radius: 999px; overflow: hidden; }
.rank .track i { display: block; height: 100%; background: linear-gradient(90deg, #6b9aff, #2f6fed); border-radius: inherit; }
.rank.hot .track i { background: linear-gradient(90deg, #f7b27a, #e97815); }

.na-detail-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(300px, .85fr);
  gap: 12px;
  align-items: stretch;
  flex: 1;
  min-height: 0;
  overflow: hidden;
}
.table-card {
  display: flex; flex-direction: column;
  padding: 0;
  min-width: 0;
  min-height: 0;
  height: 100%;
  overflow: hidden;
}
.table-card > .viz-hd { flex-shrink: 0; padding: 12px 14px 8px; }
.table-wrap {
  flex: 1;
  min-height: 0;
  overflow: auto;
  border-top: 1px solid #eef2f7;
  background: #fff;
  padding-bottom: 8px;
  -webkit-overflow-scrolling: touch;
}
.tbl { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 13px; }
.tbl th, .tbl td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #f0f3f8; vertical-align: top; }
.tbl th {
  color: #667085; font-weight: 650; position: sticky; top: 0; background: #f7f9fc;
  font-size: 12px; z-index: 1;
}
.tbl th:nth-child(1), .tbl td:nth-child(1) { width: 120px; }
.tbl th:nth-child(2), .tbl td:nth-child(2) { width: 130px; }
.tbl th:nth-child(3), .tbl td:nth-child(3) { width: auto; }
.tbl th:nth-child(4), .tbl td:nth-child(4) { width: 64px; }
.tbl th:nth-child(5), .tbl td:nth-child(5) { width: 110px; }
.tbl th:nth-child(6), .tbl td:nth-child(6) { width: 100px; }
.tbl tr.row.risk-alert td { background: #fff8f6; }
.tbl tr.row.risk-watch td { background: #fffcf5; }
.tbl tr.row.risk-alert.on td, .tbl tr.row.risk-watch.on td { background: #eef4ff; }
.tag-stack { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
.geo-tag {
  display: inline-flex; padding: 1px 6px; border-radius: 5px;
  font-size: 10px; font-weight: 700; background: #eef2f7; color: #475467;
}
.geo-tag[data-t="境外"] { background: #fef0c7; color: #b54708; }
.geo-tag[data-t="国内"] { background: #e8f8f2; color: #0e7c66; }
.geo-tag[data-t^="云:"] { background: #f4f3ff; color: #6941c6; }
.tbl tr.row { cursor: pointer; transition: background .12s; }
.tbl tr.row:hover td { background: #f5f8ff; }
.tbl tr.row.on td { background: #eef4ff; }
.tbl tr.row.new td:first-child { box-shadow: inset 3px 0 0 #e97815; }
.tbl tr.row.http td:first-child { box-shadow: inset 3px 0 0 #0e7c66; }
.tbl tr.row.http.new td:first-child { box-shadow: inset 3px 0 0 #e97815; }
.dest { min-width: 0; }
.dest-main {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.dest-main .host { color: #101828; }
.dest-main .port { color: #667085; }
.http-line {
  margin-top: 3px; color: #0e7c66 !important;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%;
}
.proc-cell {
  display: block; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px; color: #101828; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.proto-tag {
  display: inline-flex; padding: 2px 8px; border-radius: 6px;
  background: #eef2f7; color: #475467; font-size: 11px; font-weight: 700; text-transform: uppercase;
}
.proto-tag[data-p="http"] { background: #e8f8f2; color: #0e7c66; }
.pill {
  display: inline-flex; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700;
  background: #eef2f7; color: #667085;
}
.pill.new { background: #fff1e0; color: #b54708; }
.pill.watch, .pill[data-s="watch"] { background: #fef0c7; color: #b54708; }
.pill.alert, .pill[data-s="alert"] { background: #fee4e2; color: #b42318; }
.pill.info { background: #eef2f7; color: #667085; }
.risk-block[data-r="alert"] { background: #fff8f6; border: 1px solid #fecdca; border-radius: 10px; padding: 10px 12px; }
.risk-block[data-r="watch"] { background: #fffaeb; border: 1px solid #fedf89; border-radius: 10px; padding: 10px 12px; }
.risk-reasons { margin: 0; padding-left: 18px; color: #344054; font-size: 12px; line-height: 1.55; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.muted { color: #98a2b3; }
.sm { font-size: 12px; }
.empty-sm { text-align: center; color: #98a2b3; margin: 28px 0; }

.focus-card.empty-focus {
  display: flex; flex-direction: column; justify-content: center; color: #98a2b3; text-align: center;
  padding: 28px 16px;
}
.focus-card.empty-focus h3 { margin: 0 0 8px; color: #344054; font-size: 14px; }
.focus-card.empty-focus p { margin: 0; line-height: 1.5; font-size: 13px; }
.focus-hd { flex-shrink: 0; padding: 12px 14px 8px; border-bottom: 1px solid #eef2f7; }
.focus-scroll {
  flex: 1;
  min-height: 0;
  overflow-x: hidden;
  overflow-y: auto;
  padding: 10px 12px 16px;
  -webkit-overflow-scrolling: touch;
  overscroll-behavior: contain;
}
.focus-scroll::-webkit-scrollbar { width: 10px; }
.focus-scroll::-webkit-scrollbar-track { background: #f2f4f7; border-radius: 8px; }
.focus-scroll::-webkit-scrollbar-thumb {
  background: #b8c0cc; border-radius: 8px; border: 2px solid #f2f4f7;
}
.focus-scroll::-webkit-scrollbar-thumb:hover { background: #98a2b3; }
.focus-grid {
  display: grid; grid-template-columns: 1fr; gap: 8px;
  padding: 10px 12px; border-radius: 10px; background: #f8fafc; border: 1px solid #eef2f7;
}
.kv { display: flex; flex-direction: column; gap: 3px; min-width: 0; font-size: 12px; color: #344054; }
.kv em { font-style: normal; color: #98a2b3; font-size: 11px; font-weight: 650; }
.kv code, .sm-break {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all;
}
.linkish {
  border: 0; background: transparent; padding: 0; font: inherit; color: #2f6fed;
  cursor: pointer; text-align: left; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  word-break: break-all;
}
.linkish small { margin-left: 6px; color: #98a2b3; font-family: inherit; }
.cmd-block { margin-top: 12px; }
.cmd-hd h5 { margin: 0 0 6px; font-size: 12px; color: #667085; }
.cmd-block pre {
  margin: 0; white-space: pre-wrap; word-break: break-all;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
  background: #0f1724; color: #e4e7ec; padding: 10px 12px; border-radius: 10px;
}
.summary-block {
  padding: 10px 12px; border-radius: 10px; background: #f5f8ff; border: 1px solid #e4ebf5;
}
.summary { margin: 0; font-size: 13px; color: #344054; line-height: 1.55; word-break: break-all; overflow-wrap: anywhere; }
.http-meta {
  display: flex; flex-wrap: wrap; gap: 8px 14px; margin-top: 8px; font-size: 12px; color: #475467;
}
.http-meta > span { max-width: 100%; word-break: break-all; overflow-wrap: anywhere; }
.http-meta b { color: #98a2b3; font-weight: 650; margin-right: 4px; }
.resp-line {
  margin: 0; padding: 10px 12px; border-radius: 10px;
  background: #f8fafc; border: 1px solid #eef2f7; color: #344054; font-size: 13px;
  word-break: break-all;
}
.resp-line.ok { background: #ecfdf3; border-color: #abefc6; color: #027a48; }
.resp-line.warn { background: #fffaeb; border-color: #fedf89; color: #b54708; }
.resp-line.err { background: #fef3f2; border-color: #fecdca; color: #b42318; }
.resp-miss { margin: 0; color: #667085; font-size: 12px; line-height: 1.5; }
.empty-inline { margin: 12px 0 0; color: #98a2b3; font-size: 12px; }
.focus-card {
  align-self: stretch;
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  overflow: hidden;
  padding: 0;
  min-width: 0;
}

@media (max-width: 1200px) {
  .na-kpis, .na-kpis-6, .na-viz, .side-grid, .na-detail-grid { grid-template-columns: 1fr; }
}
</style>
<style scoped src="./analysisPageTheme.css"></style>
