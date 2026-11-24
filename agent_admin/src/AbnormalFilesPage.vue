<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { createAgentCommand, downloadAgentSample, listAgentCommands, listAgents, listAbnormalFiles } from './api'
import { latestRequest } from './latestRequest.js'

const busy = ref(false)
const err = ref('')
const agents = ref([])
const agentId = ref('')
const hours = ref(0) // 0 = 当天
const q = ref('')
const onlyRuleHit = ref(false)
const unsignedOnly = ref(false)
const extFilter = ref('')
const data = ref(null)
const focusId = ref('')
const requests = latestRequest()
let initialized = false
let disposed = false

function fmt(t) { return String(t || '').replace('T', ' ').slice(0, 19) || '—' }
function sevLabel(s) {
  return ({ critical: '危急', high: '高危', medium: '中危', low: '低危', info: '信息' })[String(s || '').toLowerCase()] || s || '—'
}
function signedLabel(s) {
  const v = String(s || '').toLowerCase()
  if (!v) return '未知'
  if (v === 'valid' || v === 'signed' || v === 'trusted') return '签名有效'
  if (v === 'notsigned' || v === 'unsigned') return '无签名'
  if (v === 'hashmismatch') return '哈希不匹配'
  return s
}
function etypeLabel(e) {
  const m = {
    file_create: '创建',
    file_delete: 'Deleted',
    file_rename: 'Renamed',
    file_write: '写入',
    file_write_etw: '写入',
    file_stream_create: 'ADS',
    fim_add: 'FIM 新增',
    fim_modify: 'FIM modify',
    fim_rename: '重命名',
  }
  return m[String(e || '')] || e || '—'
}
function shortPath(p, n = 48) {
  const s = String(p || '')
  if (s.length <= n) return s
  return `…${s.slice(-(n - 1))}`
}
function fmtSize(v) {
  const n = Number(v)
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(2)} MB`
}
async function copyText(t) {
  try { await navigator.clipboard.writeText(String(t || '')) } catch { /* ignore */ }
}

const sampleBusy = ref(false)
const sampleMsg = ref('')
const sampleErr = ref('')
const lastSampleCmd = ref(null)

async function pullSample() {
  const it = focus.value
  if (!it?.agent_id || !it?.path) {
    sampleErr.value = '缺少终端或路径'
    return
  }
  if (!window.confirm(`从终端提取样本到平台？\n${it.path}\n\n上限 64MB；成功后自动下载到浏览器下载目录。不修改原文件。`)) return
  sampleBusy.value = true
  sampleErr.value = ''
  sampleMsg.value = '指令已下发，等待终端回传…'
  lastSampleCmd.value = null
  try {
    const params = { path: it.path }
    const sha = String(it.sha256 || '').trim()
    if (/^[0-9a-fA-F]{64}$/.test(sha)) params.sha256 = sha.toLowerCase()
    const r = await createAgentCommand(it.agent_id, 'pull_file', params)
    lastSampleCmd.value = { agent_id: it.agent_id, id: r?.id }
    // 轮询最多 ~40s
    for (let i = 0; i < 20; i++) {
      await new Promise((res) => setTimeout(res, 2000))
      const list = await listAgentCommands(it.agent_id)
      const cmd = (list?.items || list || []).find((c) => c.id === r?.id)
      if (!cmd) continue
      if (cmd.status === 'failed') {
        let detail = cmd.result_json || '采集失败'
        try { detail = JSON.parse(cmd.result_json)?.error || detail } catch { /* */ }
        throw new Error(typeof detail === 'string' ? detail : '采集失败')
      }
      if (cmd.status === 'done') {
        let stored = false
        try { stored = !!JSON.parse(cmd.result_json || '{}').stored } catch { /* */ }
        if (stored) {
          await downloadAgentSample(it.agent_id, cmd.id)
          sampleMsg.value = '样本已下载到本地'
          return
        }
        throw new Error('终端已执行但样本未入库')
      }
    }
    sampleMsg.value = '仍在等待回传，可稍后在威胁视图「处置结果」中下载'
  } catch (e) {
    sampleErr.value = e?.message || String(e)
    sampleMsg.value = ''
  } finally {
    sampleBusy.value = false
  }
}

async function downloadLastSample() {
  const c = lastSampleCmd.value
  if (!c?.id) return
  try {
    await downloadAgentSample(c.agent_id, c.id)
    sampleMsg.value = '样本已下载到本地'
  } catch (e) {
    sampleErr.value = e?.message || String(e)
  }
}

async function loadAgents() {
  try {
    const r = await listAgents()
    agents.value = r.items || []
  } catch { /* ignore */ }
}

async function load() {
  if (disposed) return
  const current = requests.begin()
  busy.value = true
  err.value = ''
  data.value = null
  try {
    const result = await listAbnormalFiles({
      agent_id: agentId.value || '',
      hours: hours.value,
      q: q.value,
      only_rule_hit: onlyRuleHit.value,
      unsigned_only: unsignedOnly.value,
      ext: extFilter.value,
      limit: 400,
    })
    if (!current()) return
    data.value = result
    if (focusId.value && !(data.value?.items || []).some((x) => x.id === focusId.value)) {
      focusId.value = ''
    }
  } catch (e) {
    if (!current()) return
    err.value = e.message || String(e)
    data.value = null
  } finally {
    if (current()) busy.value = false
  }
}

const stats = computed(() => data.value?.stats || { files: '—', rule_hits: '—', unsigned: '—', hosts: '—' })
const items = computed(() => data.value?.items || [])
const focus = computed(() => items.value.find((x) => x.id === focusId.value) || items.value[0] || null)

onMounted(async () => {
  await loadAgents()
  if (disposed) return
  initialized = true
  await load()
})
watch([agentId, hours], () => { if (initialized) load() })
onBeforeUnmount(() => { disposed = true; requests.invalidate() })
</script>

<template>
  <section class="page af" :aria-busy="busy">
    <header class="af-top">
      <div class="af-title">
        <p class="eyebrow">文件狩猎</p>
        <h1>异常文件</h1>
      </div>
      <div class="af-toolbar">
        <label><span>终端</span>
          <select v-model="agentId" class="field">
            <option value="">全部终端</option>
            <option v-for="a in agents" :key="a.agent_id || a.id" :value="a.agent_id || a.id">
              {{ a.hostname || a.agent_id || a.id }}
            </option>
          </select>
        </label>
        <label><span>时间</span>
          <select v-model.number="hours" class="field">
            <option :value="0">今天</option>
            <option :value="6">近 6 小时</option>
            <option :value="24">近 24 小时</option>
            <option :value="72">近 3 天</option>
          </select>
        </label>
        <label><span>扩展名</span>
          <input v-model="extFilter" class="field narrow" placeholder="exe,dll" @keyup.enter="load" />
        </label>
        <label class="chk"><input type="checkbox" v-model="onlyRuleHit" @change="load" /> 仅规则命中</label>
        <label class="chk"><input type="checkbox" v-model="unsignedOnly" @change="load" /> 仅未签名</label>
        <input v-model="q" class="field search" placeholder="路径 / 文件名 / 主机" @keyup.enter="load" />
        <button type="button" class="btn primary sm" :disabled="busy" @click="load">{{ busy ? '加载中…' : '查询' }}</button>
        <div class="af-meta">
          <span>窗口 <b class="mono">{{ data?.since ? fmt(data.since).slice(0, 16) : '—' }}</b></span>
        </div>
      </div>
    </header>

    <p v-if="err" class="banner err">
      {{ err }}
      <span v-if="/not found/i.test(err)" class="hint-inline"> · 接口未注册，请重启 EDR 后台后再查</span>
    </p>

    <div class="af-kpis">
      <div class="kpi"><em>新增文件</em><b>{{ stats.files }}</b></div>
      <div class="kpi hot"><em>规则命中</em><b>{{ stats.rule_hits }}</b></div>
      <div class="kpi"><em>未签名/未知</em><b>{{ stats.unsigned }}</b></div>
      <div class="kpi"><em>涉及终端</em><b>{{ stats.hosts }}</b></div>
    </div>

    <div v-if="data?.query_info" class="af-query-info" role="status">
      <span>启用规则 <b>{{ data.query_info.active_rules }}</b></span>
      <span>查询范围内源事件 <b>{{ data.query_info.source_rows }}</b></span>
      <span>查询上限 <b>{{ data.query_info.source_limit }}</b></span>
      <span v-if="data.query_info.source_rows >= data.query_info.source_limit">当前结果仅覆盖查询上限内的数据。</span>
      <span v-else-if="data.query_info.active_rules && data.query_info.source_rows && !stats.rule_hits">当前返回结果未命中规则，请核对路径范围、扩展名和时间筛选。</span>
      <span v-else-if="!data.query_info.source_rows">当前查询范围没有源事件。</span>
    </div>

    <div v-if="!items.length && !busy" class="af-empty panel">
      <div class="empty-art" aria-hidden="true">
        <svg viewBox="0 0 200 90" width="200" height="90">
          <rect x="62" y="18" width="76" height="54" rx="8" fill="#f7faff" stroke="#93b4f5" />
          <path d="M78 36h44M78 48h32M78 60h38" stroke="#c5cedb" stroke-width="3" stroke-linecap="round" />
          <circle cx="148" cy="28" r="14" fill="#fff5f5" stroke="#f7a39a" />
          <path d="M148 22v8M148 34.5v.5" stroke="#b42318" stroke-width="2.5" stroke-linecap="round" />
        </svg>
      </div>
      <h3>{{ err ? '无法加载异常文件' : '暂无异常文件' }}</h3>
      <p v-if="err">后端返回错误。确认已重启 EDR 服务（加载 <code class="mono">/api/edr/abnormal-files</code>），再点查询。</p>
      <p v-else>当天尚无新增文件上报，或筛选过严。可放宽时间窗 / 扩展名，或在「异常文件规则」中配置关注路径（如 <code class="mono">C:\</code> 覆盖根与子目录）。</p>
    </div>

    <div v-else class="af-body">
      <div class="af-list panel">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>终端</th>
              <th>文件</th>
              <th>类型</th>
              <th>签名</th>
              <th>规则</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="it in items"
              :key="it.id"
              :class="{ on: focus?.id === it.id, hit: it.rule_hit }"
              tabindex="0"
              :aria-selected="focus?.id === it.id"
              @click="focusId = it.id"
              @keydown.enter.prevent="focusId = it.id"
              @keydown.space.prevent="focusId = it.id"
            >
              <td class="mono muted">{{ fmt(it.ts) }}</td>
              <td>{{ it.hostname || it.agent_id }}</td>
              <td class="mono path" :title="it.path">{{ it.name || it.path }}</td>
              <td><span class="etype">{{ etypeLabel(it.etype) }}</span></td>
              <td :class="{ bad: /unsigned|notsigned|hash/i.test(String(it.signed || '')) || !it.signed }">
                {{ signedLabel(it.signed) }}
              </td>
              <td>
                <span v-if="it.rule_hit" class="tag hit">{{ it.rule_hits?.[0]?.title || '命中' }}</span>
                <span v-else class="muted">—</span>
              </td>
            </tr>
            <tr v-if="busy && !items.length">
              <td colspan="6" class="empty">加载中…</td>
            </tr>
          </tbody>
        </table>
      </div>

      <aside v-if="focus" class="af-detail panel">
        <header class="detail-hd">
          <div>
            <h3 :title="focus.name">{{ focus.name || '文件详情' }}</h3>
          </div>
          <span v-if="focus.rule_hit" class="sev" data-s="high">规则命中</span>
        </header>
        <dl>
          <div class="wide"><dt>路径</dt>
            <dd class="mono wrap path-row">
              <span>{{ focus.path || '—' }}</span>
              <button v-if="focus.path" type="button" class="btn-text sm" @click="copyText(focus.path)">复制</button>
            </dd>
          </div>
          <div><dt>文件名</dt><dd class="mono" :title="focus.name">{{ focus.name || '—' }}</dd></div>
          <div><dt>终端</dt><dd>{{ focus.hostname || focus.agent_id }}</dd></div>
          <div><dt>时间</dt><dd class="mono">{{ fmt(focus.ts) }}</dd></div>
          <div><dt>事件</dt><dd>{{ etypeLabel(focus.etype) }} <span class="muted mono">({{ focus.etype }})</span></dd></div>
          <div v-if="focus.summary"><dt>摘要</dt><dd class="wrap">{{ focus.summary }}</dd></div>
          <div v-if="focus.label || focus.root"><dt>监控点</dt><dd>{{ focus.label || '—' }}<span v-if="focus.root" class="muted mono"> · {{ focus.root }}</span></dd></div>
          <div><dt>大小</dt><dd>{{ fmtSize(focus.size) }}</dd></div>
          <div v-if="focus.mtime"><dt>修改时间</dt><dd class="mono">{{ fmt(focus.mtime) }}</dd></div>
          <div><dt>签名</dt><dd>{{ signedLabel(focus.signed) }}{{ focus.signer ? ` · ${focus.signer}` : '' }}</dd></div>
          <div class="wide"><dt>SHA256</dt><dd class="mono wrap">{{ focus.sha256 || '—（非可执行 / 未哈希）' }}</dd></div>
          <div><dt>MD5</dt><dd class="mono">{{ focus.md5 || '—' }}</dd></div>
          <div><dt>进程</dt><dd>{{ focus.process_name || '—' }}{{ focus.pid != null && focus.pid !== '' ? ` (PID ${focus.pid})` : '' }}</dd></div>
          <div><dt>用户</dt><dd>{{ focus.user || '—' }}</dd></div>
          <div v-if="focus.old_path"><dt>原路径</dt><dd class="mono wrap">{{ focus.old_path }}</dd></div>
        </dl>
        <div class="af-actions">
          <button type="button" class="btn primary" :disabled="sampleBusy || !focus.path || !focus.agent_id" @click="pullSample">
            {{ sampleBusy ? '采集中…' : '采集样本' }}
          </button>
          <button v-if="lastSampleCmd?.id" type="button" class="btn sm" :disabled="sampleBusy" @click="downloadLastSample">下载样本</button>
        </div>
        <p v-if="sampleMsg" class="af-sample-msg">{{ sampleMsg }}</p>
        <p v-if="sampleErr" class="af-sample-err">{{ sampleErr }}</p>
        <div v-if="(focus.rule_hits || []).length" class="af-hits">
          <h4>异常文件规则命中</h4>
          <div v-for="h in focus.rule_hits" :key="h.rule_id" class="hit-chip" :data-s="h.severity">
            <b>{{ h.title }}</b>
            <small class="mono">{{ h.matched }}</small>
            <em>{{ sevLabel(h.severity) }}</em>
          </div>
        </div>
      </aside>
    </div>
  </section>
</template>

<style scoped>
.af {
  display: flex; flex-direction: column; gap: 14px;
  flex: 1; min-height: 0; height: 100%; overflow: hidden;
  box-sizing: border-box;
}
.af-top {
  flex: 0 0 auto;
  display: flex; flex-wrap: wrap; align-items: flex-end; justify-content: space-between;
  gap: 12px 20px; padding: 14px 18px; border-radius: 14px;
  background: #fff; border: 1px solid #e8eef6;
}
.af-title { min-width: 0; }
.eyebrow {
  margin: 0 0 2px; font-size: 11px; font-weight: 700; letter-spacing: .08em;
  text-transform: uppercase; color: #2f6fed;
}
.af-title h1 { margin: 0; font-size: 20px; letter-spacing: -.03em; color: var(--ink, #101828); }

.af-toolbar {
  display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: flex-end;
}
.af-toolbar label {
  display: flex; flex-direction: column; gap: 3px; font-size: 11px; color: #98a2b3;
}
.af-toolbar label.chk {
  flex-direction: row; align-items: center; gap: 6px;
  padding-bottom: 8px; color: #344054; font-size: 12px;
}
.field {
  padding: 7px 10px; border: 1px solid #d0d5dd; border-radius: 8px; font: inherit;
  min-width: 140px; background: #fff; color: var(--ink, #101828);
}
.field.narrow { width: 88px; min-width: 88px; }
.field.search { min-width: 180px; flex: 1; }
.af-meta {
  margin-left: 4px; display: flex; gap: 14px; align-items: center;
  color: #98a2b3; font-size: 12px; padding-bottom: 6px;
}
.af-meta b { color: #101828; font-variant-numeric: tabular-nums; font-weight: 650; }

.af-kpis { flex: 0 0 auto; display: flex; flex-wrap: wrap; gap: 8px; }
.kpi {
  display: inline-flex; align-items: baseline; gap: 8px;
  padding: 8px 16px; border-radius: 999px; background: #fff; border: 1px solid #e8eef6;
  min-width: 110px;
}
.kpi em { font-style: normal; color: #98a2b3; font-size: 12px; }
.kpi b {
  font-size: 16px; letter-spacing: -.02em; line-height: 1;
  font-variant-numeric: tabular-nums; color: #101828;
}
.kpi.hot { background: #fef3f2; border-color: #fecdca; }
.kpi.hot b { color: #b42318; }

.banner {
  flex: 0 0 auto; margin: 0; padding: 8px 12px; border-radius: 8px; font-size: 13px;
}
.banner.err { background: #fdecea; color: #a1281d; }
.hint-inline { opacity: .85; font-size: 12px; }

.af-empty {
  flex: 1; min-height: 0; overflow: auto; padding: 48px 24px; text-align: center; color: #667085;
}
.af-empty h3 { margin: 8px 0 6px; color: #101828; }
.af-empty p { margin: 0 auto; max-width: 460px; line-height: 1.55; }
.empty-art { display: flex; justify-content: center; }

.af-body {
  display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(280px, .95fr); gap: 14px;
  flex: 1; min-height: 0; overflow: hidden;
}
.af-list {
  overflow: auto; min-height: 0; height: 100%; padding: 0;
  border: 1px solid #e8eef6; border-radius: 14px; background: #fff;
}
.af-list table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.af-list th {
  text-align: left; padding: 10px 14px; background: #f8fafc; color: #667085;
  position: sticky; top: 0; z-index: 1; border-bottom: 1px solid #e8eef6; font-weight: 650;
}
.af-list td { padding: 10px 14px; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }
.af-list tr { cursor: pointer; transition: background .12s; }
.af-list tr:hover td { background: #f8fafc; }
.af-list tr.on td { background: #f0f6ff; }
.af-list tr.hit td:first-child { box-shadow: inset 3px 0 0 #f04438; }
.af-list .path { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.af-list .empty { text-align: center; color: #98a2b3; padding: 28px; }
.af-list .bad { color: #b42318; font-weight: 600; }
.etype {
  display: inline-block; padding: 1px 7px; border-radius: 6px;
  background: #f2f4f7; color: #475467; font-size: 11px; font-weight: 650;
}
.tag.hit {
  background: #fee4e2; color: #b42318; font-size: 11px;
  padding: 2px 8px; border-radius: 6px; font-weight: 700;
}
.muted { color: #98a2b3; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }

.af-detail {
  overflow: auto; min-height: 0; height: 100%; padding: 16px 18px;
  border: 1px solid #e8eef6; border-radius: 14px; background: #fff;
}
.detail-hd {
  display: flex; justify-content: space-between; align-items: flex-start; gap: 12px;
  margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid #f1f5f9;
}
.detail-hd h3 {
  margin: 0; font-size: 15px; word-break: break-all; color: #101828; letter-spacing: -.02em;
}
.path-full { margin: 4px 0 0; color: #667085; font-size: 12px; word-break: break-all; }
.sev {
  flex: 0 0 auto; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 6px;
  background: #fee4e2; color: #b42318;
}
.af-detail dl { margin: 0; display: flex; flex-direction: column; gap: 9px; }
.af-detail dl > div { display: grid; grid-template-columns: 72px minmax(0, 1fr); gap: 8px; font-size: 12.5px; }
.af-detail dl > div.wide { align-items: start; }
.af-detail dt { color: #98a2b3; font-weight: 650; }
.af-detail dd { margin: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #344054; }
.af-detail dd.wrap { white-space: normal; word-break: break-all; overflow: visible; }
.af-detail .path-row { display: flex; gap: 8px; align-items: flex-start; }
.af-detail .path-row span { flex: 1; min-width: 0; }
.af-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; padding-top: 12px; border-top: 1px solid #eef2f6; }
.af-sample-msg { margin: 8px 0 0; font-size: 12px; color: #027a48; }
.af-sample-err { margin: 8px 0 0; font-size: 12px; color: #b42318; }
.af-query-info { display: flex; align-items: center; flex-wrap: wrap; gap: 8px 18px; padding: 10px 14px; border: 1px solid #d8e5ef; border-radius: 8px; background: #f4f9fc; color: #355167; font-size: 12px; }
.af-query-info b { color: #17344b; font-variant-numeric: tabular-nums; }
.af-hits { margin-top: 16px; display: flex; flex-direction: column; gap: 8px; }
.af-hits h4 { margin: 0; font-size: 12px; color: #98a2b3; font-weight: 650; }
.hit-chip {
  text-align: left; border: 1px solid #fecdca; background: #fef3f2; border-radius: 10px;
  padding: 9px 11px; display: flex; flex-direction: column; gap: 2px;
}
.hit-chip b { font-size: 13px; color: #912018; }
.hit-chip small { color: #667085; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hit-chip em { font-style: normal; font-size: 11px; color: #b42318; font-weight: 700; }
.hit-chip[data-s="medium"] { background: #fff8eb; border-color: #ecd39c; }
.hit-chip[data-s="medium"] b, .hit-chip[data-s="medium"] em { color: #875900; }
.hit-chip[data-s="low"], .hit-chip[data-s="info"] { background: #eef5fb; border-color: #c8ddeb; }
.hit-chip[data-s="low"] b, .hit-chip[data-s="low"] em,
.hit-chip[data-s="info"] b, .hit-chip[data-s="info"] em { color: #315b76; }

@media (max-width: 1100px) {
  .af { overflow: auto; height: auto; }
  .af-body { grid-template-columns: 1fr; overflow: visible; height: auto; }
  .af-list, .af-detail { height: auto; max-height: none; }
}
</style>
<style scoped src="./analysisPageTheme.css"></style>
