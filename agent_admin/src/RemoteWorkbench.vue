<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { createAgentCommand, listAgentCommands } from './api'

const props = defineProps({
  agentId: { type: String, required: true },
  online: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  hostname: { type: String, default: '' },
})

const tab = ref('files')
const busy = ref(false)
const err = ref('')
const ok = ref('')
const tabs = [
  { id: 'files', label: '文件' },
  { id: 'registry', label: '注册表' },
  { id: 'query', label: 'Live Query' },
  { id: 'shell', label: 'Shell' },
]

const volumes = ref([])
const fsPath = ref('C:\\')
const fsEntries = ref([])
const fsPreview = ref('')
const fsHint = ref('')

const regHive = ref('HKLM')
const regPath = ref('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')
const regResult = ref(null)

const lqTable = ref('processes')
const lqRows = ref([])
const lqTables = [
  { id: 'processes', label: '进程' },
  { id: 'services', label: '服务' },
  { id: 'startup_items', label: '启动项' },
  { id: 'scheduled_tasks', label: '计划任务' },
  { id: 'users', label: '用户' },
  { id: 'listening_ports', label: '监听端口' },
]

const shellId = ref('')
const shellInput = ref('')
const shellOut = ref('')
const shellTimer = ref(null)
const runCmdLine = ref('tasklist')
const runCmdOut = ref('')

function flash(msg, isErr = false) {
  ok.value = isErr ? '' : msg
  err.value = isErr ? msg : ''
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

async function waitCommand(cmdId, { timeoutMs = 45000 } = {}) {
  const t0 = Date.now()
  while (Date.now() - t0 < timeoutMs) {
    const r = await listAgentCommands(props.agentId)
    const hit = (r.items || r.commands || []).find((c) => c.id === cmdId)
    if (hit && (hit.status === 'done' || hit.status === 'failed' || hit.status === 'expired')) {
      let result = hit.result
      if (typeof hit.result_json === 'string' && hit.result_json) {
        try { result = JSON.parse(hit.result_json) } catch { result = { raw: hit.result_json } }
      }
      if (typeof result === 'string') {
        try { result = JSON.parse(result) } catch { /* keep */ }
      }
      return { ...hit, result: result || {} }
    }
    await sleep(900)
  }
  throw new Error('等待终端回执超时（请确认 Agent 在线且策略已开启远程运维）')
}

async function runAction(action, params = {}) {
  if (!props.isAdmin) throw new Error('需要管理员权限')
  if (!props.online) throw new Error('终端离线')
  const created = await createAgentCommand(props.agentId, action, params)
  if (!created?.ok && created?.error) throw new Error(created.error)
  const id = created.id || created.command_id
  if (!id) throw new Error('未返回指令 ID')
  return waitCommand(id)
}

async function loadVolumes() {
  busy.value = true
  try {
    const r = await runAction('fs_volumes', {})
    if (r.status !== 'done') throw new Error(r.result?.error || r.status)
    volumes.value = r.result?.entries || r.result?.volumes || r.result?.items || []
    if (!fsPath.value && volumes.value[0]) fsPath.value = volumes.value[0].path || volumes.value[0].name || 'C:\\'
    flash(`盘符 ${volumes.value.length} 个`)
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function browseFs(path = fsPath.value) {
  busy.value = true
  fsPreview.value = ''
  try {
    const p = String(path || 'C:\\')
    fsPath.value = p
    const r = await runAction('fs_list', { path: p })
    if (r.status !== 'done') throw new Error(r.result?.error || r.status)
    const entries = r.result?.entries || r.result?.items || []
    fsEntries.value = entries
    fsHint.value = r.result?.truncated ? '目录项过多，已截断' : ''
    flash(`列出 ${entries.length} 项`)
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

function fsUp() {
  const p = fsPath.value.replace(/[\\/]+$/, '')
  const i = Math.max(p.lastIndexOf('\\'), p.lastIndexOf('/'))
  if (i <= 2) {
    browseFs((p.slice(0, 3) || 'C:\\'))
    return
  }
  browseFs(p.slice(0, i + 1))
}

async function openEntry(ent) {
  const name = ent.name || ent.Name || ''
  const isDir = !!(ent.dir || ent.is_dir || ent.isdir || ent.type === 'dir')
  const base = fsPath.value.replace(/[\\/]+$/, '')
  const next = `${base}\\${name}`
  if (isDir) return browseFs(next + '\\')
  busy.value = true
  try {
    const r = await runAction('fs_read', { path: next, max_bytes: 64 * 1024 })
    if (r.status !== 'done') throw new Error(r.result?.error || r.status)
    fsPreview.value = r.result?.text || r.result?.content || r.result?.hex || JSON.stringify(r.result, null, 2)
    flash(`已读取 ${name}`)
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function readReg() {
  busy.value = true
  try {
    // Agent 侧参数名为 key（兼容旧 path）
    const r = await runAction('reg_read', { hive: regHive.value, key: regPath.value, path: regPath.value })
    if (r.status !== 'done') throw new Error(r.result?.error || r.status)
    regResult.value = r.result
    flash('注册表已读取')
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function runLiveQuery() {
  busy.value = true
  try {
    const r = await runAction('live_query', { table: lqTable.value, limit: 80 })
    if (r.status !== 'done') throw new Error(r.result?.error || r.status)
    lqRows.value = r.result?.rows || r.result?.items || []
    if (!lqRows.value.length && r.result && typeof r.result === 'object') {
      // 回执被截断时可能没有 rows
      const raw = r.result_json || r.result?.raw || ''
      if (typeof raw === 'string' && raw && !raw.trim().endsWith('}')) {
        throw new Error('查询结果过大被截断，请换小表或稍后重试')
      }
    }
    flash(`查询 ${lqRows.value.length} 行`)
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function runCmd() {
  busy.value = true
  try {
    const r = await runAction('run_cmd', { command: runCmdLine.value })
    if (r.status !== 'done') throw new Error(r.result?.error || r.status)
    runCmdOut.value = r.result?.output || r.result?.stdout || JSON.stringify(r.result, null, 2)
    flash('命令已执行')
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function shellOpen() {
  busy.value = true
  try {
    stopShellPoll()
    const r = await runAction('shell_open', {})
    if (r.status !== 'done') throw new Error(r.result?.error || r.status)
    // Agent 返回 session_id；兼容旧 shell_id
    shellId.value = r.result?.session_id || r.result?.shell_id || r.result?.id || ''
    shellOut.value = ''
    if (!shellId.value) throw new Error('未返回 session_id（请先在策略中开启「允许交互 Shell」）')
    flash('Shell 已打开')
    startShellPoll()
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function shellSend() {
  if (!shellId.value || !shellInput.value.trim()) return
  busy.value = true
  try {
    const line = shellInput.value.endsWith('\n') ? shellInput.value : `${shellInput.value}\n`
    await runAction('shell_write', { session_id: shellId.value, shell_id: shellId.value, input: line, data: line })
    shellInput.value = ''
    await shellPollOnce()
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

async function shellPollOnce() {
  if (!shellId.value) return
  const r = await runAction('shell_poll', { session_id: shellId.value, shell_id: shellId.value })
  if (r.status === 'done') {
    const chunk = r.result?.output || r.result?.data || ''
    if (chunk) shellOut.value += chunk
  }
}

function startShellPoll() {
  stopShellPoll()
  shellTimer.value = setInterval(() => {
    shellPollOnce().catch(() => {})
  }, 2000)
}

function stopShellPoll() {
  if (shellTimer.value) {
    clearInterval(shellTimer.value)
    shellTimer.value = null
  }
}

async function shellClose() {
  stopShellPoll()
  if (!shellId.value) return
  busy.value = true
  try {
    await runAction('shell_close', { session_id: shellId.value, shell_id: shellId.value })
    shellId.value = ''
    flash('Shell 已关闭')
  } catch (e) {
    flash(e.message || String(e), true)
  } finally {
    busy.value = false
  }
}

const fsDirs = computed(() => fsEntries.value.filter((e) => e.dir || e.is_dir || e.isdir || e.type === 'dir'))
const fsFiles = computed(() => fsEntries.value.filter((e) => !(e.dir || e.is_dir || e.isdir || e.type === 'dir')))

watch(() => props.agentId, () => {
  volumes.value = []
  fsEntries.value = []
  fsPreview.value = ''
  regResult.value = null
  lqRows.value = []
  shellClose()
})

onMounted(() => {
  if (props.online && props.isAdmin) loadVolumes().then(() => browseFs(fsPath.value)).catch(() => {})
})
onBeforeUnmount(() => stopShellPoll())
</script>

<template>
  <div class="rw">
    <header class="rw-hd">
      <div>
        <h2>远程运维</h2>
        <p class="hint">经 Agent 指令通道（非 RDP）。默认只读；Shell / run_cmd 需在策略中显式开启。当前主机 {{ hostname || agentId }}</p>
      </div>
      <span class="pill" :class="{ on: online }">{{ online ? '在线' : '离线' }}</span>
    </header>
    <p v-if="err" class="banner err">{{ err }}</p>
    <p v-else-if="ok" class="banner ok">{{ ok }}</p>
    <nav class="rw-tabs">
      <button v-for="t in tabs" :key="t.id" type="button" :class="{ on: tab === t.id }" @click="tab = t.id">{{ t.label }}</button>
    </nav>

    <div v-show="tab === 'files'" class="rw-panel">
      <div class="toolbar">
        <input v-model="fsPath" class="field mono grow" @keyup.enter="browseFs()" />
        <button type="button" class="btn sm" :disabled="busy" @click="fsUp">上级</button>
        <button type="button" class="btn sm" :disabled="busy || !online" @click="browseFs()">刷新</button>
        <button type="button" class="btn sm" :disabled="busy || !online" @click="loadVolumes">盘符</button>
      </div>
      <p v-if="fsHint" class="hint sm">{{ fsHint }}</p>
      <div class="rw-split">
        <aside class="vol">
          <button
            v-for="v in volumes"
            :key="v.path || v.name"
            type="button"
            class="vol-btn"
            @click="browseFs((v.path || v.name || 'C:\\').replace(/\\?$/, '\\'))"
          >{{ v.name || v.path }}</button>
          <p v-if="!volumes.length" class="empty sm">点「盘符」加载</p>
        </aside>
        <div class="list">
          <button v-for="e in fsDirs" :key="'d'+e.name" type="button" class="row dir" :disabled="busy" @click="openEntry(e)">
            📁 {{ e.name }}
          </button>
          <button v-for="e in fsFiles" :key="'f'+e.name" type="button" class="row" :disabled="busy" @click="openEntry(e)">
            📄 {{ e.name }} <span class="muted">{{ e.size || '' }}</span>
          </button>
          <p v-if="!fsEntries.length" class="empty sm">空目录或未加载</p>
        </div>
        <pre v-if="fsPreview" class="preview mono">{{ fsPreview }}</pre>
      </div>
    </div>

    <div v-show="tab === 'registry'" class="rw-panel">
      <div class="toolbar">
        <select v-model="regHive" class="field">
          <option>HKLM</option>
          <option>HKCU</option>
          <option>HKU</option>
          <option>HKCR</option>
        </select>
        <input v-model="regPath" class="field mono grow" />
        <button type="button" class="btn sm" :disabled="busy || !online" @click="readReg">读取</button>
      </div>
      <pre v-if="regResult" class="preview mono">{{ JSON.stringify(regResult, null, 2) }}</pre>
    </div>

    <div v-show="tab === 'query'" class="rw-panel">
      <div class="toolbar">
        <select v-model="lqTable" class="field">
          <option v-for="t in lqTables" :key="t.id" :value="t.id">{{ t.label }}</option>
        </select>
        <button type="button" class="btn sm" :disabled="busy || !online" @click="runLiveQuery">查询</button>
      </div>
      <div class="table-wrap" v-if="lqRows.length">
        <table class="tbl">
          <thead>
            <tr>
              <th v-for="k in Object.keys(lqRows[0] || {})" :key="k">{{ k }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(row, i) in lqRows.slice(0, 200)" :key="i">
              <td v-for="k in Object.keys(lqRows[0] || {})" :key="k" class="mono">{{ row[k] }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="empty sm">选择表后查询（依赖 Agent live_query）</p>
    </div>

    <div v-show="tab === 'shell'" class="rw-panel">
      <p class="hint sm">Shell / 白名单命令默认关闭，请在「策略」中打开 remote_ops.shell_enabled 或 run_cmd_enabled。</p>
      <div class="toolbar">
        <input v-model="runCmdLine" class="field mono grow" placeholder="白名单命令，如 tasklist" />
        <button type="button" class="btn sm" :disabled="busy || !online" @click="runCmd">run_cmd</button>
      </div>
      <pre v-if="runCmdOut" class="preview mono">{{ runCmdOut }}</pre>
      <div class="toolbar">
        <button type="button" class="btn sm" :disabled="busy || !online || !!shellId" @click="shellOpen">打开 Shell</button>
        <button type="button" class="btn sm" :disabled="busy || !shellId" @click="shellClose">关闭</button>
      </div>
      <pre class="preview mono shell">{{ shellOut || '（无输出）' }}</pre>
      <div class="toolbar">
        <input v-model="shellInput" class="field mono grow" :disabled="!shellId" @keyup.enter="shellSend" placeholder="输入命令后回车" />
        <button type="button" class="btn sm" :disabled="busy || !shellId" @click="shellSend">发送</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.rw { display: flex; flex-direction: column; gap: 10px; min-height: 420px; }
.rw-hd { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
.rw-hd h2 { margin: 0 0 6px; font-size: 16px; }
.rw-hd .hint { margin: 0; color: #64748b; font-size: 13px; line-height: 1.5; max-width: 720px; }
.rw-tabs { display: flex; gap: 6px; flex-wrap: wrap; }
.rw-tabs button {
  border: 1px solid #e2e8f0; background: #fff; border-radius: 8px; padding: 6px 12px; cursor: pointer; font: inherit;
}
.rw-tabs button.on { background: #eff6ff; border-color: #93c5fd; color: #1d4ed8; font-weight: 650; }
.rw-panel { border: 1px solid #e8eef6; border-radius: 12px; padding: 12px; background: #fff; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
.field { padding: 7px 10px; border: 1px solid #dbe3ee; border-radius: 8px; font: inherit; }
.field.grow { flex: 1; min-width: 160px; }
.field.mono, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.rw-split { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 10px; }
.vol { display: flex; flex-direction: column; gap: 6px; }
.vol-btn { text-align: left; border: 1px solid #d8e3ed; background: #f7fafc; color: #36546d; border-radius: 8px; padding: 8px 10px; cursor: pointer; transition: background .15s, border-color .15s; }
.vol-btn:hover, .vol-btn.on { background: #e8f4fb; border-color: #89b4d1; color: #174c68; }
.list { border: 1px solid #eef2f7; border-radius: 10px; max-height: 360px; overflow: auto; }
.row {
  display: flex; width: 100%; gap: 8px; text-align: left; border: 0; border-bottom: 1px solid #f1f5f9;
  background: #fff; padding: 7px 10px; cursor: pointer; font: inherit;
}
.row:hover, .row:focus-visible { background: #edf6fc; }
.row:focus-visible { outline: 2px solid #2563eb; outline-offset: -2px; }
.preview {
  margin: 10px 0 0; padding: 10px; background: #0b1220; color: #e2e8f0; border-radius: 10px;
  max-height: 280px; overflow: auto; white-space: pre-wrap; word-break: break-word;
}
.preview.shell { min-height: 160px; }
.banner { margin: 0; padding: 8px 12px; border-radius: 8px; }
.banner.ok { background: #e8f7ee; color: #146c2e; }
.banner.err { background: #fdecea; color: #a1281d; }
.tbl { width: 100%; border-collapse: collapse; font-size: 12px; }
.tbl th, .tbl td { border-bottom: 1px solid #e2eaf1; padding: 8px 10px; text-align: left; vertical-align: top; }
.tbl th { position: sticky; top: 0; z-index: 1; background: linear-gradient(180deg, #faf7f5, #f3ede9); color: #5a4b42; }
.tbl tbody tr:nth-child(even) { background: #f8fbfd; }
.table-wrap { overflow: auto; max-height: 420px; }
.pill { display: inline-flex; padding: 2px 8px; border-radius: 999px; background: #f1f5f9; color: #64748b; font-size: 12px; }
.pill.on { background: #dcfce7; color: #166534; }
.empty { color: #94a3b8; }
.muted { color: #94a3b8; }
@media (max-width: 900px) { .rw-split { grid-template-columns: 1fr; } }

.rw, .rw-panel, .rw-split, .table-wrap { min-width: 0; }
.rw-panel { box-shadow: 0 2px 10px rgba(16, 43, 66, .045); }
.rw-tabs button:focus-visible, .vol-btn:focus-visible, .row:focus-visible { outline-color: #0b879f; }
.table-wrap { border: 1px solid #d8e3ed; border-radius: 9px; }
.tbl td { max-width: 360px; overflow-wrap: anywhere; }
.rw .preview { border: 1px solid #1b2a3c; }
@media (max-width: 640px) {
  .rw { min-height: 0; }
  .rw-panel { padding: 9px; }
  .rw .field.grow { min-width: min(100%, 180px); }
  .rw-split { grid-template-columns: minmax(0, 1fr); }
  .vol { flex-direction: row; flex-wrap: wrap; }
  .vol-btn { flex: 1 1 110px; }
}
</style>
