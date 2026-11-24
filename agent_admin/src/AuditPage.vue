<template>
  <section class="page page-stack">
    <ConsolePageHeader title="审计日志" description="登录、策略、处置指令与账号变更的操作留痕；可按类别筛选">
      <slot name="refresh" />
    </ConsolePageHeader>
    <div class="audit-toolbar panel pad">
      <div class="audit-cats" role="tablist" aria-label="审计类别">
        <button
          v-for="c in categories"
          :key="c.id"
          type="button"
          class="audit-cat"
          :class="{ on: cat === c.id }"
          @click="cat = c.id"
        >{{ c.label }} <em v-if="c.id !== 'all'">{{ countOf(c.id) }}</em></button>
      </div>
      <input v-model="q" class="field audit-q" placeholder="搜索操作者 / 动作 / 终端 / 详情…" />
    </div>
    <div class="panel pad fill-rest audit-panel">
      <div v-if="filtered.length" class="audit-table-wrap fill-rest-body">
        <table class="audit-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>类别</th>
              <th>操作者</th>
              <th>动作</th>
              <th>终端</th>
              <th>详情</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in filtered" :key="a.id || (a.created_at + a.action + a.agent_id)">
              <td class="muted nowrap">{{ fmtTime(a.created_at) }}</td>
              <td><span class="audit-badge" :data-c="classify(a.action)">{{ catLabel(classify(a.action)) }}</span></td>
              <td>{{ a.actor || '—' }}</td>
              <td class="mono">{{ a.action }}</td>
              <td class="mono">{{ a.agent_id ? short(a.agent_id) : '—' }}</td>
              <td class="audit-detail" :title="a.detail || ''">
                <button
                  v-if="(a.detail || '').length > 120"
                  type="button"
                  class="btn-text"
                  @click="toggle(a)"
                >{{ expanded[rowKey(a)] ? '收起' : '展开' }}</button>
                <pre v-if="expanded[rowKey(a)]" class="audit-pre">{{ a.detail }}</pre>
                <span v-else>{{ shortDetail(a.detail) }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="empty">{{ items.length ? '当前筛选下无审计记录' : '暂无审计记录' }}</p>
    </div>
  </section>
</template>

<script setup>
import { computed, reactive, ref } from 'vue'
import ConsolePageHeader from './ConsolePageHeader.vue'

const props = defineProps({
  items: { type: Array, required: true },
  fmtTime: { type: Function, required: true },
  short: { type: Function, required: true },
})

const cat = ref('all')
const q = ref('')
const expanded = reactive({})

const categories = [
  { id: 'all', label: '全部' },
  { id: 'auth', label: '登录账号' },
  { id: 'policy', label: '策略' },
  { id: 'response', label: '处置指令' },
  { id: 'deploy', label: '部署升级' },
  { id: 'other', label: '其他' },
]

function classify(action) {
  const a = String(action || '').toLowerCase()
  if (/login|logout|auth|password|user|account|session/.test(a)) return 'auth'
  if (/policy|whitelist|allow|wl|sync|fim|yara/.test(a)) return 'policy'
  if (/ack:|response|kill_|quarantine|isolate|pull_file|scan_memory|uninstall|command|approval/.test(a)) return 'response'
  if (/upgrade|deploy|release|package|install/.test(a)) return 'deploy'
  return 'other'
}

function catLabel(id) {
  return ({ auth: '登录账号', policy: '策略', response: '处置', deploy: '部署', other: '其他' })[id] || id
}

function countOf(id) {
  return props.items.filter(x => classify(x.action) === id).length
}

function rowKey(a) {
  return String(a.id || `${a.created_at}|${a.action}|${a.agent_id}|${(a.detail || '').slice(0, 24)}`)
}

function shortDetail(d) {
  const s = String(d || '')
  if (!s) return '—'
  return s.length > 100 ? `${s.slice(0, 100)}…` : s
}

function toggle(a) {
  const k = rowKey(a)
  expanded[k] = !expanded[k]
}

const filtered = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return props.items.filter((a) => {
    if (cat.value !== 'all' && classify(a.action) !== cat.value) return false
    if (!needle) return true
    const blob = `${a.actor || ''} ${a.action || ''} ${a.agent_id || ''} ${a.detail || ''}`.toLowerCase()
    return blob.includes(needle)
  })
})
</script>

<style scoped>
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }
.panel.pad { padding: 14px 16px; }
.audit-toolbar {
  display: flex; flex-wrap: wrap; align-items: center; gap: 12px;
  margin-bottom: 12px; flex: 0 0 auto;
}
.audit-cats { display: flex; flex-wrap: wrap; gap: 6px; flex: 1; min-width: 0; }
.audit-cat {
  border: 1px solid var(--line); background: var(--bg-elevated); color: var(--ink-2);
  border-radius: 8px; padding: 6px 10px; font-size: 12.5px; font-weight: 650; cursor: pointer;
}
.audit-cat em { font-style: normal; color: var(--muted); margin-left: 4px; font-variant-numeric: tabular-nums; }
.audit-cat.on { background: var(--accent-soft); color: var(--accent-2); border-color: #f0b6a0; }
.audit-q { max-width: 280px; flex: 1 1 180px; }
.audit-panel { display: flex; flex-direction: column; min-height: 0; }
.audit-table-wrap { overflow: auto; min-height: 0; }
.audit-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.audit-table th, .audit-table td {
  text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line);
  vertical-align: top;
}
.audit-table th {
  position: sticky; top: 0; z-index: 1;
  background: linear-gradient(180deg, #f5f6f8, #eef0f3); color: #575f6c;
  font-size: 12px; font-weight: 650;
}
.audit-badge {
  display: inline-flex; padding: 2px 8px; border-radius: 999px;
  font-size: 11.5px; font-weight: 700; background: #eef1f6; color: #536b80;
}
.audit-badge[data-c="auth"] { background: #eef6ff; color: #1d4ed8; }
.audit-badge[data-c="policy"] { background: #f3eefc; color: #6d28d9; }
.audit-badge[data-c="response"] { background: #fff1f0; color: #b42318; }
.audit-badge[data-c="deploy"] { background: #ecfdf3; color: #067647; }
.audit-detail { max-width: 420px; color: var(--ink-2); word-break: break-word; }
.audit-pre {
  margin: 6px 0 0; padding: 8px 10px; border-radius: 8px;
  background: #f7f9fc; border: 1px solid var(--line);
  font-size: 12px; white-space: pre-wrap; word-break: break-word; max-height: 200px; overflow: auto;
}
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.muted { color: var(--muted); }
.nowrap { white-space: nowrap; }
.empty { padding: 28px; text-align: center; color: #98a2b3; }
</style>
