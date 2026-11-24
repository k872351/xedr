<script setup>
const props = defineProps({
  query: { type: String, default: '' },
  hits: { type: Array, default: () => [] },
  busy: Boolean,
  done: Boolean,
  shortId: { type: Function, required: true },
  moduleLabel: { type: Function, required: true },
  formatTime: { type: Function, required: true },
})
const emit = defineEmits(['update:query', 'run', 'open-module', 'open-hit'])
function searchFor(value) {
  emit('update:query', value)
  emit('run')
}
</script>

<template>
      <section class="page hunt-page">
        <header class="page-hd">
          <div>
            <h1>威胁狩猎</h1>
            <p class="desc">跨主机搜索：时间线 / 快照 / 威胁事件（哈希、路径、命令行等）</p>
          </div>
        </header>
        <div class="panel pad">
          <div class="hunt-bar">
            <input :value="props.query" @input="emit('update:query', $event.target.value)" class="search grow" placeholder="输入 SHA256 / 路径 / 进程名 / 命令片段…" @keyup.enter="emit('run')" />
            <button type="button" class="btn primary" :disabled="props.busy" @click="emit('run')">{{ props.busy ? '搜索中…' : '搜索' }}</button>
          </div>
          <div class="hunt-quick">
            <button type="button" class="chip" @click="searchFor('powershell')">powershell</button>
            <button type="button" class="chip" @click="searchFor('\\\\temp\\\\')">\\temp\\</button>
            <button type="button" class="chip" @click="searchFor('NotSigned')">NotSigned</button>
            <button type="button" class="chip" :class="{ on: /sysmon/i.test(props.query) }" @click="searchFor('sysmon')">Sysmon</button>
            <button type="button" class="chip" @click="emit('open-module', 'process', 'temp')">快照·临时目录进程</button>
            <button type="button" class="chip" @click="emit('open-module', 'file', 'Public')">快照·Public 文件</button>
          </div>
        </div>
        <div class="panel record-panel">
          <div class="panel-hd"><h3>检索结果</h3><span class="record-count">{{ props.hits.length }} 条记录</span></div>
          <div v-if="props.hits.length" class="table-scroll record-table"><table>
            <thead><tr><th>来源</th><th>标题</th><th>主机</th><th>模块</th><th>时间</th><th>片段</th></tr></thead>
            <tbody>
              <tr v-for="(h, i) in props.hits" :key="i" class="row-click" @click="emit('open-hit', h)">
                <td><span class="tag">{{ h.source }}</span></td>
                <td class="strong">{{ h.title }}</td>
                <td>{{ h.hostname || props.shortId(h.agent_id) }}</td>
                <td>{{ props.moduleLabel(h.module) || h.module || '—' }}</td>
                <td>{{ props.formatTime(h.ts) }}</td>
                <td class="muted" :title="h.snippet">{{ (h.snippet || '').slice(0, 80) }}</td>
              </tr>
            </tbody>
          </table></div>
          <div v-else class="record-empty"><span class="record-empty-mark" aria-hidden="true">—</span><strong>{{ props.busy ? '正在检索' : props.done ? '未找到匹配记录' : '等待检索' }}</strong><p>{{ props.done ? '可以调整查询条件后重新搜索。' : '输入关键词开始搜索。' }}</p></div>
        </div>
      </section>
</template>

<style scoped>
.hunt-page { display: flex; flex-direction: column; gap: 12px; min-height: 0; }
.hunt-page .page-hd {
  display: flex; align-items: center; justify-content: space-between; gap: 14px;
  padding: 14px 18px; border: 1px solid var(--line); border-left: 3px solid var(--accent);
  border-radius: var(--radius); background: var(--panel); box-shadow: var(--shadow);
}
.hunt-page .page-hd h1 { margin: 0; color: var(--ink); font-size: var(--fs-title, 22px); font-weight: 700; }
.hunt-page .page-hd .desc { margin: 5px 0 0; color: var(--muted); line-height: 1.55; font-size: var(--fs-meta, 12px); }
.hunt-page .panel { min-width: 0; padding: 16px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--panel); box-shadow: var(--shadow); }
.hunt-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 12px; }
.hunt-bar .grow { flex: 1; min-width: min(100%, 220px); }
.hunt-quick { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 4px; }
.chip {
  border: 1px solid var(--line); border-radius: 999px; padding: 5px 12px;
  background: var(--panel); color: var(--ink-2); font-size: 12px; cursor: pointer;
}
.chip:hover, .chip.on { border-color: #f0b6a0; background: var(--accent-soft); color: var(--accent-2); }
.hunt-page table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 12px; }
.hunt-page th { position: sticky; top: 0; padding: var(--row-pad-y, 9px) 10px; background: var(--bg-elevated); color: var(--muted); text-align: left; font-weight: 650; }
.hunt-page td { padding: var(--row-pad-y, 9px) 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
.hunt-page tbody tr:hover td { background: var(--accent-soft); }
.hunt-page button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.record-empty { display: grid; place-items: center; gap: 6px; padding: 40px 16px; text-align: center; color: var(--muted); }
.record-empty-mark {
  width: 36px; height: 36px; border-radius: 10px; display: grid; place-items: center;
  background: var(--bg-elevated); border: 1px solid var(--line); margin-bottom: 2px;
}
.record-empty strong { color: var(--ink-2); font-size: 14px; }
.record-empty p { margin: 0; font-size: 12px; max-width: 40ch; }
@media (max-width: 760px) { .hunt-page { overflow: auto; } .hunt-page .panel { overflow: auto; padding: 12px; } .hunt-page .page-hd { padding: 12px; } }
</style>
