<template>
  <aside class="panel snap-detail">
    <template v-if="currentModule === 'sysinfo' && systemInfo">
      <div class="sd-hd"><div><b>系统信息</b><small>完整字段</small></div></div>
      <dl class="sd-dl">
        <div v-for="(v, k) in systemInfo" :key="k">
          <dt>{{ columnLabel(k) }}</dt><dd>{{ v == null || v === '' ? '—' : String(v) }}</dd>
        </div>
      </dl>
    </template>
    <template v-else-if="row">
      <div class="sd-hd">
        <div><b>{{ rowTitle(row) }}</b><small>{{ moduleLabel(currentModule) }} · 共 {{ Object.keys(row).length }} 个字段</small></div>
        <button type="button" class="icon-x" aria-label="关闭详情" @click="emit('close')">×</button>
      </div>
      <div class="sd-groups">
        <div v-for="g in detailGroups(row)" :key="g.title" class="sd-group">
          <h4>{{ g.title }}</h4>
          <dl class="sd-dl compact-gap">
            <div v-for="(v, k) in g.fields" :key="k"><dt>{{ columnLabel(k) }}</dt><dd :title="String(v ?? '')">{{ formatDetail(v) }}</dd></div>
          </dl>
        </div>
      </div>
      <slot name="row-extra" />
    </template>
    <slot v-else name="summary" />
  </aside>
</template>

<script setup>
import { colLabel as columnLabel, modLabel as moduleLabel, formatDetail } from './consoleDisplay.js'
import { rowTitle, detailGroups } from './hostSnapshotDisplay.js'
defineProps({ currentModule: String, systemInfo: Object, row: Object })
const emit = defineEmits(['close'])
</script>

<style scoped>
.snap-detail { display: flex; flex-direction: column; min-height: 0; height: 100%; overflow: hidden; }
.sd-hd { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.sd-hd b { display: block; font-size: 14px; word-break: break-word; }
.sd-hd small { color: var(--muted); font-size: 11px; }
.icon-x { width: 28px; height: 28px; border: 0; background: #f3f5f9; border-radius: 8px; font-size: 18px; color: var(--muted); line-height: 1; flex-shrink: 0; }
.sd-dl { margin: 0; padding: 12px 16px; overflow: auto; flex: 1; display: flex; flex-direction: column; gap: 10px; }
.sd-dl > div { display: grid; grid-template-columns: 100px 1fr; gap: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--line-2); font-size: 12px; }
.sd-dl dt { color: var(--muted); margin: 0; }
.sd-dl dd { margin: 0; word-break: break-all; font-weight: 500; color: var(--ink); white-space: pre-wrap; }
.sd-groups { overflow: auto; flex: 1; }
.sd-group { padding: 4px 0 8px; border-bottom: 1px solid var(--line-2); }
.sd-group h4 { margin: 0; padding: 10px 16px 6px; font-size: 12px; color: var(--muted); font-weight: 700; }
.sd-dl.compact-gap { padding-top: 0; }
</style>
