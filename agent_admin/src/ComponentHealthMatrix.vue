<template>
  <section class="component-matrix" aria-label="组件状态">
    <div class="matrix-head">
      <h4>传感器健康状态</h4>
      <div class="summary" aria-label="传感器状态汇总">
        <span class="summary-chip good">正常 {{ counts.ok }}</span>
        <span class="summary-chip warning">启动中 {{ counts.starting }}</span>
        <span class="summary-chip unknown">未知 {{ counts.unknown }}</span>
        <span class="summary-chip error">异常 {{ counts.failed }}</span>
        <span class="summary-chip neutral">未授权 {{ counts.unauthorized }}</span>
        <span class="summary-chip neutral">未启用 {{ counts.disabled }}</span>
        <span class="summary-chip neutral">不支持 {{ counts.unsupported }}</span>
      </div>
    </div>
    <div v-if="!rows.length" class="matrix-empty">暂无组件健康状态上报</div>
    <div v-else class="matrix-scroll">
      <table>
        <thead><tr><th scope="col">Component</th><th scope="col">State</th><th scope="col">Last activity</th><th scope="col">Resource estimate</th><th scope="col">Details</th></tr></thead>
        <tbody>
          <tr v-for="row in rows" :key="row.k">
            <td>{{ row.k }}</td>
            <td><span class="state" :data-state="row.state">{{ row.label }}</span></td>
            <td class="observed-at">{{ formatObservedAt(row.observedAt) }}</td>
            <td class="resource">{{ formatResources(row.resourceUsage) }}</td>
            <td>{{ row.message || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ rows: { type: Array, default: () => [] } })
function formatObservedAt(value) {
  if (!value) return 'N/A'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'N/A' : date.toLocaleString('zh-CN', { hour12: false })
}
function formatResources(value) {
  if (!value || typeof value !== 'object' || !Number(value.calls_total)) return '暂无采样'
  const calls = Number(value.calls_total) || 0
  const activeMs = Number(value.active_ms_total) || 0
  const allocatedMb = Number(value.estimated_alloc_mb_total) || 0
  return `CPU \u672a\u5355\u72ec\u8ba1\u91cf \u00b7 ${calls} \u6b21 \u00b7 \u7d2f\u8ba1\u5904\u7406 ${activeMs.toFixed(0)} ms \u00b7 \u91c7\u6837\u5206\u914d\u4f30\u7b97 ${allocatedMb.toFixed(2)} MB`
}
const counts = computed(() => ({
  ok: props.rows.filter(row => row?.state === 'OK').length,
  starting: props.rows.filter(row => row?.state === 'STARTING').length,
  unknown: props.rows.filter(row => row?.state === 'UNKNOWN').length,
  failed: props.rows.filter(row => ['FAILED', 'DEGRADED'].includes(row?.state)).length,
  unauthorized: props.rows.filter(row => row?.state === 'UNAUTHORIZED').length,
  disabled: props.rows.filter(row => ['OFF', 'DISABLED'].includes(row?.state)).length,
  unsupported: props.rows.filter(row => row?.state === 'UNSUPPORTED').length,
}))
</script>

<style scoped>
.component-matrix { margin: 8px 0; min-width: 0; }
.matrix-head { display: grid; gap: 8px; margin-bottom: 10px; }
h4 { margin: 0; font-size: 13px; color: var(--ink); }
.summary { display: flex; flex-wrap: wrap; gap: 6px; }
.summary-chip { display: inline-flex; align-items: center; border: 1px solid transparent; border-radius: 999px; padding: 3px 8px; font-size: 11px; font-weight: 650; line-height: 1.3; font-variant-numeric: tabular-nums; }
.summary-chip.good { color: #047857; background: #ecfdf5; border-color: #a7f3d0; }
.summary-chip.warning { color: #1d4ed8; background: #eff6ff; border-color: #bfdbfe; }
.summary-chip.unknown { color: #8a5600; background: #fff8e8; border-color: #f5d79d; }
.summary-chip.error { color: #a32020; background: #fff0ef; border-color: #fecaca; }
.summary-chip.neutral { color: #536579; background: #f2f5f8; border-color: #dce4eb; }
.summary { font-size: 11px; font-weight: 500; color: var(--muted); line-height: 1.5; }
.matrix-scroll { max-height: 260px; overflow: auto; border: 1px solid var(--line); border-radius: 8px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; text-align: left; }
th, td { padding: 8px 10px; border-bottom: 1px solid var(--line-2); vertical-align: top; overflow-wrap: anywhere; }
th { background: #f8fafc; position: sticky; top: 0; }
.state { display: inline-block; padding: 2px 6px; border-radius: 5px; color: #475569; background: #eef2f7; white-space: nowrap; }
.state[data-state="OK"] { color: #047857; background: #ecfdf5; }
.state[data-state="DEGRADED"] { color: #875900; background: #fff5dd; }
.state[data-state="FAILED"] { color: #a32020; background: #fff0ef; }
.state[data-state="STARTING"] { color: #1e40af; background: #eff6ff; }
.state[data-state="UNAUTHORIZED"] { color: #7c3aed; background: #f5f3ff; }
.state[data-state="DISABLED"], .state[data-state="OFF"] { color: #475569; background: #eef2f7; border: 1px solid #d9e2eb; }
.state[data-state="UNSUPPORTED"], .state[data-state="OFF"], .state[data-state="UNKNOWN"] { color: #475569; background: #eef2f7; }
.state[data-state="UNSUPPORTED"] { color: #334155; background: #e8edf2; border: 1px solid #d6dee6; }
.state[data-state="UNKNOWN"] { color: #7c4a03; background: #fff8e8; }
tbody tr:hover { background: #edf6fc; }
tbody tr:nth-child(even) { background: #f8fafc; }
td:last-child { line-height: 1.5; }
.observed-at { white-space: nowrap; color: #526a80; font-variant-numeric: tabular-nums; }
.resource { color: #526a80; white-space: nowrap; font-variant-numeric: tabular-nums; }
.matrix-empty { color: var(--muted); padding: 8px 0; }
</style>
