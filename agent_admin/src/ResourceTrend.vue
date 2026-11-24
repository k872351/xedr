<template>
  <section class="resource-trend" aria-label="资源趋势">
    <header><strong>资源趋势</strong><small>本次展开期间 · {{ history.rows.length }} 个采样</small></header>
    <div class="trend-grid">
      <article v-for="metric in metrics" :key="metric.key">
        <span>{{ metric.label }}</span>
        <b>{{ metric.latest == null ? '—' : metric.latest.toFixed(1) + metric.unit }}</b>
        <svg v-if="metric.points.length && history.rows.length > 1" viewBox="0 0 240 60" preserveAspectRatio="none" role="img" :aria-label="metric.label + '趋势'">
          <template v-for="(points, i) in metric.points" :key="i">
            <circle v-if="!points.includes(' ')" :cx="points.split(',')[0]" :cy="points.split(',')[1]" r="2.5" :fill="metric.color"/>
            <polyline v-else :points="points" fill="none" :stroke="metric.color" stroke-width="2" vector-effect="non-scaling-stroke"/>
          </template>
        </svg>
        <small v-else>等待更多有效采样</small>
      </article>
    </div>
  </section>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { appendResourceSample, resourceSegments } from './resourceHistory.js'

const props = defineProps({ agent: { type: Object, default: null } })
const history = ref({ id: null, rows: [] })
watch(() => props.agent?.agent_id, () => {
  history.value = { id: null, rows: [] }
}, { immediate: true })
watch(() => [props.agent?.agent_id, props.agent?.health_at], () => {
  history.value = appendResourceSample(history.value, props.agent)
}, { immediate: true })
const metrics = computed(() => {
  const rows = history.value.rows
  const latest = rows.at(-1) || {}
  const rssScale = Math.max(1, ...rows.map(row => row.rss || 0))
  return [
    { key: 'cpu', label: 'CPU', unit: '%', latest: latest.cpu, color: '#087d9b', points: resourceSegments(rows, 'cpu', 100) },
    { key: 'rss', label: '内存', unit: ' MB', latest: latest.rss, color: '#2563eb', points: resourceSegments(rows, 'rss', rssScale) },
  ]
})
</script>

<style scoped>
.resource-trend { margin: 10px 0; min-width: 0; }
header { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin-bottom: 8px; }
small { color: var(--muted); font-size: 11px; }
.trend-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
article { display: grid; gap: 4px; padding: 10px; border: 1px solid var(--line); border-radius: 8px; background: #fff; }
article > span { color: var(--muted); font-size: 12px; }
article > b { font-size: 18px; font-variant-numeric: tabular-nums; }
article { border-top: 3px solid #76a4bc; min-width: 0; }
article:nth-child(2) { border-top-color: #7e9cdb; }
svg { width: 100%; height: 48px; overflow: visible; }
@media (max-width: 600px) { .trend-grid { grid-template-columns: 1fr; } }
</style>
