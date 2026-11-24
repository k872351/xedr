<template>
  <section class="budget" aria-label="资源参考预算">
    <header><strong>Agent 资源参考预算</strong><small>当前采样 · 仅用于健康展示</small></header>
    <div class="budget-grid">
      <article v-for="row in rows" :key="row.key">
        <span>{{ row.label }}</span>
        <strong>{{ row.value == null ? '—' : row.value.toFixed(1) + row.unit }}</strong>
        <span class="state" :data-state="row.state">{{ labels[row.state] }}</span>
        <small>参考上限 {{ row.limit }}{{ row.unit }}</small>
      </article>
    </div>
    <small>当前数据仅覆盖 Agent 进程整体，组件级指标暂无独立采样。</small>
    <section v-if="components.length" class="component-work" aria-label="Sensor work estimates">
      <strong>Sensor resource attribution (estimated)</strong>
      <div class="work-head"><span>Sensor</span><span>Active time</span><span>Estimated allocations</span><span>Calls</span></div>
      <div v-for="row in components" :key="row.id" class="work-row">
        <b>{{ row.id }}</b>
        <span>{{ row.activeMs.toLocaleString('zh-CN', { maximumFractionDigits: 1 }) }} ms</span>
        <span>{{ row.allocMb.toLocaleString('zh-CN', { maximumFractionDigits: 2 }) }} MB</span>
        <span>{{ row.calls.toLocaleString('zh-CN') }}</span>
      </div>
      <small>CPU is not independently attributed yet. Active time approximates synchronous processing work. Allocation is extrapolated from 1/{{ sampleRate }} samples and may include concurrent Agent allocations; it is not retained sensor memory.</small>
    </section>
    <div class="diagnostic-timing">
      <strong>自身诊断模块耗时</strong>
      <div v-for="row in timings" :key="row.key">
        <span>{{ row.label }}</span>
        <b>{{ row.elapsed == null ? '—' : row.elapsed.toLocaleString('zh-CN') + ' μs' }}</b>
      </div>
      <small>耗时包含等待时间，不等同于组件 CPU 或内存占用。</small>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import { resourceBudgetRows, diagnosticTimingRows } from './resourceBudget.js'
const props = defineProps({ health: { type: Object, default: () => ({}) } })
const rows = computed(() => resourceBudgetRows(props.health))
const timings = computed(() => diagnosticTimingRows(props.health))
const components = computed(() => {
  const raw = props.health?.sensors?.components
  if (!Array.isArray(raw)) return []
  return raw.map((item) => {
    const r = item?.resource_usage || {}
    return {
      id: String(item?.name || item?.k || ''),
      activeMs: Number(r.active_ms_total || 0),
      allocMb: Number(r.estimated_alloc_mb_total || 0),
      calls: Number(r.calls_total || 0),
      sampleRate: Number(r.allocation_sample_rate || 64),
    }
  }).filter((item) => item.id && item.calls > 0)
})
const sampleRate = computed(() => Math.max(1, ...components.value.map((item) => item.sampleRate)))
const labels = { unknown: '暂无有效数据', above: '超过参考值', within: '参考范围内' }
</script>

<style scoped>
.budget { margin: 8px 0; min-width: 0; }
header { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin-bottom: 8px; }
small { color: var(--muted); font-size: 11px; }
.budget-grid { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 8px; margin-bottom: 6px; }
article { display: grid; gap: 5px; background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 10px; min-width: 0; }
article > span:first-child { font-size: 12px; color: var(--muted); }
article > strong { font-size: 19px; font-variant-numeric: tabular-nums; }
.state { font-size: 11px; color: #64748b; }
.state[data-state="above"] { color: #ad5908; }
.state[data-state="within"] { color: #047857; }
.component-work { margin-top: 10px; display: grid; gap: 6px; padding: 10px; border: 1px solid var(--line); border-radius: 8px; background: #fff; min-width: 0; }
.work-head, .work-row { display: grid; grid-template-columns: minmax(90px, 1fr) repeat(3, minmax(78px, auto)); gap: 8px; align-items: center; font-size: 11px; }
.work-head { color: var(--muted); border-bottom: 1px solid var(--line-2); padding-bottom: 5px; }
.work-row { color: var(--ink); font-variant-numeric: tabular-nums; padding: 3px 0; }
.work-row b { overflow: hidden; text-overflow: ellipsis; }
.component-work > small { line-height: 1.45; }
.diagnostic-timing { margin-top: 10px; display: grid; gap: 6px; padding: 10px; border: 1px solid var(--line); border-radius: 8px; background: #fff; }
.diagnostic-timing > div { display: flex; justify-content: space-between; gap: 8px; font-size: 12px; }
.diagnostic-timing > div b { font-variant-numeric: tabular-nums; }
.budget-grid article { border-top: 3px solid #8aa9bf; }
.budget-grid article:has(.state[data-state="above"]) { border-top-color: #cc8a2f; background: #fffcf5; }
.budget-grid article:has(.state[data-state="within"]) { border-top-color: #31916e; }
@media (max-width: 520px) { .budget-grid { grid-template-columns: 1fr; } header { flex-wrap: wrap; } .work-head, .work-row { grid-template-columns: minmax(68px, 1fr) repeat(3, minmax(58px, auto)); gap: 5px; font-size: 10px; } }
</style>
