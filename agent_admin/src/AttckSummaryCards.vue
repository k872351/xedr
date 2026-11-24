<template>
  <div class="ak-kpis">
    <article class="kpi click" @click="emit('events')">
      <span>威胁事件</span><strong class="c-danger">{{ total }}</strong><em>不含已加白 / 无需处置</em>
    </article>
    <article class="kpi click" @click="emit('events')">
      <span>未处置</span><strong class="c-warn">{{ open }}</strong><em>待研判处置</em>
    </article>
    <article class="kpi"><span>高危 / 严重</span><strong class="c-danger">{{ high }}</strong><em>优先响应</em></article>
    <article class="kpi"><span>覆盖战术</span><strong class="c-ink">{{ covered }}<small class="kpi-den">/{{ tacticCount || 12 }}</small></strong><em>MITRE ATT&CK 战术</em></article>
    <article class="kpi"><span>命中技术</span><strong class="c-ink">{{ techniqueCount }}</strong><em>{{ unmapped ? `另有 ${unmapped} 条未映射` : '技术去重' }}</em></article>
  </div>
</template>

<script setup>
defineProps({ total: Number, open: Number, high: Number, covered: Number, tacticCount: Number, techniqueCount: Number, unmapped: Number })
const emit = defineEmits(['events'])
</script>

<style scoped>
.ak-kpis { display: grid; grid-template-columns: repeat(5,minmax(0,1fr)); gap: 12px; margin: 0; flex-shrink: 0; }
.kpi { background: #fff; border: 1px solid rgba(15,23,42,.06); border-radius: 12px; padding: 16px 18px 14px; box-shadow: 0 6px 18px rgba(15,23,42,.04); transition: box-shadow .15s, transform .15s,border-color .15s; }
.kpi span { display: block; color: #98a2b3; font-size: 13px; font-weight: 500; margin-bottom: 10px; }
.kpi strong { display: block; font-size: 38px; font-weight: 720; letter-spacing: -.04em; line-height: 1.05; color: var(--ink); }
.kpi em { display: block; margin-top: 10px; font-style: normal; color: #98a2b3; font-size: 12px; }
.kpi.click { cursor: pointer; }
.kpi.click:hover { border-color: rgba(37,99,235,.22); box-shadow: 0 12px 28px rgba(15,23,42,.07); transform: translateY(-1px); }
.kpi-den { font-size: 18px; font-weight: 600; color: #98a2b3; margin-left: 2px; letter-spacing: 0; }
.c-danger { color: #f04438; }
.c-warn { color: #c2410c; }
.c-ink { color: #101828; }
@media (max-width: 1100px) { .ak-kpis { grid-template-columns: repeat(3,minmax(0,1fr)); } }
</style>
