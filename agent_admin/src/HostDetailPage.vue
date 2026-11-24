<template>
  <section class="page host-detail">
    <slot name="header" />
    <div class="snap-shell">
      <slot name="navigation" />
      <div v-if="currentModule !== 'sysinfo' && group === 'runtime'" class="snap-viewbar">
        <button type="button" class="tl-fchip" :class="{ on: view === 'all' }" @click="emit('view-change', 'all')">全部</button>
        <button type="button" class="tl-fchip" :class="{ on: view === 'risk' }" data-k="file" @click="emit('view-change', 'risk')">仅可疑 <em>{{ riskCount }}</em></button>
        <button type="button" class="tl-fchip" :class="{ on: view === 'hide_noise' }" @click="emit('view-change', 'hide_noise')">隐藏系统噪声</button>
        <span class="meta">运行态筛选 · 告警/时间线请到「检测」分区</span>
      </div>
      <div v-else-if="currentModule !== 'sysinfo' && group === 'inventory'" class="snap-viewbar">
        <span class="meta">资产清单：软件 / 补丁 / 监听端口 / 用户 · 与检测态分离</span>
      </div>
      <div class="snap-work has-detail">
        <slot name="list" />
        <slot name="detail" />
      </div>
    </div>
  </section>
</template>

<script setup>
defineProps({ currentModule: String, group: String, view: String, riskCount: Number })
const emit = defineEmits(['view-change'])
</script>

<style scoped>
.host-detail { overflow: hidden; gap: 0; }
.snap-shell { display: flex; flex-direction: column; gap: 10px; flex: 1 1 auto; min-height: 0; overflow: hidden; }
.snap-work { display: grid; grid-template-columns: minmax(0,1.4fr) minmax(300px,.9fr); gap: 12px; flex: 1 1 auto; min-height: 0; align-items: stretch; overflow: hidden; }
.snap-viewbar {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 0 0 12px;
  padding: 10px 12px; border: 1px solid var(--line); border-radius: var(--radius);
  background: var(--panel); box-shadow: var(--shadow);
}
.snap-viewbar .meta { font-size: 12px; color: var(--muted); }
.tl-fchip {
  border: 1px solid var(--line); background: var(--bg-elevated); border-radius: 999px;
  padding: 6px 12px; font-size: 12px; color: var(--ink-2); cursor: pointer;
  display: inline-flex; align-items: center; gap: 6px;
}
.tl-fchip em {
  font-style: normal; font-size: 11px; font-weight: 700; color: var(--muted);
  background: var(--line-2); border-radius: 999px; padding: 0 6px; min-width: 18px; text-align: center;
}
.tl-fchip.on { border-color: #f0b6a0; background: var(--accent-soft); color: var(--accent-2); }
.tl-fchip.on em { background: #fff; color: var(--accent-2); }
.tl-fchip[data-k="file"].on { border-color: #f9a8d4; background: #fdf2f8; color: #9d174d; }
@media (max-width: 1100px) { .snap-work { grid-template-columns: 1fr; } }
</style>
