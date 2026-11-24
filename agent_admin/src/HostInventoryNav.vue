<template>
  <nav class="host-group-nav">
    <button v-for="g in groups" :key="g.id" type="button" class="host-group-btn" :class="{ on: group === g.id }" @click="emit('group', g.id)">{{ g.label }}</button>
  </nav>
  <nav class="mod-tabs bar">
    <button v-for="m in modules" :key="m" type="button" class="mod-tab" :class="{ on: currentModule === m }" @click="emit('module', m)">{{ moduleLabel(m) }}</button>
  </nav>
  <div class="snap-flags">
    <span v-for="f in flags" :key="f.k" class="sflag" :data-t="f.tone">{{ f.label }}</span>
    <span class="sflag muted">共 {{ total }} 条 · 同步 {{ collectedAt }}</span>
    <span v-if="columnCount" class="sflag muted">展示 {{ columnCount }} 列</span>
  </div>
</template>

<script setup>
defineProps({ groups: { type: Array, required: true }, group: String, modules: { type: Array, required: true }, currentModule: String, moduleLabel: { type: Function, required: true }, flags: { type: Array, required: true }, total: Number, collectedAt: String, columnCount: Number })
const emit = defineEmits(['group', 'module'])
</script>

<style scoped>
.host-group-nav { display: flex; gap: 8px; padding: 10px 14px 0; flex-wrap: wrap; }
.host-group-btn { border: 1px solid var(--line); background: #fff; color: var(--ink-2); border-radius: 8px; padding: 7px 14px; font-size: 13px; font-weight: 650; cursor: pointer; }
.host-group-btn.on { background: #0f172a; color: #fff; border-color: #0f172a; }
.host-group-btn:hover:not(.on) { background: #f4f7fb; }
.mod-tabs.bar { display: flex; gap: 0; flex-wrap: wrap; background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 4px; box-shadow: var(--shadow); width: 100%; flex-shrink: 0; }
.mod-tab { border: 0; background: transparent; border-radius: 6px; padding: 8px 14px; font-size: 13px; font-weight: 550; color: var(--ink-2); }
.mod-tab.on { background: #c81626; color: #fff; }
.snap-flags { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; flex-shrink: 0; }
.sflag { display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 650; background: #f1f5f9; color: #475569; }
.sflag[data-t="bad"] { background: #fef2f2; color: #b91c1c; }
.sflag[data-t="warn"] { background: #fff7ed; color: #c2410c; }
.sflag[data-t="info"] { background: #eff6ff; color: #1d4ed8; }
.sflag.muted { background: transparent; color: var(--muted); font-weight: 500; padding-left: 2px; }
</style>
