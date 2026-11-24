<template>
  <div class="host-summary">
    <div v-for="item in items" :key="item.label" class="hs" :class="item.tone">
      <span>{{ item.label }}</span><b>{{ item.value }}</b>
    </div>
  </div>
</template>

<script setup>
defineProps({ items: { type: Array, required: true } })
</script>

<style scoped>
.host-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px; }
.hs {
  background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 12px 14px; display: flex; justify-content: space-between; align-items: center;
  box-shadow: var(--shadow); border-left: 3px solid #9aa8b8;
}
.hs span { color: var(--muted); font-size: var(--fs-meta, 12px); font-weight: 600; }
.hs b { font-size: 20px; font-weight: 700; font-variant-numeric: tabular-nums; color: var(--ink); }
.hs.on { border-left-color: var(--online); }
.hs.on b { color: var(--online); }
.hs.off { border-left-color: #94a3b8; }
.hs.off b { color: var(--muted); }
.hs.danger { border-left-color: var(--danger); }
.hs.danger b { color: var(--danger); }
@media (max-width: 1100px) { .host-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
