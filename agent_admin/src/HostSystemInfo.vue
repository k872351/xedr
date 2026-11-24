<template>
  <div class="sysinfo-grid">
    <div v-for="(v, k) in (items?.[0] || {})" :key="k" class="si-item">
      <label>{{ columnLabel(k) }}</label>
      <div>{{ cell({ [k]: v }, k) }}</div>
    </div>
    <p v-if="!items?.length" class="empty">暂无系统信息</p>
  </div>
</template>

<script setup>
defineProps({ items: Array, columnLabel: { type: Function, required: true }, cell: { type: Function, required: true } })
</script>

<style scoped>
.sysinfo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; padding: 16px; }
.si-item { background: #f7f9fc; border-radius: 8px; padding: 12px; }
.si-item label { display: block; font-size: 11px; color: var(--muted); margin-bottom: 4px; }
.si-item div { font-size: 13px; font-weight: 550; word-break: break-all; }
.empty { padding: 4px 20px 40px; text-align: center; color: #98a2b3; font-size: 12.5px; }
</style>
