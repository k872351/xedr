<template>
  <div class="panel pad">
    <p>
      时间线保留 <b>{{ retention?.timeline_days ?? '—' }}</b> 天 ·
      已关闭事件保留 <b>{{ retention?.events_days ?? '—' }}</b> 天 ·
      MySQL 双写 <b>{{ retention?.mysql_dual_write == null ? '未知' : (retention.mysql_dual_write ? '开' : '关') }}</b>
    </p>
    <p class="hint">后台每小时自动清理一次；未关闭的威胁事件永不清理。</p>
    <slot />
  </div>
</template>

<script setup>
defineProps({ retention: Object })
</script>

<style scoped>
.hint { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
</style>
