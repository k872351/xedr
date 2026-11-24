<template>
  <em class="status-tag" :class="toneClass" :data-status="status"><slot>{{ label }}</slot></em>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  /** online | offline | error | warn | success | disabled | pending */
  status: { type: String, default: 'offline' },
  label: { type: String, default: '' },
})

const toneClass = computed(() => {
  const s = String(props.status || '').toLowerCase()
  if (s === 'online' || s === 'on' || s === 'success' || s === 'enabled' || s === 'ok') return 'status-online'
  if (s === 'error' || s === 'failed' || s === 'danger' || s === 'critical') return 'status-error'
  if (s === 'warn' || s === 'warning' || s === 'abnormal' || s === 'outdated') return 'status-warn'
  if (s === 'pending' || s === 'review') return 'status-warn'
  return 'status-offline'
})
</script>

<style scoped>
.status-tag {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 650; font-style: normal;
}
.status-online { background: #e8f8ef; color: var(--online, #12b76a); }
.status-offline { background: #eef1f6; color: var(--muted); }
.status-error { background: var(--sev-critical-bg, #fef3f2); color: var(--sev-critical, #b42318); }
.status-warn { background: var(--sev-medium-bg, #fffaeb); color: #b54708; }
</style>
