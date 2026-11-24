<template>
  <span class="os-fam" :title="label">
    <svg v-if="kind === 'windows'" class="os-ico win" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="currentColor" d="M3 4.5h8.2v7.2H3zm9.6 0H21v7.2h-8.4zM3 12.9h8.2V21H3zm9.6 0H21V21h-8.4z" />
    </svg>
    <svg v-else-if="kind === 'linux'" class="os-ico linux" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="currentColor" d="M12 2.4c-1.2 0-2.2 1.3-2.2 3 0 .7.2 1.3.5 1.8-.9.5-1.9 1.7-1.9 3.4 0 1.2.5 2.1 1.2 2.7-.1.4-.2.9-.2 1.3 0 1.6.8 2.7 1.8 3.3-.3.5-.5 1.1-.5 1.7 0 1.6 1 2.8 2.3 2.8s2.3-1.2 2.3-2.8c0-.6-.2-1.2-.5-1.7 1-.6 1.8-1.7 1.8-3.3 0-.4-.1-.9-.2-1.3.7-.6 1.2-1.5 1.2-2.7 0-1.7-1-2.9-1.9-3.4.3-.5.5-1.1.5-1.8 0-1.7-1-3-2.2-3zm-1.5 4.1c.3 0 .6.4.6 1s-.3 1-.6 1-.6-.4-.6-1 .3-1 .6-1zm3 0c.3 0 .6.4.6 1s-.3 1-.6 1-.6-.4-.6-1 .3-1 .6-1z" />
    </svg>
    <svg v-else class="os-ico unknown" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" stroke-width="1.8" />
      <path fill="none" stroke="currentColor" stroke-width="1.8" d="M9.5 10a2.5 2.5 0 1 1 3.8 2.1c-.7.4-1.3 1-1.3 2v.4M12 17.2h.01" />
    </svg>
    <span class="os-lab">{{ label }}</span>
  </span>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ family: { type: String, default: '' } })
const kind = computed(() => {
  const s = String(props.family || '').toLowerCase()
  if (/win/.test(s)) return 'windows'
  if (/linux|ubuntu|centos|debian|rhel|kylin|uos/.test(s)) return 'linux'
  return s ? 'other' : 'unknown'
})
const label = computed(() => {
  if (kind.value === 'windows') return 'Windows'
  if (kind.value === 'linux') return 'Linux'
  return props.family || '未知'
})
</script>

<style scoped>
.os-fam {
  display: inline-flex; align-items: center; gap: 8px;
  color: var(--ink-2); font-weight: 650; font-size: 13px;
}
.os-ico { width: 16px; height: 16px; flex: 0 0 16px; }
.os-ico.win { color: #276eb4; }
.os-ico.linux { color: #b8860b; }
.os-ico.unknown, .os-ico.other { color: #748698; }
.os-lab { line-height: 1; }
</style>
