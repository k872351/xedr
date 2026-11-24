<template>
  <div v-if="agent" class="host-evidence-grid">
    <div v-for="row in hostEvidenceStatus(agent)" :key="row.key" class="host-evidence-card">
      <span>{{ row.label }}</span><strong>{{ row.value }}</strong><small>{{ row.detail }}</small>
    </div>
  </div>
</template>

<script setup>
import { hostEvidenceStatus } from './hostEvidenceStatus.js'
defineProps({ agent: Object })
</script>

<style scoped>
.host-evidence-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(165px,1fr)); gap:8px; margin:8px 0; }
.host-evidence-card { display:grid; gap:4px; border:1px solid var(--line); border-radius:8px; padding:9px 12px; min-width:0; overflow-wrap:anywhere; }
.host-evidence-card span, .host-evidence-card small { font-size:12px; color:var(--muted); }
.host-evidence-card strong { font-size:13px; }
</style>
