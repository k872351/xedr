<template>
  <header class="host-hdr">
    <div class="host-hdr-top">
      <div class="host-hdr-id">
        <slot name="back" />
        <div class="host-hdr-title">
          <h1>{{ agent.hostname || agent.agent_id }}</h1>
          <p class="host-hdr-meta">
            <i :class="['dot', agent.online ? 'on' : '']" />
            <em class="pill" :class="{ on: agent.online }">{{ agent.online ? '在线' : '离线' }}</em>
            <span>{{ agent.ip || '—' }}</span>
            <span>心跳 {{ fmtTime(agent.last_seen) }}</span>
            <span>Agent v{{ agent.version || '—' }}</span>
            <em v-if="agent.revoked" class="pill warn">凭据已吊销</em>
          </p>
        </div>
      </div>
      <div class="host-hdr-acts"><slot name="actions" /></div>
    </div>
    <HostEvidenceSummary :agent="agent" />
    <div class="host-hdr-stats">
      <span v-for="c in quickStats" :key="c.k" class="hchip" :class="{ warn: c.warn }" :title="c.title || ''">{{ c.k }} {{ c.v }}</span>
      <span v-for="c in warningChips.slice(0, 3)" :key="'cw-' + c.k" class="hchip warn" :title="c.message || ''">{{ c.k }} {{ c.state }}</span>
      <button v-if="sensorPanel" type="button" class="host-health-toggle" :aria-expanded="expanded"
        :class="{ warn: (sensorPanel.advise?.length || 0) > 0 || sensorPanel.level === 'poor' }" @click="emit('toggle-health')">
        采集健康 {{ sensorPanel.score ?? '—' }} <em>{{ expanded ? '▾' : '▸' }}</em>
      </button>
    </div>
    <HostHealthPanel v-if="expanded" :panel="sensorPanel" :health="agent.health" :component-chips="componentChips" :runtime-chips="runtimeChips" :drift="drift" :module-label="moduleLabel" />
  </header>
</template>

<script setup>
import HostEvidenceSummary from './HostEvidenceSummary.vue'
import HostHealthPanel from './HostHealthPanel.vue'
defineProps({
  agent: { type: Object, required: true }, fmtTime: { type: Function, required: true },
  quickStats: { type: Array, default: () => [] }, warningChips: { type: Array, default: () => [] },
  sensorPanel: Object, expanded: Boolean, componentChips: { type: Array, default: () => [] },
  runtimeChips: { type: Array, default: () => [] }, drift: String, moduleLabel: { type: Function, required: true },
})
const emit = defineEmits(['toggle-health'])
</script>

<style scoped>
.host-hdr {
  flex-shrink: 0; display: flex; flex-direction: column; gap: 10px;
  padding: 14px 16px 12px; border: 1px solid var(--line); border-left: 3px solid var(--accent);
  border-radius: var(--radius); background: var(--panel); box-shadow: var(--shadow); margin-bottom: 12px;
}
.host-hdr-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.host-hdr-id { display: flex; align-items: flex-start; gap: 10px; min-width: 0; }
.host-hdr-title { min-width: 0; }
.host-hdr-title h1 { margin: 0; font-size: var(--fs-title, 22px); font-weight: 700; letter-spacing: -.02em; line-height: 1.2; color: var(--ink); }
.host-hdr-meta { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; margin: 6px 0 0; font-size: var(--fs-meta, 12px); color: var(--muted); }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #c5ccd8; flex-shrink: 0; }
.dot.on { background: var(--online); box-shadow: 0 0 0 3px rgba(22,185,129,.18); }
.pill { display: inline-flex; align-items: center; border-radius: 999px; padding: 2px 9px; font-size: 11px; background: #eef1f6; color: var(--muted); font-weight: 600; font-style: normal; }
.pill.on { background: #e8f8ef; color: var(--online); }
.pill.warn { background: #fffaeb; color: #b54708; margin-left: 6px; }
.host-hdr-acts { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; justify-content: flex-end; }
.host-hdr-stats { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.hchip { font-size: 12px; padding: 2px 8px; border-radius: 999px; background: var(--bg-elevated); color: var(--ink-2); border: 1px solid var(--line); }
.hchip.warn { background: var(--sev-medium-bg); color: #b54708; border-color: #f5d0a0; }
.host-health-toggle {
  display: inline-flex; align-items: center; gap: 6px; border: 1px solid #f0b6a0;
  background: var(--accent-soft); color: var(--accent-2); border-radius: 999px;
  padding: 2px 10px; font-size: 12px; font-weight: 700; cursor: pointer;
}
.host-health-toggle.warn { border-color: #fdba74; background: #fff7ed; color: #c2410c; }
.host-health-toggle em { font-style: normal; font-weight: 650; opacity: .75; }
</style>
