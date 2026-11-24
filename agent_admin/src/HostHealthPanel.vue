<template>
  <div v-if="panel" class="host-health-card open">
    <div class="host-health-body">
      <div class="hsp-row">
        <span class="hsp-score" :data-lv="panel.level">{{ panel.score ?? '—' }}</span>
        <span class="hsp-chip">{{ panel.pipeline }}</span>
        <span v-if="panel.cmdFill != null" class="hsp-chip">cmd {{ panel.cmdFill }}%</span>
        <span v-if="panel.disks" class="hsp-chip" :class="{ warn: String(panel.disks).includes('100%') }">{{ panel.disks }}</span>
        <span v-if="panel.netLine" class="hsp-chip">{{ panel.netLine }}</span>
      </div>
      <div v-if="panel.statusChips?.length" class="hsp-row hsp-chips">
        <span
          v-for="(c, i) in panel.statusChips"
          :key="i"
          class="hsp-chip"
          :class="{ warn: c.warn, ok: c.ok }"
          :title="c.title || ''"
        >{{ c.label }}</span>
      </div>
      <div v-if="componentChips.length" class="hsp-row hsp-chips">
        <span class="hsp-label">组件</span>
        <span
          v-for="c in componentChips"
          :key="'cmp-' + c.k"
          class="hsp-chip"
          :class="{ warn: c.state === 'DEGRADED', off: c.state === 'OFF', ok: c.state === 'OK' }"
          :title="c.message || ''"
        >{{ c.k }} {{ c.state }}</span>
      </div>
      <HostCaptureQuality :health="health" :module-label="moduleLabel" />
      <div v-if="panel.channelChips?.length" class="hsp-row hsp-channels">
        <span class="hsp-label">Winlog</span>
        <span v-for="ch in panel.channelChips" :key="ch" class="hsp-chip soft">{{ ch }}</span>
      </div>
      <div v-if="runtimeChips.length" class="hsp-row hsp-chips">
        <span class="hsp-label">运行</span>
        <span v-for="c in runtimeChips" :key="'hc-' + c.k" class="hsp-chip" :class="{ warn: c.warn }" :title="c.title || ''">{{ c.k }} {{ c.v }}</span>
      </div>
      <div v-if="panel.byKindLine" class="hsp-row mono sm muted">outbox {{ panel.byKindLine }}</div>
      <p v-if="drift" class="hsp-drift">{{ drift }}</p>
      <ul v-if="panel.advise?.length" class="hsp-advise">
        <li v-for="(a, i) in panel.advise" :key="i">{{ a }}</li>
      </ul>
    </div>
  </div>
</template>

<script setup>
import HostCaptureQuality from './HostCaptureQuality.vue'
defineProps({
  panel: Object,
  health: Object,
  componentChips: { type: Array, default: () => [] },
  runtimeChips: { type: Array, default: () => [] },
  drift: String,
  moduleLabel: { type: Function, required: true },
})
</script>

<style scoped>
.host-health-card {
  border: 1px solid #dbeafe;
  border-radius: 10px;
  background: #f8fbff;
  overflow: hidden;
  max-height: 220px;
  overflow-y: auto;
}
.host-health-body { padding: 10px 12px; }
.hsp-chip {
  display: inline-flex; align-items: center;
  padding: 2px 8px; border-radius: 999px;
  background: #fff; border: 1px solid #e2e8f0;
  color: #334155; font-size: 11px; line-height: 1.4;
}
.hsp-chip.soft { background: #f8fafc; color: #64748b; }
.hsp-chip.ok { background: #ecfdf5; border-color: #a7f3d0; color: #047857; }
.hsp-chip.warn { background: #fff7ed; border-color: #fdba74; color: #c2410c; }
.hsp-chips, .hsp-channels { margin-top: 6px; }
.hsp-label { font-size: 11px; color: #64748b; font-weight: 600; margin-right: 2px; }
.hsp-drift { margin: 8px 0 0; font-size: 12px; color: #b45309; }
.hsp-row { display: flex; flex-wrap: wrap; gap: 10px 14px; align-items: center; font-size: 12px; }
.hsp-score { font-weight: 700; padding: 2px 8px; border-radius: 6px; background: #ecfdf5; color: #047857; }
.hsp-score[data-lv="fair"] { background: #fffbeb; color: #b45309; }
.hsp-score[data-lv="poor"] { background: #fef2f2; color: #b91c1c; }
.hsp-advise { margin: 8px 0 0; padding-left: 18px; color: #92400e; font-size: 12px; line-height: 1.45; }
.mono { font-variant-numeric: tabular-nums; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.muted { color: var(--muted); }
</style>
