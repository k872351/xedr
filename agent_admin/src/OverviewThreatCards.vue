<template>
  <div class="ov-threat-rail">
    <button type="button" class="ov-rail-card click" data-tone="alert" @click="emit('navigate', 'events')">
      <div class="ov-rail-ico" aria-hidden="true"><span class="ico-mark">!</span></div>
      <div class="ov-rail-body">
        <span>告警主机</span>
        <strong>{{ overviewStats.threats?.alerted_hosts ?? 0 }}</strong>
        <small>Agent <b>{{ overviewStats.agents?.online ?? onlineCount }}</b> · VA <b>0</b></small>
      </div>
    </button>
    <button type="button" class="ov-rail-card click" data-tone="file" @click="emit('navigate', 'malware')">
      <div class="ov-rail-ico" aria-hidden="true"><span class="ico-mark">F</span></div>
      <div class="ov-rail-body">
        <span>检出恶意文件</span>
        <strong>{{ overviewStats.threats?.malware_total ?? 0 }}</strong>
        <small>已处置 <b class="ok">{{ overviewStats.threats?.malware_handled ?? 0 }}</b></small>
      </div>
    </button>
    <button type="button" class="ov-rail-card click" data-tone="host" @click="emit('events', { scope: 'endpoint' })">
      <div class="ov-rail-ico" aria-hidden="true"><span class="ico-mark">H</span></div>
      <div class="ov-rail-body">
        <span>终端威胁</span>
        <strong>{{ overviewStats.threats?.endpoint_total ?? 0 }}</strong>
        <small>已处置 <b class="ok">{{ overviewStats.threats?.endpoint_handled ?? 0 }}</b>
          <template v-if="overviewStats.threats?.endpoint_need_auth"> · 待跟进 {{ overviewStats.threats.endpoint_need_auth }}</template>
        </small>
      </div>
    </button>
    <button type="button" class="ov-rail-card click" data-tone="net" @click="emit('events', { scope: 'external' })">
      <div class="ov-rail-ico" aria-hidden="true"><span class="ico-mark">N</span></div>
      <div class="ov-rail-body">
        <span>外连威胁</span>
        <strong>{{ overviewStats.threats?.external_total ?? 0 }}</strong>
        <small>已处置 <b class="ok">{{ overviewStats.threats?.external_handled ?? 0 }}</b></small>
      </div>
    </button>
  </div>
</template>

<script setup>
defineProps({ overviewStats: { type: Object, default: () => ({}) }, onlineCount: Number })
const emit = defineEmits(['navigate', 'events'])
</script>

<style scoped>
.ov-threat-rail { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; margin-bottom: 14px; }
.ov-rail-card {
  text-align: left; display: flex; align-items: center; gap: 12px; min-width: 0;
  padding: 14px 16px; border: 1px solid var(--line); border-top: 3px solid var(--accent);
  border-radius: var(--radius); background: var(--panel); color: inherit;
  box-shadow: var(--shadow); cursor: pointer; font: inherit;
  transition: border-color .12s, box-shadow .12s, transform .12s;
}
.ov-rail-card[data-tone="file"] { border-top-color: var(--sev-medium); }
.ov-rail-card[data-tone="host"] { border-top-color: var(--sev-low); }
.ov-rail-card[data-tone="net"] { border-top-color: #0f9a8a; }
.ov-rail-card.click:hover {
  transform: translateY(-1px); border-color: #f0b6a0;
  box-shadow: 0 8px 22px rgba(226,86,44,.12);
}
.ov-rail-card:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.ov-rail-ico {
  flex: 0 0 40px; height: 40px; border-radius: 10px; display: grid; place-items: center;
  background: var(--accent-soft); color: var(--accent-2); border: 1px solid #f3cfc2;
}
.ico-mark { font-size: 13px; font-weight: 800; letter-spacing: .02em; }
.ov-rail-card[data-tone="file"] .ov-rail-ico { background: var(--sev-medium-bg); color: #b54708; border-color: #f5d0a0; }
.ov-rail-card[data-tone="host"] .ov-rail-ico { background: var(--sev-low-bg); color: #1d5f9a; border-color: #bfd5f0; }
.ov-rail-card[data-tone="net"] .ov-rail-ico { background: #e6f7f4; color: #0b7a6d; border-color: #b5e4dc; }
.ov-rail-body { min-width: 0; display: block; }
.ov-rail-body span { display: block; color: var(--muted); font-size: var(--fs-meta, 12px); font-weight: 600; }
.ov-rail-body strong {
  display: block; font-size: var(--fs-metric, 26px); font-weight: 750; line-height: 1.15;
  color: var(--ink); font-variant-numeric: tabular-nums; margin: 2px 0 4px;
}
.ov-rail-body small { display: block; color: var(--muted); font-size: 11px; line-height: 1.45; }
.ok { color: #047857; }
@media (max-width: 1280px) { .ov-threat-rail { grid-template-columns: repeat(2,minmax(0,1fr)); } }
@media (max-width: 520px) { .ov-threat-rail { grid-template-columns: 1fr; } }
</style>
