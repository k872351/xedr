<template>
  <div class="ov-fleet-strip" :class="{ collapsed: ovFleetCollapsed }">
    <div class="ov-fleet-main">
      <section class="ov-fleet-block">
        <header class="ov-fleet-hd">
          <span class="ov-fleet-ico" aria-hidden="true">🖥</span>
          <span>已接入终端</span>
          <i class="ov-info" title="Forensic Agent 注册主机；VA 为无 Agent 探针占位">i</i>
        </header>
        <div class="ov-fleet-metric">
          <strong>{{ ovAgentTotal }}</strong>
          <span class="ov-pill agent">Agent {{ ovAgentTotal }}</span>
          <span class="ov-pill va">VA {{ overviewStats.agents?.va ?? 0 }}</span>
        </div>
        <div class="ov-fleet-sub">
          <button type="button" class="ov-fleet-cell click" @click="emit('navigate', 'hosts')">
            <em>在线终端</em><b class="c-online">{{ onlineCount }}</b>
          </button>
          <div class="ov-fleet-cell">
            <em>24小时采集日志</em>
            <div class="ov-spark-row">
              <b>{{ overviewStats.timeline_24h?.display ?? '—' }}</b>
              <svg v-if="overviewSparkTl" class="ov-spark" viewBox="0 0 120 32" preserveAspectRatio="none">
                <polyline :points="overviewSparkTl" fill="none" stroke="#12b76a" stroke-width="1.5" />
              </svg>
            </div>
          </div>
        </div>
      </section>
      <span class="ov-fleet-div" />
      <section class="ov-fleet-block">
        <header class="ov-fleet-hd">
          <span class="ov-fleet-ico" aria-hidden="true">🏢</span>
          <span>职场 / 出口</span>
        </header>
        <div class="ov-fleet-sub three">
          <button type="button" class="ov-fleet-cell click" @click="emit('navigate', 'groups')">
            <em>已接入分组</em><b>{{ overviewStats.groups ?? 0 }}</b>
          </button>
          <button type="button" class="ov-fleet-cell click" @click="emit('network', 'external')">
            <em>活跃外联 IP(24h)</em><b>{{ overviewStats.network_exits ?? 0 }}</b>
          </button>
          <button type="button" class="ov-fleet-cell click" @click="emit('network', 'dns')">
            <em>24小时 DNS 请求</em>
            <div class="ov-spark-row">
              <b>{{ overviewStats.dns_24h?.display ?? '—' }}</b>
              <svg v-if="overviewSparkDns" class="ov-spark" viewBox="0 0 120 32" preserveAspectRatio="none">
                <polyline :points="overviewSparkDns" fill="none" stroke="#12b76a" stroke-width="1.5" />
              </svg>
            </div>
          </button>
        </div>
      </section>
    </div>
    <button type="button" class="ov-fleet-toggle" :aria-expanded="!ovFleetCollapsed" @click="emit('toggle')">
      {{ ovFleetCollapsed ? '展开' : '收起' }}
    </button>
  </div>
</template>

<script setup>
defineProps({
  ovAgentTotal: Number,
  onlineCount: Number,
  overviewStats: { type: Object, default: () => ({}) },
  overviewSparkTl: String,
  overviewSparkDns: String,
  ovFleetCollapsed: Boolean,
})
const emit = defineEmits(['navigate', 'network', 'toggle'])
</script>

<style scoped>
.ov-fleet-strip {
  display: flex; align-items: stretch; gap: 10px; margin-bottom: 12px;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: var(--radius); padding: 16px 18px; color: var(--ink);
  box-shadow: var(--shadow);
}
.ov-fleet-strip.collapsed .ov-fleet-main { display: none; }
.ov-fleet-main { display: flex; flex: 1; gap: 18px; align-items: stretch; min-width: 0; }
.ov-fleet-block { flex: 1; min-width: 0; }
.ov-fleet-block:last-child { flex: 1.15; }
.ov-fleet-hd { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #526e84; font-weight: 650; margin-bottom: 8px; }
.ov-fleet-ico { font-size: 16px; opacity: .85; }
.ov-info { font-style: normal; font-size: 11px; width: 16px; height: 16px; border-radius: 50%; border: 1px solid #64748b; display: inline-grid; place-items: center; cursor: help; }
.ov-fleet-metric { display: flex; align-items: baseline; gap: 10px; margin-bottom: 10px; }
.ov-fleet-metric > strong { font-size: var(--fs-metric, 26px); font-weight: 750; letter-spacing: -.02em; color: var(--ink); font-variant-numeric: tabular-nums; }
.ov-pill { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px; }
.ov-pill.agent { background: var(--accent-soft); color: var(--accent-2); }
.ov-pill.va { background: #fff3df; color: #a65b16; }
.ov-fleet-div { width: 1px; background: var(--line); align-self: stretch; }
.ov-fleet-sub { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 20px; align-items: end; }
.ov-fleet-sub.three {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 28px;
  align-items: flex-end;
  justify-content: flex-start;
}
.ov-fleet-sub.three .ov-fleet-cell { flex: 0 1 auto; min-width: 7.5rem; max-width: 14rem; }
.ov-fleet-cell em { display: block; font-style: normal; font-size: 12px; color: #64778b; margin-bottom: 4px; }
.ov-fleet-cell b { font-size: 20px; font-weight: 700; }
.ov-fleet-cell.click { cursor: pointer; border: 0; background: transparent; color: inherit; text-align: left; border-radius: 8px; padding: 4px 6px; margin: -4px -6px; }
.ov-fleet-cell.click:hover { background: var(--accent-soft); }
.ov-fleet-cell.click:focus-visible, .ov-fleet-toggle:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 3px; background: var(--accent-soft);
}
.ov-fleet-cell.click:active { background: #f8e4db; }
.ov-spark-row { display: flex; align-items: center; gap: 10px; }
.ov-spark { width: 120px; height: 32px; flex-shrink: 0; opacity: .95; }
.ov-fleet-toggle {
  align-self: center; border: 1px solid var(--line); background: var(--bg-elevated); color: var(--ink-2);
  border-radius: var(--radius-sm); padding: 6px 10px; font-size: 12px; cursor: pointer;
}
.ov-fleet-toggle:hover { border-color: #f0b6a0; background: var(--accent-soft); color: var(--accent-2); }
.c-online { color: var(--online); }
.ov-fleet-cell.click { font: inherit; }
@media (max-width: 900px) {
  .ov-fleet-main { flex-wrap: wrap; }
  .ov-fleet-block { flex-basis: 100%; }
  .ov-fleet-div { display: none; }
  .ov-spark-row { flex-wrap: wrap; }
  .ov-fleet-sub.three { flex-direction: column; align-items: stretch; }
  .ov-fleet-sub.three .ov-fleet-cell { max-width: none; }
}
</style>
