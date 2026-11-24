<template>
  <div class="ov-body">
    <div class="panel ov-threats">
      <div class="panel-hd">
        <div>
          <h3>最近威胁</h3>
          <span class="meta">点击进入威胁视图处置</span>
        </div>
        <div class="hd-right">
          <button type="button" class="btn-text" @click="emit('menu', 'behaviors')">检出行为</button>
          <button type="button" class="btn-text" @click="emit('navigate', 'events')">全部 →</button>
        </div>
      </div>
      <div v-if="recentThreats.length" class="table-scroll ov-threat-scroll">
        <table class="evt-table">
          <thead>
            <tr>
              <th>级别</th>
              <th>事件</th>
              <th>主机</th>
              <th>模块</th>
              <th>时间</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="e in recentThreats"
              :key="e.id"
              class="row-click"
              @click="emit('event', e)"
            >
              <td><span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span></td>
              <td class="strong">{{ e.title }}</td>
              <td>{{ e.hostname || short(e.agent_id) }}</td>
              <td class="muted">{{ modLabel(e.module) || '—' }}</td>
              <td class="mono">{{ fmtTime(e.updated_at || e.created_at) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else-if="recentRiskTimeline.length" class="table-scroll ov-threat-scroll">
        <p class="hint" style="margin:8px 14px">暂无正式威胁事件，以下为近期中高危时间线</p>
        <table class="evt-table">
          <thead>
            <tr><th>级别</th><th>摘要</th><th>主机</th><th>类型</th><th>时间</th></tr>
          </thead>
          <tbody>
            <tr
              v-for="t in recentRiskTimeline"
              :key="t.id || (t.ts + t.summary)"
              class="row-click"
              @click="emit('timeline', t.agent_id)"
            >
              <td><span class="sev" :data-s="t.severity">{{ sevLabel(t.severity) }}</span></td>
              <td class="strong">{{ cleanSummary(t.summary) }}</td>
              <td>{{ t.hostname || short(t.agent_id) }}</td>
              <td class="muted">{{ etypeLabel(t.etype) }}</td>
              <td class="mono">{{ fmtTime(t.ts) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty sm ov-empty">
        <p>暂无威胁事件</p>
        <p v-if="!agents.length" class="hint sm">尚未接入终端，可前往 <button type="button" class="btn-text" @click="emit('menu', 'deploy')">部署安装</button> 纳管第一台主机。</p>
        <button type="button" class="btn sm" @click="emit('menu', 'timeline')">查看时间线</button>
      </div>
    </div>

    <aside class="panel ov-side">
      <div class="panel-hd">
        <h3>终端</h3>
        <button type="button" class="btn-text" @click="emit('navigate', 'hosts')">管理 →</button>
      </div>
      <div class="ov-host-summary">
        <div><b>{{ onlineCount }}</b><span>在线</span></div>
        <div><b>{{ agents.length - onlineCount }}</b><span>离线</span></div>
        <div><b>{{ agents.reduce((n, a) => n + (alertCount(a.agent_id) || 0), 0) }}</b><span>告警</span></div>
      </div>
      <div class="ov-host-list">
        <button
          v-for="a in agents"
          :key="a.agent_id"
          type="button"
          class="ov-host-row"
          @click="emit('host', a, 'hosts')"
        >
          <i :class="['dot', a.online ? 'on' : '']" />
          <div class="ov-host-main">
            <b>{{ a.hostname || short(a.agent_id) }}</b>
            <small>{{ a.ip || '—' }} · v{{ a.version || '—' }} · {{ a.online ? '在线' : '离线' }}</small>
          </div>
          <span v-if="alertCount(a.agent_id)" class="alert-n badge">{{ alertCount(a.agent_id) }}</span>
          <span v-else class="ov-host-ok">正常</span>
        </button>
        <p v-if="!agents.length" class="empty sm">暂无终端</p>
      </div>
      <div class="ov-side-links">
        <button type="button" class="btn sm" @click="emit('menu', 'deploy')">部署安装</button>
        <button type="button" class="btn sm" @click="emit('menu', 'hunt')">威胁狩猎</button>
        <button type="button" class="btn sm" @click="emit('menu', 'policy')">EDR 策略</button>
        <button type="button" class="btn sm" @click="emit('menu', 'attck')">ATT&CK</button>
      </div>
    </aside>
  </div>
</template>

<script setup>
defineProps({
  recentThreats: { type: Array, required: true }, recentRiskTimeline: { type: Array, required: true },
  agents: { type: Array, required: true }, onlineCount: { type: Number, required: true },
  sevLabel: { type: Function, required: true }, short: { type: Function, required: true },
  modLabel: { type: Function, required: true }, fmtTime: { type: Function, required: true },
  cleanSummary: { type: Function, required: true }, etypeLabel: { type: Function, required: true },
  alertCount: { type: Function, required: true },
})
const emit = defineEmits(['menu', 'navigate', 'event', 'timeline', 'host'])
</script>

<style scoped>
.ov-body {
  display: grid; grid-template-columns: minmax(0, 1.7fr) minmax(280px, .85fr);
  gap: 14px; align-items: stretch; flex: 1 1 auto; min-height: 0;
}
.ov-threats { min-width: 0; display: flex; flex-direction: column; min-height: 0; }
.ov-threats .ov-threat-scroll { flex: 1; min-height: 0; max-height: none; }
.ov-threat-scroll { max-height: min(520px, calc(100vh - 260px)); }
.ov-side { display: flex; flex-direction: column; min-width: 0; min-height: 0; height: 100%; }
.ov-host-summary {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;
  padding: 10px 12px; border-bottom: 1px solid var(--line); flex-shrink: 0;
}
.ov-host-summary > div {
  background: #f7f9fc; border-radius: 8px; padding: 8px 10px; text-align: center;
}
.ov-host-summary b { display: block; font-size: 18px; font-weight: 700; color: var(--ink); line-height: 1.2; }
.ov-host-summary span { font-size: 11px; color: var(--muted); }
.ov-host-list {
  padding: 6px 8px; display: flex; flex-direction: column; gap: 2px;
  flex: 1 1 auto; min-height: 0; overflow: auto;
}
.ov-host-row {
  display: flex; align-items: center; gap: 10px; width: 100%; text-align: left;
  border: 0; background: transparent; border-radius: 8px; padding: 9px 10px; cursor: pointer;
}
.ov-host-row:hover { background: #f5f8fc; }
.ov-host-main { flex: 1; min-width: 0; }
.ov-host-main b {
  display: block; font-size: 13px; font-weight: 650;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ov-host-main small { color: var(--muted); font-size: 11px; }
.ov-host-ok { font-size: 11px; color: #059669; font-weight: 600; flex-shrink: 0; }
.ov-side-links {
  display: flex; flex-wrap: wrap; gap: 8px; padding: 12px 14px 14px;
  border-top: 1px solid var(--line); margin-top: auto; flex-shrink: 0;
}
.panel-hd {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 12px 16px; border-bottom: 1px solid var(--line);
}
.panel-hd.bare { border: 0; padding: 0 0 12px; }
.panel-hd h3 { margin: 0; font-size: 14px; font-weight: 650; }
.meta { color: var(--muted); font-size: 12px; }
.table-scroll { overflow: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td {
  padding: 11px 14px; text-align: left; border-bottom: 1px solid var(--line);
  white-space: nowrap; max-width: 280px; overflow: hidden; text-overflow: ellipsis; vertical-align: middle;
}
th { background: #fafbfd; color: var(--muted); font-weight: 600; font-size: 12px; position: sticky; top: 0; z-index: 1; }
.strong { font-weight: 650; }
.row-click { cursor: pointer; }
.sev {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 2px 9px; border-radius: 6px; font-size: 11.5px; font-weight: 700;
  line-height: 1.6; white-space: nowrap;
}
.sev::before {
  content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor;
}
.sev[data-s=critical] { color: var(--sev-critical); background: var(--sev-critical-bg); }
.sev[data-s=high]     { color: var(--sev-high);     background: var(--sev-high-bg); }
.sev[data-s=medium]   { color: var(--sev-medium);   background: var(--sev-medium-bg); }
.sev[data-s=low]      { color: var(--sev-low);      background: var(--sev-low-bg); }
.sev[data-s=info]     { color: var(--sev-info);     background: var(--sev-info-bg); }
th {
  background: linear-gradient(180deg, #f5f6f8, #eef0f3);
  color: #575f6c;
  border-bottom-color: #dfe2e8;
  letter-spacing: .02em;
}
td { border-bottom-color: #eceef2; }
tbody tr:nth-child(even) td { background: #fafbfc; }
.row-click:hover td, tbody tr:hover td { background: #fdf0ea; }
.alert-n.badge {
  min-width: 18px; height: 18px; padding: 0 5px; border-radius: 999px;
  display: inline-grid; place-items: center; font-size: 11px; font-style: normal;
}
.btn {
  border: 1px solid var(--line); background: #fff; border-radius: 8px;
  padding: 7px 13px; font-size: 13px; font-weight: 550; color: var(--ink-2);
}
.btn:hover { border-color: #cfd7e6; }
.btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: #c5ccd8; flex-shrink: 0; }
.dot.on { background: var(--online); }
.panel { background: #fff; border: 1px solid #e4e7ec; border-radius: 12px; box-shadow: 0 4px 20px rgba(28,30,36,.06); overflow: hidden; }
.panel-hd { background: linear-gradient(180deg,#fcfcfd,#ffffff); border-bottom-color: #eceef2; }
.panel-hd h3 { color: #2b3038; }
.hd-right { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.btn-text { border: 0; background: none; color: var(--accent); font-weight: 600; font-size: 13px; cursor: pointer; }
.btn.sm { padding: 5px 10px; font-size: 12px; font-weight: 600; cursor: pointer; }
th { padding: 10px 12px; font-size: 12px; }
td { padding: 9px 12px; font-size: 12.5px; }
.mono { font-variant-numeric: tabular-nums; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.muted { color: var(--muted); }
.hint { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
.empty { padding: 4px 16px 28px; text-align: center; color: #98a2b3; font-size: 12.5px; line-height: 1.7; }
.ov-empty { padding: 28px 16px; text-align: center; }
.ov-empty .hint { margin: 6px 0 12px; }
.alert-n { display: inline-flex; background: #fef2f2; color: #e11d2e; font-weight: 700; }
.row-click { cursor: pointer; }
@media (max-width: 1100px) { .ov-body { grid-template-columns: 1fr; } }
</style>
