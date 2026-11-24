<template>
  <div class="ov-bottom-grid">
    <div class="panel ov-panel">
      <div class="panel-hd"><h3>威胁分类</h3><button type="button" class="btn-text" @click="emit('navigate', 'events')">威胁事件 →</button></div>
      <div class="ov-cats ov-cats-compact">
        <button v-for="c in focusCats" :key="c.key" type="button" class="ov-cat" @click="emit('events', { focus: c.key })">
          <span class="focus-ico" :style="{ background: c.color }">{{ c.short }}</span>
          <b>{{ c.label }}</b>
          <em>{{ c.count }}</em>
        </button>
      </div>
    </div>

    <div class="panel ov-panel">
      <div class="panel-hd"><h3>告警级别</h3><span class="meta">未处置 {{ ovStatus.open }} · 已处置 {{ ovStatus.closed }}</span></div>
      <div class="ov-bars">
        <div v-for="s in ovSevDist" :key="s.key" class="ov-bar-row">
          <span class="sev" :data-s="s.key">{{ s.label }}</span>
          <div class="ov-bar"><i :style="{ width: s.pct + '%' }" :data-s="s.key" /></div>
          <b>{{ s.count }}</b>
        </div>
      </div>
    </div>

    <div class="panel ov-panel">
      <div class="panel-hd"><h3>近 7 天告警趋势</h3><span class="meta">共 {{ ovTrend.total }} 条</span></div>
      <div class="ov-trend">
        <div v-for="d in ovTrend.days" :key="d.day" class="ov-trend-col" :title="`${d.day}：${d.count} 条（高危 ${d.high}）`">
          <em>{{ d.count || '' }}</em>
          <div class="ov-trend-bar"><i :style="{ height: d.pct + '%' }" /><i class="hi" :style="{ height: d.hpct + '%' }" /></div>
          <small>{{ d.label }}</small>
        </div>
      </div>
    </div>

    <div class="panel ov-panel">
      <div class="panel-hd">
        <h3>{{ overviewTopMalware.length ? 'TOP5 恶意文件' : '风险终端 Top 5' }}</h3>
        <button type="button" class="btn-text" @click="overviewTopMalware.length ? emit('navigate', 'malware') : emit('navigate', 'hosts')">{{ overviewTopMalware.length ? '全部 →' : '终端列表 →' }}</button>
      </div>
      <ul v-if="overviewTopMalware.length" class="ov-mal-list compact">
        <li v-for="(m, i) in overviewTopMalware" :key="i">
          <i>{{ i + 1 }}</i><span class="mono" :title="m.title">{{ m.title }}</span><em>{{ m.count }}</em>
        </li>
      </ul>
      <div v-else class="ov-rank">
        <button v-for="(h, i) in ovTopHosts" :key="h.agent_id" type="button" class="ov-rank-row" @click="emit('events', { agent: h.agent_id })">
          <i>{{ i + 1 }}</i>
          <b>{{ h.hostname }}</b>
          <span v-if="h.high" class="sev" data-s="high">高危 {{ h.high }}</span>
          <em>{{ h.count }} 条</em>
        </button>
        <p v-if="!ovTopHosts.length" class="empty sm">暂无数据</p>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  focusCats: { type: Array, required: true }, ovStatus: { type: Object, required: true },
  ovSevDist: { type: Array, required: true }, ovTrend: { type: Object, required: true },
  overviewTopMalware: { type: Array, required: true }, ovTopHosts: { type: Array, required: true },
})
const emit = defineEmits(['navigate', 'events'])
</script>

<style scoped>
.ov-bottom-grid {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px;
  margin-top: 10px; flex: 0 0 auto;
}
.ov-panel { min-height: 168px; display: flex; flex-direction: column; }
.ov-panel .ov-bars, .ov-panel .ov-trend, .ov-panel .ov-rank, .ov-panel .ov-mal-list { flex: 1; }
.ov-cats-compact { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.ov-mal-list.compact { padding: 6px 14px 12px; }
.ov-mal-list { list-style: none; margin: 0; padding: 8px 16px 14px; }
.ov-mal-list li { display: grid; grid-template-columns: 24px 1fr auto; gap: 10px; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--line); font-size: 13px; }
.ov-mal-list li:last-child { border-bottom: 0; }
.ov-mal-list i { font-style: normal; color: var(--muted); font-weight: 700; }
.ov-mal-list em { font-style: normal; font-weight: 700; }
.ov-cats { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; padding: 12px 14px 14px; }
.ov-cat {
  display: flex; align-items: center; gap: 8px; border: 1px solid var(--line); background: #fafbfd;
  border-radius: 8px; padding: 7px 9px; cursor: pointer; text-align: left; min-width: 0;
}
.ov-cat:hover { border-color: #b7c9f0; background: var(--accent-soft); }
.ov-cat .focus-ico { width: 24px; height: 24px; font-size: 11px; }
.ov-cat b { flex: 1; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ov-cat em { font-style: normal; font-weight: 700; font-size: 13px; }
.ov-bars { display: flex; flex-direction: column; gap: 12px; padding: 16px; flex: 1; justify-content: center; }
.ov-bar-row { display: grid; grid-template-columns: 48px 1fr 40px; align-items: center; gap: 10px; }
.ov-bar-row b { text-align: right; font-size: 13px; }
.ov-bar { height: 8px; border-radius: 4px; background: #eef1f6; overflow: hidden; }
.ov-bar i { display: block; height: 100%; border-radius: 4px; background: #98a2b3; transition: width .3s; }
.ov-bar i[data-s="critical"] { background: #b42318; }
.ov-bar i[data-s="high"] { background: #e11d2e; }
.ov-bar i[data-s="medium"] { background: #f79009; }
.ov-bar i[data-s="low"] { background: #2e90fa; }
.ov-trend { display: grid; grid-template-columns: repeat(7, 1fr); gap: 8px; padding: 14px 16px 12px; flex: 1; min-height: 170px; }
.ov-trend-col { display: flex; flex-direction: column; align-items: center; gap: 4px; min-width: 0; }
.ov-trend-col em { font-style: normal; font-size: 11px; color: var(--muted); height: 14px; }
.ov-trend-bar { position: relative; flex: 1; width: 100%; max-width: 30px; background: #f2f4f8; border-radius: 6px; overflow: hidden; }
.ov-trend-bar i { position: absolute; left: 0; right: 0; bottom: 0; background: #9db4e6; border-radius: 6px 6px 0 0; }
.ov-trend-bar i.hi { background: #e11d2e; opacity: .85; }
.ov-trend-col small { font-size: 11px; color: var(--muted); }
.ov-rank { display: flex; flex-direction: column; gap: 4px; padding: 10px 12px 12px; }
.ov-rank-row {
  display: grid; grid-template-columns: 22px 1fr auto auto; align-items: center; gap: 8px;
  border: 0; background: transparent; border-radius: 8px; padding: 8px; cursor: pointer; text-align: left;
}
.ov-rank-row:hover { background: var(--accent-soft); }
.ov-rank-row i {
  font-style: normal; width: 22px; height: 22px; border-radius: 6px; background: #eef1f6;
  display: grid; place-items: center; font-size: 12px; font-weight: 700;
}
.ov-rank-row:nth-child(-n+3) i { background: #fde8e8; color: #b42318; }
.ov-rank-row b { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ov-rank-row em { font-style: normal; color: var(--muted); font-size: 12px; }
.focus-ico {
  width: 30px; height: 30px; border-radius: 8px; color: #fff;
  display: grid; place-items: center; font-size: 12px; font-weight: 700; flex-shrink: 0;
}
.panel-hd {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 12px 16px; border-bottom: 1px solid var(--line);
}
.panel-hd.bare { border: 0; padding: 0 0 12px; }
.panel-hd h3 { margin: 0; font-size: 14px; font-weight: 650; }
.meta { color: var(--muted); font-size: 12px; }
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
.ov-bar { background: #eceff4; }
.ov-bar i { background: #3b82c4; }
.ov-bar i[data-s="critical"] { background: #b42318; }
.ov-bar i[data-s="high"] { background: #e2562c; }
.ov-bar i[data-s="medium"] { background: #f79009; }
.ov-bar i[data-s="low"] { background: #3b82c4; }
.ov-trend-bar { background: #eceff4; }
.ov-trend-bar i { background: #6b9bcb; }
.ov-trend-bar i.hi { background: #e2562c; }
.ov-bar i[data-s="critical"] { background: var(--sev-critical); }
.ov-bar i[data-s="high"]     { background: var(--sev-high); }
.ov-bar i[data-s="medium"]   { background: var(--sev-medium); }
.ov-bar i[data-s="low"]      { background: var(--sev-low); }
.ov-trend-bar i[data-s="critical"], .ov-trend-bar i.hi { background: var(--sev-critical); }
.ov-trend-bar i[data-s="high"] { background: var(--sev-high); }
.panel { background: #fff; border: 1px solid rgba(15,23,42,.06); border-radius: 12px; box-shadow: 0 8px 24px rgba(15,23,42,.04); overflow: hidden; }
.panel-hd { background: linear-gradient(180deg,#fcfcfd,#ffffff); border-bottom-color: #eceef2; }
.panel-hd h3 { color: #2b3038; }
.btn-text { border: 0; background: none; color: var(--accent); font-weight: 600; font-size: 13px; cursor: pointer; }
.mono { font-variant-numeric: tabular-nums; font-family: ui-monospace, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
.empty { padding: 4px 16px 28px; text-align: center; color: #98a2b3; font-size: 12.5px; line-height: 1.7; }
@media (max-width: 1280px) { .ov-bottom-grid { grid-template-columns: repeat(2,minmax(0,1fr)); } .ov-cats-compact { grid-template-columns: repeat(2,minmax(0,1fr)); } }
@media (max-width: 900px) { .ov-bottom-grid { grid-template-columns: 1fr; } }
</style>
