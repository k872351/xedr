<template>
  <div class="snap-sum">
    <div class="sd-hd"><div><b>{{ moduleTitle }} 模块摘要</b><small>{{ inventory ? '资产字段概览' : '点击左侧行查看完整字段' }}</small></div></div>
    <div class="ss-kpis">
      <div><span>条目</span><strong>{{ stats.total }}</strong></div>
      <div v-if="stats.unsigned != null"><span>未签名</span><strong class="c-danger">{{ stats.unsigned }}</strong></div>
      <div v-if="stats.hotpath != null"><span>可疑路径</span><strong class="c-warn">{{ stats.hotpath }}</strong></div>
      <div v-if="stats.admins != null"><span>管理员身份</span><strong>{{ stats.admins }}</strong></div>
      <div v-if="stats.fields"><span>字段数</span><strong>{{ stats.fields }}</strong></div>
    </div>
    <slot name="detection" />
    <div v-if="stats.hotRows?.length" class="ss-list">
      <h4>关注项</h4>
      <button v-for="(r, i) in stats.hotRows" :key="i" type="button" class="ss-row" @click="emit('select', r.row)">
        <span class="sev" :data-s="r.sev">{{ r.tag }}</span><b>{{ r.title }}</b><small>{{ r.sub }}</small>
      </button>
    </div>
    <div v-if="stats.sampleRows?.length" class="ss-list">
      <h4>最近条目</h4>
      <button v-for="(r, i) in stats.sampleRows" :key="'s'+i" type="button" class="ss-row" @click="emit('select', r.row)">
        <span class="sev" data-s="info">条目</span><b>{{ r.title }}</b><small>{{ r.sub }}</small>
      </button>
    </div>
    <p v-else-if="!stats.hotRows?.length" class="empty sm">本模块暂无高亮项，可在左侧点行查看详情</p>
    <slot name="actions" />
  </div>
</template>

<script setup>
defineProps({ stats: { type: Object, required: true }, moduleTitle: String, inventory: Boolean })
const emit = defineEmits(['select'])
</script>

<style scoped>
.snap-sum { display: flex; flex-direction: column; min-height: 0; overflow: auto; }
.sd-hd { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.sd-hd b { display: block; font-size: 14px; word-break: break-word; }
.sd-hd small { color: var(--muted); font-size: 11px; }
.ss-kpis { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 8px; padding: 12px 14px; }
.ss-kpis > div { background: #f5f8fc; border: 1px solid #e8eef6; border-radius: 8px; padding: 10px 12px; }
.ss-kpis span { display: block; font-size: 11px; color: var(--muted); margin-bottom: 4px; }
.ss-kpis strong { font-size: 22px; font-weight: 720; letter-spacing: -.03em; }
.ss-kpis .c-warn { color: #c2410c; }
.ss-kpis .c-danger { color: #b91c1c; }
.ss-list { padding: 0 12px 10px; display: flex; flex-direction: column; gap: 6px; }
.ss-list h4 { margin: 4px 0 6px; font-size: 12px; color: var(--muted); }
.ss-row { display: grid; grid-template-columns: auto 1fr; gap: 2px 10px; text-align: left; border: 1px solid var(--line); background: #fff; border-radius: 8px; padding: 8px 10px; cursor: pointer; }
.ss-row b { font-size: 13px; grid-column: 2; }
.ss-row small { grid-column: 2; color: var(--muted); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ss-row .sev { grid-row: 1 / span 2; align-self: center; }
.sev { display: inline-flex; align-items: center; gap: 5px; padding: 2px 9px; border-radius: 6px; font-size: 11.5px; font-weight: 700; line-height: 1.6; white-space: nowrap; }
.sev::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.sev[data-s=critical] { color: var(--sev-critical); background: var(--sev-critical-bg); }
.sev[data-s=high] { color: var(--sev-high); background: var(--sev-high-bg); }
.sev[data-s=medium] { color: var(--sev-medium); background: var(--sev-medium-bg); }
.sev[data-s=low] { color: var(--sev-low); background: var(--sev-low-bg); }
.sev[data-s=info] { color: var(--sev-info); background: var(--sev-info-bg); }
.empty { padding: 4px 16px 28px; text-align: center; color: #98a2b3; font-size: 12.5px; line-height: 1.7; }
</style>
