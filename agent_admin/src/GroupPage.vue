<template>
  <section class="page page-stack">
    <ConsolePageHeader title="终端分组" description="把终端编成业务组（如财务 / 研发），供事件筛选、列表过滤与分批运维" />
    <div class="panel pad fill-rest group-panel">
      <p class="group-lead">分组不改变采集，只给终端打业务标签；在威胁事件、终端列表等处可按组缩小范围。</p>
      <slot name="form" />
      <div v-if="items.length" class="host-cards padded fill-rest-body">
        <div v-for="g in items" :key="g.id" class="host-card rich tile">
          <div class="hc-top"><b>{{ g.name }}</b><span class="pill">{{ (g.agent_ids || []).length }} 台</span></div>
          <div class="hc-meta"><span>{{ (g.agent_ids || []).join(', ') || '—' }}</span></div>
          <small class="muted">{{ g.note || '无备注' }}</small>
        </div>
      </div>
      <p v-else class="empty">暂无分组。在上方创建名称并勾选终端后保存。</p>
    </div>
  </section>
</template>

<script setup>
import ConsolePageHeader from './ConsolePageHeader.vue'
defineProps({ items: { type: Array, required: true } })
</script>

<style scoped>
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }
.panel.pad { padding: 18px 20px; }
.group-panel { display: flex; flex-direction: column; min-height: 0; }
.group-lead {
  margin: 0 0 14px; padding: 10px 12px; border-radius: 8px;
  background: var(--bg-elevated); border: 1px solid var(--line);
  color: var(--ink-2); font-size: 12.5px; line-height: 1.55;
}
.host-cards { padding: 4px 0 8px; display: flex; flex-direction: column; gap: 8px; overflow: auto; flex: 1; min-height: 0; }
.host-card {
  box-sizing: border-box; width: 100%; display: flex; flex-direction: column; align-items: stretch; gap: 6px;
  text-align: left; padding: 12px 14px; border: 1px solid var(--line); border-radius: 10px; background: var(--bg-elevated);
}
.host-card:hover { border-color: #f0b6a0; background: color-mix(in srgb, var(--accent-soft) 55%, #fff); }
.hc-top { display: flex; align-items: center; gap: 8px; }
.hc-top b { flex: 1; font-size: 13px; text-align: left; }
.hc-meta { display: flex; flex-wrap: wrap; gap: 8px 12px; font-size: 11px; color: var(--muted); padding-left: 2px; overflow-wrap: anywhere; }
.pill { display: inline-flex; align-items: center; border-radius: 999px; padding: 2px 9px; font-size: 11px; background: #eef1f6; color: var(--muted); font-weight: 600; }
.muted { color: var(--muted); font-size: 11px; }
.empty { padding: 16px 8px 28px; text-align: center; color: #98a2b3; font-size: 12.5px; line-height: 1.7; }
</style>
