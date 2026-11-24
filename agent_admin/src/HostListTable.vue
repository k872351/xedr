<template>
  <div class="host-table">
    <div class="ht-head">
      <span>主机</span><span>系统</span><span>IP</span><span>状态</span><span>最近心跳</span><span>版本</span><span>告警</span><span>操作</span>
    </div>
    <div v-if="loading && !agents.length" class="console-skel" aria-busy="true" aria-label="正在加载终端">
      <div class="console-skel-line lg" />
      <div class="console-skel-line md" />
      <div class="console-skel-line sm" />
      <div class="console-skel-line md" />
      <p class="sr-load">正在加载终端</p>
    </div>
    <template v-else>
      <div v-for="a in agents" :key="a.agent_id" class="ht-row">
        <span class="ht-host">
          <i :class="['dot', a.online ? 'on' : '']" />
          <b>{{ a.hostname || short(a.agent_id) }}</b>
        </span>
        <span><OsFamilyIcon :family="a.os_family" /></span>
        <span class="mono">{{ a.ip || '—' }}</span>
        <span><ConsoleStatusTag :status="a.online ? 'online' : 'offline'" :label="a.online ? '在线' : '离线'" /></span>
        <span class="muted">{{ fmtTime(a.last_seen) }}</span>
        <span class="ver">{{ a.version || '—' }}<ConsoleStatusTag v-if="a.outdated" status="warn" label="可升级" title="落后于当前发布版本" /></span>
        <span>
          <em v-if="alertCount(a.agent_id)" class="alert-n">{{ alertCount(a.agent_id) }}</em>
          <em v-else class="muted">0</em>
        </span>
        <slot name="actions" :agent="a" />
      </div>
      <div v-if="!agents.length" class="console-empty" data-kind="empty">
        <span class="console-empty-mark" aria-hidden="true">—</span>
        <strong>{{ total > 0 ? '没有符合当前筛选条件的终端' : '暂无终端' }}</strong>
        <p>{{ total > 0 ? '调整筛选条件后重试。' : '请先在部署页生成并安装 Agent。' }}</p>
      </div>
    </template>
  </div>
</template>

<script setup>
import ConsoleStatusTag from './ConsoleStatusTag.vue'
import OsFamilyIcon from './OsFamilyIcon.vue'
defineProps({
  agents: { type: Array, required: true },
  total: { type: Number, required: true },
  loading: Boolean,
  short: { type: Function, required: true },
  fmtTime: { type: Function, required: true },
  alertCount: { type: Function, required: true },
})
</script>

<style scoped>
.host-table { flex: 1; min-height: 0; overflow: auto; }
.ht-head, .ht-row {
  display: grid; grid-template-columns: 1.4fr .7fr 1fr .7fr 1.2fr .6fr .5fr 1.2fr;
  gap: 8px; align-items: center; padding: var(--row-pad-y, 10px) 16px; font-size: 13px; min-width: 850px;
}
.ht-head { background: var(--bg-elevated); color: var(--muted); font-size: 11.5px; font-weight: 650; border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 1; }
.ht-row { border-bottom: 1px solid var(--line); }
.ht-row:hover { background: var(--accent-soft); }
.ht-host { display: flex; align-items: center; gap: 8px; min-width: 0; }
.ht-host b { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: #c5ccd8; flex-shrink: 0; }
.dot.on { background: var(--online); box-shadow: 0 0 0 3px rgba(22,185,129,.18); }
.pill { display: inline-flex; align-items: center; border-radius: 999px; padding: 2px 9px; font-size: 11px; background: #eef1f6; color: var(--muted); font-weight: 600; font-style: normal; }
.pill.on { background: #e8f8ef; color: var(--online); }
.pill.warn { background: #fffaeb; color: #b54708; margin-left: 6px; }
.alert-n { display: inline-flex; min-width: 18px; justify-content: center; padding: 1px 6px; border-radius: 999px; background: var(--sev-critical-bg); color: var(--sev-critical); font-style: normal; font-size: 12px; font-weight: 700; }
.mono { font-variant-numeric: tabular-nums; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.ver { display: inline-flex; align-items: center; flex-wrap: wrap; gap: 4px; }
.muted { color: var(--muted); }
.sr-load { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
.console-skel { position: relative; }
</style>
