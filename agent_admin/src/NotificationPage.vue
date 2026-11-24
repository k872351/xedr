<template>
  <section class="page page-stack">
    <ConsolePageHeader title="通知渠道" description="新威胁事件达到级别阈值时推送（同主机同标题 10 分钟内只推一次）" />
    <div class="panel pad settings fill-rest">
      <slot name="form" />
      <div v-if="result" class="notify-results">
        <p v-if="result.error" class="err-text">{{ result.error }}</p>
        <p v-for="r in result.results || []" :key="r.channel" :class="r.ok ? 'hint' : 'err-text'">
          {{ ({ webhook: 'Webhook', feishu: '飞书', dingtalk: '钉钉' })[r.channel] || r.channel }}：
          {{ r.ok ? `成功（HTTP ${r.status}）` : `失败：${r.error}` }}
        </p>
      </div>
    </div>
  </section>
</template>

<script setup>
import ConsolePageHeader from './ConsolePageHeader.vue'
defineProps({ result: Object })
</script>

<style scoped>
.panel { background: #fff; border: 1px solid #e4e7ec; border-radius: 12px; box-shadow: 0 4px 20px rgba(28,30,36,.06); overflow: hidden; }
.panel.pad { padding: 18px 20px; }
.settings :slotted(label) { display: block; font-weight: 600; font-size: 13px; }
.settings :slotted(.row) { display: flex; gap: 8px; margin-top: 14px; }
.notify-results { margin-top: 10px; }
.hint, .err-text { font-size: 12px; margin: 8px 0 0; }
.hint { color: var(--muted); }
.err-text { color: var(--danger); }
</style>
