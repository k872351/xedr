<template>
  <section class="page page-stack">
    <ConsolePageHeader title="存储与保留" description="SQLite 存近期热数据；MySQL 双写保留 4 倍时长作历史检索层；保留期在「EDR 策略」中设置">
      <slot name="refresh" />
    </ConsolePageHeader>
    <SummaryCards v-if="info" :items="cards" />
    <StorageRetentionSummary v-if="info" :retention="info.retention">
      <slot name="retention-actions" />
    </StorageRetentionSummary>
    <div class="panel pad fill-rest" style="margin-top:14px">
      <h3>历史时间线检索（MySQL）</h3>
      <slot name="search" />
      <div v-if="hits.length" style="margin-top:12px"><ConsoleReadOnlyTable :rows="hits" :columns="columns" /></div>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import ConsolePageHeader from './ConsolePageHeader.vue'
import ConsoleReadOnlyTable from './ConsoleReadOnlyTable.vue'
import SummaryCards from './SummaryCards.vue'
import StorageRetentionSummary from './StorageRetentionSummary.vue'
const props = defineProps({ info: Object, hits: { type: Array, required: true }, fmtNum: { type: Function, required: true }, fmtTime: { type: Function, required: true }, short: { type: Function, required: true } })
const cards = computed(() => props.info ? [
  { label: 'SQLite 时间线', value: props.fmtNum(props.info.sqlite_timeline) },
  { label: 'SQLite 事件', value: props.fmtNum(props.info.sqlite_events) },
  { label: 'MySQL 时间线', value: props.info.mysql?.available ? props.fmtNum(props.info.mysql.timeline) : '不可用', tone: 'on' },
  { label: 'MySQL 事件', value: props.info.mysql?.available ? props.fmtNum(props.info.mysql.events) : '不可用', tone: 'on' },
] : [])
const columns = computed(() => [
  { label: '时间', value: h => props.fmtTime(h.ts) },
  { label: '主机', value: h => h.hostname || props.short(h.agent_id) },
  { label: '类型', value: h => h.etype, class: 'mono' },
  { label: '摘要', value: h => h.summary },
])
</script>

<style scoped>
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }
.panel.pad { padding: 18px 20px; }
.panel h3 { margin: 0 0 12px; font-size: 14px; font-weight: 700; color: var(--ink); padding-bottom: 10px; border-bottom: 1px solid var(--line); }
</style>
