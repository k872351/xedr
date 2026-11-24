<template>
  <section class="page hosts-page">
    <ConsolePageHeader title="终端列表" description="接入主机一览；点主机查看进程 / 服务 / 网络等模块与可疑行为">
      <slot name="filters" />
    </ConsolePageHeader>
    <SummaryCards :items="cards" />
    <div class="panel host-panel">
      <HostListTable :agents="items" :total="total" :loading="loading" :short="short" :fmt-time="fmtTime" :alert-count="alertCount">
        <template #actions="{ agent }"><slot name="actions" :agent="agent" /></template>
      </HostListTable>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import ConsolePageHeader from './ConsolePageHeader.vue'
import SummaryCards from './SummaryCards.vue'
import HostListTable from './HostListTable.vue'
const props = defineProps({
  items: { type: Array, required: true }, total: { type: Number, required: true },
  onlineCount: { type: Number, required: true }, hostsWithAlert: { type: Number, required: true },
  loading: Boolean, short: { type: Function, required: true }, fmtTime: { type: Function, required: true },
  alertCount: { type: Function, required: true },
})
const cards = computed(() => [
  { label: '全部', value: props.total },
  { label: '在线', value: props.onlineCount, tone: 'on' },
  { label: '离线', value: props.total - props.onlineCount, tone: 'off' },
  { label: '有告警', value: props.hostsWithAlert, tone: 'danger' },
])
</script>

<style scoped>
.hosts-page { overflow: hidden; gap: 0; display: flex; flex-direction: column; min-height: 0; }
.hosts-page > .page-hd, .hosts-page > .host-summary { flex-shrink: 0; }
.host-panel {
  background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--shadow); padding: 0; flex: 1; min-height: 0;
  display: flex; flex-direction: column; overflow: hidden;
}
</style>
