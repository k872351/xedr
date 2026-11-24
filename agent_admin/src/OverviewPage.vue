<template>
  <section class="page overview">
    <slot name="header" />
    <OverviewFleetStrip v-bind="fleet" @navigate="emit('navigate', $event)" @network="emit('network', $event)" @toggle="emit('toggle')" />
    <OverviewThreatCards :overview-stats="fleet.overviewStats" :online-count="fleet.onlineCount" @navigate="emit('navigate', $event)" @events="emit('events', $event)" />
    <OverviewActivity v-bind="activity" @menu="emit('menu', $event)" @navigate="emit('navigate', $event)" @event="emit('event', $event)" @timeline="emit('timeline', $event)" @host="(agent, origin) => emit('host', agent, origin)" />
    <OverviewSummaryPanels v-bind="summary" @navigate="emit('navigate', $event)" @events="emit('events', $event)" />
  </section>
</template>

<script setup>
import OverviewFleetStrip from './OverviewFleetStrip.vue'
import OverviewThreatCards from './OverviewThreatCards.vue'
import OverviewActivity from './OverviewActivity.vue'
import OverviewSummaryPanels from './OverviewSummaryPanels.vue'

defineProps({ fleet: { type: Object, required: true }, activity: { type: Object, required: true }, summary: { type: Object, required: true } })
const emit = defineEmits(['navigate', 'network', 'toggle', 'events', 'menu', 'event', 'timeline', 'host'])
</script>
