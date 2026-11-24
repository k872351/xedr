import { computed, ref } from 'vue'

/**
 * 案件 / 威胁事件领域状态（列表筛选 + 威胁详情树）。
 * 打开/关闭详情函数仍由 App 持有，避免与导航强耦合。
 */
export function useThreatCases() {
  const events = ref([])
  const allEvents = ref([])
  const eventAgentId = ref('')
  const focusKey = ref('')
  const eventQName = ref('')
  const eventIocQ = ref('')
  const eventGroupId = ref('')
  const eventTypeFilter = ref('')
  const eventFiltersOn = ref({ name: '', ioc: '', group: '', type: '', sev: '' })
  const openEventCount = ref(0)
  const eventSort = ref({ key: 'created_at', dir: 'desc' })
  const eventSevFilter = ref('')
  const selectedEventIds = ref([])
  const eventListReturnPage = ref('events')
  const pendingThreatRestoreId = ref(null)

  const activeEvent = ref(null)
  const threatTab = ref('graph')
  const threatTree = ref(null)
  const threatTreeBusy = ref(false)
  const threatChainSelId = ref('')
  const tvTreeExpanded = ref({})
  const tvShowDotted = ref(true)
  const tvReadable = ref(true)
  const tvZoom = ref(1)
  const threatPanelNode = ref('hit')

  const listFocusId = ref(null)
  const listFocusEvent = ref(null)

  const allEventsSelected = computed(() => {
    const rows = events.value || []
    return rows.length > 0 && selectedEventIds.value.length === rows.length
  })

  function applyEventFilters() {
    eventFiltersOn.value = {
      name: String(eventQName.value || '').trim(),
      ioc: String(eventIocQ.value || '').trim(),
      group: String(eventGroupId.value || ''),
      type: String(eventTypeFilter.value || ''),
      sev: String(eventSevFilter.value || ''),
    }
  }

  function clearListFocus() {
    listFocusId.value = null
    listFocusEvent.value = null
  }

  return {
    events,
    allEvents,
    eventAgentId,
    focusKey,
    eventQName,
    eventIocQ,
    eventGroupId,
    eventTypeFilter,
    eventFiltersOn,
    openEventCount,
    eventSort,
    eventSevFilter,
    selectedEventIds,
    eventListReturnPage,
    pendingThreatRestoreId,
    activeEvent,
    threatTab,
    threatTree,
    threatTreeBusy,
    threatChainSelId,
    tvTreeExpanded,
    tvShowDotted,
    tvReadable,
    tvZoom,
    threatPanelNode,
    listFocusId,
    listFocusEvent,
    allEventsSelected,
    applyEventFilters,
    clearListFocus,
  }
}
