import { computed, ref, watch } from 'vue'
import { pageLabelOf } from '../consolePageCatalog.js'
import { NAV_PAGES } from '../consoleNavigation.js'

const TABS_KEY = 'edr.console.tabs'
const SHOW_TABS_KEY = 'edr.console.showTabs'
/** 已下线页面：从本地页签缓存里清掉，避免「主机基线」等残留 */
const DROPPED_PAGES = new Set(['baseline'])

function sanitizeTabIds(ids) {
  const out = []
  for (const id of ids || []) {
    if (typeof id !== 'string') continue
    if (DROPPED_PAGES.has(id)) continue
    if (NAV_PAGES.size && !NAV_PAGES.has(id) && id !== 'overview') continue
    if (!out.includes(id)) out.push(id)
  }
  return out
}

/**
 * Lightweight multi-page tabs for the console shell.
 * Stores page ids only; page content still mounts via existing App.vue v-if.
 */
export function useWorkspaceTabs({ page, isAdmin, goMenu }) {
  const tabs = ref([])
  const pinned = ref(new Set(['overview']))
  const showTabs = ref(true)

  try {
    const raw = JSON.parse(localStorage.getItem(TABS_KEY) || '[]')
    if (Array.isArray(raw) && raw.length) {
      tabs.value = sanitizeTabIds(raw).slice(0, 12)
    }
  } catch { /* ignore */ }
  try {
    const s = localStorage.getItem(SHOW_TABS_KEY)
    if (s === '0' || s === 'false') showTabs.value = false
  } catch { /* ignore */ }
  if (!tabs.value.includes('overview')) tabs.value.unshift('overview')
  // 启动时写回清洗结果，立刻去掉已下线页签
  try { localStorage.setItem(TABS_KEY, JSON.stringify(tabs.value.slice(0, 12))) } catch { /* ignore */ }

  const items = computed(() => tabs.value.map(id => ({
    id,
    label: pageLabelOf(id, !!isAdmin?.value),
    pinned: pinned.value.has(id),
  })))

  function persist() {
    try { localStorage.setItem(TABS_KEY, JSON.stringify(tabs.value.slice(0, 12))) } catch { /* ignore */ }
  }

  function persistShow() {
    try { localStorage.setItem(SHOW_TABS_KEY, showTabs.value ? '1' : '0') } catch { /* ignore */ }
  }

  function openTab(id) {
    const pid = String(id || '').trim()
    if (!pid || DROPPED_PAGES.has(pid)) return
    if (!tabs.value.includes(pid)) {
      tabs.value = [...tabs.value, pid].slice(-12)
      persist()
    }
  }

  function closeTab(id) {
    const pid = String(id || '').trim()
    if (!pid || pinned.value.has(pid) || tabs.value.length <= 1) return
    if (!tabs.value.includes(pid)) return
    const next = tabs.value.filter(x => x !== pid)
    tabs.value = [...next]
    persist()
    if (page.value === pid) goMenu(next[next.length - 1] || 'overview')
  }

  function closeOtherTabs(id) {
    const keep = String(id || page.value || 'overview')
    const next = tabs.value.filter(x => x === keep || pinned.value.has(x))
    if (!next.includes('overview')) next.unshift('overview')
    tabs.value = [...next]
    persist()
    if (!next.includes(page.value)) goMenu(keep)
  }

  function closeAllTabs() {
    tabs.value = ['overview']
    persist()
    if (page.value !== 'overview') goMenu('overview')
  }

  function activateTab(id) {
    openTab(id)
    if (page.value !== id) goMenu(id)
  }

  function setShowTabs(next) {
    showTabs.value = !!next
    persistShow()
  }

  watch(page, (id) => { openTab(id) }, { immediate: true })

  return {
    tabItems: items,
    showTabs,
    openTab,
    closeTab,
    closeOtherTabs,
    closeAllTabs,
    activateTab,
    setShowTabs,
  }
}
