import { computed, onUnmounted, ref } from 'vue'
import { listAgentCommands } from '../api.js'

const STORE_KEY = 'edr_sample_inbox_v1'

function loadStore() {
  try {
    const raw = sessionStorage.getItem(STORE_KEY)
    const arr = raw ? JSON.parse(raw) : []
    return Array.isArray(arr) ? arr : []
  } catch {
    return []
  }
}

function saveStore(items) {
  try {
    sessionStorage.setItem(STORE_KEY, JSON.stringify(items.slice(0, 40)))
  } catch { /* ignore */ }
}

/**
 * 采集样本全局收件箱：离开威胁页也能轮询，完成后可直接下载。
 */
export function useSampleInbox() {
  const items = ref(loadStore())
  const open = ref(false)
  let timer = null

  const pendingCount = computed(() => items.value.filter((x) => x.status === 'pending' || x.status === 'sent').length)
  const readyCount = computed(() => items.value.filter((x) => x.status === 'done' && x.stored).length)

  function persist() {
    saveStore(items.value)
  }

  function trackSample({ agentId, commandId, eventId = null, path = '', hostname = '' }) {
    if (!agentId || !commandId) return
    const id = String(commandId)
    const exists = items.value.find((x) => x.commandId === id)
    if (exists) {
      exists.status = 'pending'
      exists.path = path || exists.path
      exists.updatedAt = Date.now()
    } else {
      items.value.unshift({
        commandId: id,
        agentId: String(agentId),
        eventId,
        path: path || '',
        hostname: hostname || '',
        status: 'pending',
        stored: false,
        filename: '',
        size: 0,
        error: '',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      })
    }
    persist()
    startPoll()
  }

  function dismissSample(commandId) {
    items.value = items.value.filter((x) => x.commandId !== String(commandId))
    persist()
  }

  function clearReady() {
    items.value = items.value.filter((x) => x.status !== 'done' && x.status !== 'failed')
    persist()
  }

  async function refreshOnce() {
    const pending = items.value.filter((x) => x.status === 'pending' || x.status === 'sent')
    if (!pending.length) return []
    const byAgent = new Map()
    for (const p of pending) {
      if (!byAgent.has(p.agentId)) byAgent.set(p.agentId, [])
      byAgent.get(p.agentId).push(p)
    }
    const newlyReady = []
    for (const [aid, list] of byAgent) {
      try {
        const r = await listAgentCommands(aid)
        const cmds = r?.items || []
        for (const job of list) {
          const c = cmds.find((x) => String(x.id) === String(job.commandId))
          if (!c) continue
          job.status = c.status || job.status
          job.updatedAt = Date.now()
          let res = {}
          try {
            res = typeof c.result_json === 'string' ? JSON.parse(c.result_json || '{}') : (c.result_json || {})
          } catch { res = {} }
          if (c.status === 'done') {
            job.stored = !!(res.stored || res.filename)
            job.filename = res.filename || res.name || ''
            job.size = Number(res.size || res.bytes || 0) || 0
            if (job.stored) newlyReady.push({ ...job })
          } else if (c.status === 'failed') {
            job.error = String(res.error || res.message || '采集失败')
            job.stored = false
          }
        }
      } catch { /* keep pending */ }
    }
    persist()
    return newlyReady
  }

  function startPoll() {
    if (timer) return
    timer = setInterval(async () => {
      const pending = items.value.some((x) => x.status === 'pending' || x.status === 'sent')
      if (!pending) {
        stopPoll()
        return
      }
      await refreshOnce()
    }, 3000)
  }

  function stopPoll() {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  }

  // 进入页面时若有未完成任务继续轮询
  if (items.value.some((x) => x.status === 'pending' || x.status === 'sent')) startPoll()

  onUnmounted(() => { /* 单例式：App 级持有，不在此停 */ })

  return {
    items,
    open,
    pendingCount,
    readyCount,
    trackSample,
    dismissSample,
    clearReady,
    refreshOnce,
    startPoll,
    stopPoll,
  }
}
