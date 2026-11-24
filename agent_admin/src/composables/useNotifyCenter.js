import { computed, ref } from 'vue'
import { listAgentCommands } from '../api.js'

const SAMPLE_KEY = 'edr_sample_inbox_v1'
const FEED_KEY = 'edr_notify_feed_v1'

function loadJson(key, fallback) {
  try {
    const raw = sessionStorage.getItem(key)
    const v = raw ? JSON.parse(raw) : fallback
    return Array.isArray(v) ? v : fallback
  } catch {
    return fallback
  }
}

function saveJson(key, items, max = 50) {
  try {
    sessionStorage.setItem(key, JSON.stringify(items.slice(0, max)))
  } catch { /* ignore */ }
}

const ACTION_TITLE = {
  pull_file: '恶意样本提取',
  quarantine_file: '文件隔离',
  unquarantine_file: '解除文件隔离',
  kill_process: '结束进程',
  isolate_network: '网络隔离',
  unisolate_network: '解除网络隔离',
  scan_memory: '内存扫描',
}

/**
 * 顶栏通知中心：样本下载 + 处置回执（类似消息通知列表）。
 */
export function useNotifyCenter() {
  const samples = ref(loadJson(SAMPLE_KEY, []))
  const feed = ref(loadJson(FEED_KEY, []))
  const open = ref(false)
  let timer = null

  const pendingCount = computed(() =>
    samples.value.filter((x) => x.status === 'pending' || x.status === 'sent').length,
  )
  const readyCount = computed(() =>
    samples.value.filter((x) => x.status === 'done' && x.stored).length,
  )

  const items = computed(() => samples.value)

  const notifications = computed(() => {
    const rows = []
    for (const s of samples.value) {
      const ok = s.status === 'done' && s.stored
      const fail = s.status === 'failed'
      const running = s.status === 'pending' || s.status === 'sent'
      let title = '恶意样本提取'
      if (ok) title = '恶意样本提取成功'
      else if (fail) title = '恶意样本提取失败'
      else if (running) title = '恶意样本提取中…'
      else if (s.status === 'done') title = '恶意样本提取完成（未入库）'
      rows.push({
        id: `sample:${s.commandId}`,
        kind: 'sample',
        title,
        detail: [s.hostname || s.agentId, s.filename || s.path || `指令 ${String(s.commandId).slice(0, 8)}`]
          .filter(Boolean)
          .join(' · '),
        status: ok ? 'ok' : fail ? 'err' : running ? 'wait' : 'info',
        unread: s.unread !== false && (ok || fail || running),
        createdAt: s.updatedAt || s.createdAt || Date.now(),
        sample: s,
      })
    }
    for (const n of feed.value) {
      rows.push({
        id: n.id,
        kind: n.kind || 'response',
        title: n.title,
        detail: n.detail || '',
        status: n.status || 'info',
        unread: !!n.unread,
        createdAt: n.createdAt || Date.now(),
        action: n.action || '',
        agentId: n.agentId || '',
        eventId: n.eventId || null,
        commandId: n.commandId || '',
      })
    }
    return rows.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).slice(0, 40)
  })

  const unreadCount = computed(() => notifications.value.filter((n) => n.unread).length)
  const badgeCount = computed(() => unreadCount.value || pendingCount.value || readyCount.value)

  function persistSamples() {
    saveJson(SAMPLE_KEY, samples.value, 40)
  }
  function persistFeed() {
    saveJson(FEED_KEY, feed.value, 50)
  }

  function trackSample({ agentId, commandId, eventId = null, path = '', hostname = '' }) {
    if (!agentId || !commandId) return
    const id = String(commandId)
    const exists = samples.value.find((x) => x.commandId === id)
    if (exists) {
      exists.status = 'pending'
      exists.path = path || exists.path
      exists.unread = true
      exists.updatedAt = Date.now()
    } else {
      samples.value.unshift({
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
        unread: true,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      })
    }
    persistSamples()
    startPoll()
  }

  function pushResponseNotify({
    commandId,
    agentId = '',
    eventId = null,
    action = '',
    status = 'done',
    hostname = '',
    detail = '',
  } = {}) {
    if (!commandId && !action) return
    const id = `resp:${commandId || `${action}-${Date.now()}`}`
    const ok = status === 'done'
    const fail = status === 'failed'
    const base = ACTION_TITLE[action] || action || '远程处置'
    const title = fail ? `${base}失败` : ok ? `${base}成功` : `${base}进行中`
    const existing = feed.value.find((x) => x.id === id)
    const row = {
      id,
      kind: 'response',
      title,
      detail: detail || [hostname, agentId && `终端 ${String(agentId).slice(0, 8)}`].filter(Boolean).join(' · '),
      status: ok ? 'ok' : fail ? 'err' : 'wait',
      unread: true,
      createdAt: Date.now(),
      action,
      agentId: String(agentId || ''),
      eventId,
      commandId: commandId ? String(commandId) : '',
    }
    if (existing) Object.assign(existing, row)
    else feed.value.unshift(row)
    feed.value = feed.value.slice(0, 50)
    persistFeed()
  }

  function dismissSample(commandId) {
    samples.value = samples.value.filter((x) => x.commandId !== String(commandId))
    persistSamples()
  }

  function dismissNotify(id) {
    if (String(id).startsWith('sample:')) {
      dismissSample(String(id).slice(7))
      return
    }
    feed.value = feed.value.filter((x) => x.id !== id)
    persistFeed()
  }

  function clearReady() {
    samples.value = samples.value.filter((x) => x.status !== 'done' && x.status !== 'failed')
    feed.value = feed.value.filter((x) => x.status === 'wait')
    persistSamples()
    persistFeed()
  }

  function markRead(id) {
    if (String(id).startsWith('sample:')) {
      const s = samples.value.find((x) => x.commandId === String(id).slice(7))
      if (s) {
        s.unread = false
        persistSamples()
      }
      return
    }
    const n = feed.value.find((x) => x.id === id)
    if (n) {
      n.unread = false
      persistFeed()
    }
  }

  function markAllRead() {
    for (const s of samples.value) s.unread = false
    for (const n of feed.value) n.unread = false
    persistSamples()
    persistFeed()
  }

  async function refreshOnce() {
    const pending = samples.value.filter((x) => x.status === 'pending' || x.status === 'sent')
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
          } catch {
            res = {}
          }
          if (c.status === 'done') {
            job.stored = !!(res.stored || res.filename)
            job.filename = res.filename || res.name || ''
            job.size = Number(res.size || res.bytes || 0) || 0
            job.unread = true
            if (job.stored) newlyReady.push({ ...job })
          } else if (c.status === 'failed') {
            job.error = String(res.error || res.message || '采集失败')
            job.stored = false
            job.unread = true
          }
        }
      } catch { /* keep pending */ }
    }
    persistSamples()
    return newlyReady
  }

  function startPoll() {
    if (timer) return
    timer = setInterval(async () => {
      const pending = samples.value.some((x) => x.status === 'pending' || x.status === 'sent')
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

  if (samples.value.some((x) => x.status === 'pending' || x.status === 'sent')) startPoll()

  return {
    // sample-compatible
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
    // notify center
    notifications,
    unreadCount,
    badgeCount,
    pushResponseNotify,
    dismissNotify,
    markRead,
    markAllRead,
  }
}
