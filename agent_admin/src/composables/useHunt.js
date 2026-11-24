import { ref } from 'vue'
import { huntAgents } from '../api.js'
import { latestRequest } from '../latestRequest.js'

/**
 * 威胁狩猎领域状态与动作。
 * openEvent / openHost / openTimelineFor 以函数注入，可在定义前用闭包延后调用。
 */
export function useHunt({
  error,
  agents,
  labels = {},
  setModule,
  openEvent,
  openHost,
  openTimelineFor,
} = {}) {
  const huntQ = ref('')
  const huntHits = ref([])
  const huntBusy = ref(false)
  const huntDone = ref(false)
  const requests = latestRequest()

  async function runHunt() {
    const q = String(huntQ.value || '').trim()
    const current = requests.begin()
    const matches = () => current() && String(huntQ.value || '').trim() === q
    if (q.length < 2) {
      huntBusy.value = false
      if (error) error.value = '请输入至少 2 个字符'
      return
    }
    huntBusy.value = true
    huntDone.value = false
    try {
      const r = await huntAgents(q, 120)
      if (!matches()) return
      huntHits.value = r?.items || []
      huntDone.value = true
    } catch (e) {
      if (matches() && error) error.value = e?.message || String(e)
    } finally {
      if (current()) huntBusy.value = false
    }
  }

  function openHuntHit(h) {
    if (h?.source === 'event' && h.id) {
      openEvent?.({
        id: h.id,
        agent_id: h.agent_id,
        title: h.title,
        module: h.module,
        severity: h.severity,
      })
      return
    }
    const a = (agents?.value || []).find((x) => x.agent_id === h.agent_id)
    if (a && h.module && labels[h.module]) {
      setModule?.(h.module)
      openHost?.(a, 'hosts')
    } else if (h?.agent_id) {
      openTimelineFor?.(h.agent_id)
    }
  }

  return {
    huntQ,
    huntHits,
    huntBusy,
    huntDone,
    runHunt,
    openHuntHit,
  }
}
