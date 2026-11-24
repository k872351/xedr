import { ref } from 'vue'
import { listAgentCommands } from '../api.js'

/**
 * 处置结果 / 指令回执轮询（审批列表已在 PlatformExtras / ApprovalsPage）。
 */
export function useResponseOps({
  activeEvent,
  page,
  error,
  actionLabel = (a) => a,
  cmdStatusLabel = (s) => s,
  friendlyCmdResult = () => '',
  onCommandNotify = null,
} = {}) {
  const respCommands = ref([])
  const respToast = ref(null)
  let respToastTimer = null
  let respToastCmdKey = ''
  let respPollTimer = null

  function dismissRespToast() {
    respToast.value = null
    if (respToastTimer) {
      clearTimeout(respToastTimer)
      respToastTimer = null
    }
  }

  function resetRespToastKey() {
    respToastCmdKey = ''
  }

  function showRespToast(cls, title, detail = '', { ms, sticky = false } = {}) {
    respToast.value = { cls, title, detail }
    if (respToastTimer) {
      clearTimeout(respToastTimer)
      respToastTimer = null
    }
    void sticky
    const waitMs = ms ?? (cls === 'err' ? 4000 : cls === 'ok' ? 2000 : 3000)
    respToastTimer = setTimeout(() => {
      respToast.value = null
      respToastTimer = null
    }, waitMs)
  }

  async function loadRespCommands({ announce = false } = {}) {
    const aid = activeEvent?.value?.agent_id
    if (!aid) return
    try {
      const r = await listAgentCommands(aid)
      respCommands.value = r?.items || []
      const latest = respCommands.value[0]
      if (!latest) return
      const key = `${latest.id}:${latest.status}`
      if (key === respToastCmdKey) return
      if (!announce) {
        respToastCmdKey = key
        return
      }
      if (latest.status === 'done') {
        respToastCmdKey = key
        showRespToast('ok', `${actionLabel(latest.action)} · 成功`, friendlyCmdResult(latest.action, latest.result_json), { ms: 2000 })
        try {
          onCommandNotify?.({
            commandId: latest.id,
            agentId: aid,
            eventId: activeEvent?.value?.id || null,
            action: latest.action,
            status: 'done',
            hostname: activeEvent?.value?.hostname || '',
            detail: friendlyCmdResult(latest.action, latest.result_json),
          })
        } catch { /* ignore */ }
      } else if (latest.status === 'failed') {
        respToastCmdKey = key
        showRespToast('err', `${actionLabel(latest.action)} · 失败`, friendlyCmdResult(latest.action, latest.result_json), { ms: 4000 })
        try {
          onCommandNotify?.({
            commandId: latest.id,
            agentId: aid,
            eventId: activeEvent?.value?.id || null,
            action: latest.action,
            status: 'failed',
            hostname: activeEvent?.value?.hostname || '',
            detail: friendlyCmdResult(latest.action, latest.result_json),
          })
        } catch { /* ignore */ }
      } else if (latest.status === 'pending' || latest.status === 'sent') {
        respToastCmdKey = key
        showRespToast(
          'wait',
          `${actionLabel(latest.action)} · ${cmdStatusLabel(latest.status)}`,
          '指令已入队，等终端心跳领取；可在「处置结果」查看进度',
          { ms: 3000 },
        )
      }
    } catch (e) {
      if (error) error.value = e?.message || String(e)
    }
  }

  function startRespPoll() {
    if (respPollTimer) clearInterval(respPollTimer)
    let ticks = 0
    respPollTimer = setInterval(async () => {
      if (page?.value !== 'threat-view' || !activeEvent?.value?.agent_id) {
        if (respPollTimer) { clearInterval(respPollTimer); respPollTimer = null }
        return
      }
      ticks += 1
      await loadRespCommands({ announce: true })
      const pending = respCommands.value.some((c) => c.status === 'pending' || c.status === 'sent')
      if ((!pending || ticks >= 48) && respPollTimer) {
        if (!pending && respToast.value?.cls === 'wait') dismissRespToast()
        clearInterval(respPollTimer)
        respPollTimer = null
      }
    }, 2500)
  }

  function stopRespPoll() {
    if (respPollTimer) {
      clearInterval(respPollTimer)
      respPollTimer = null
    }
    dismissRespToast()
  }

  return {
    respCommands,
    respToast,
    dismissRespToast,
    resetRespToastKey,
    showRespToast,
    loadRespCommands,
    startRespPoll,
    stopRespPoll,
  }
}
