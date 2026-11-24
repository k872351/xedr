import { computed } from 'vue'
import { short } from '../consoleDisplay.js'

// Existing dashboard display metrics; no fetching or changes to source records.
export function useOverviewDisplay({ agents, allEvents, overviewStats }) {
  const onlineCount = computed(() => agents.value.filter((a) => a.online).length)
  /** 概览顶栏终端数以实时 agents 为准（overviewStats 仅定时刷新，避免新上线主机要手动 F5） */
  const ovAgentTotal = computed(() => agents.value.length)
  
  function sparklinePoints(buckets, w = 120, h = 32) {
    const arr = Array.isArray(buckets) ? buckets : []
    if (!arr.length) return ''
    const max = Math.max(...arr, 1)
    return arr
      .map((v, i) => {
        const x = (i / Math.max(arr.length - 1, 1)) * w
        const y = h - (Number(v) / max) * (h - 6) - 3
        return `${x.toFixed(1)},${y.toFixed(1)}`
      })
      .join(' ')
  }
  const overviewSparkTl = computed(() => sparklinePoints(overviewStats.value?.timeline_24h?.buckets))
  const overviewSparkDns = computed(() => sparklinePoints(overviewStats.value?.dns_24h?.buckets))
  const overviewTopMalware = computed(() => overviewStats.value?.threats?.top_malware || [])

  /** 仅统计仍在册终端的告警，避免删除终端后概览残留 */
  const knownAgentIds = computed(() => new Set((agents.value || []).map((a) => a.agent_id).filter(Boolean)))
  const liveEvents = computed(() => {
    const known = knownAgentIds.value
    if (!known.size) return []
    return (allEvents.value || []).filter((e) => known.has(e.agent_id))
  })

  const recentThreats = computed(() => liveEvents.value.slice(0, 8))
  const ovStatus = computed(() => {
    const out = { open: 0, closed: 0, ignored: 0 }
    for (const e of liveEvents.value) out[e.status in out ? e.status : 'open'] += 1
    return out
  })
  const ovSevDist = computed(() => {
    const defs = [['critical', '严重'], ['high', '高危'], ['medium', '中危'], ['low', '低危'], ['info', '信息']]
    const cnt = Object.fromEntries(defs.map(([k]) => [k, 0]))
    for (const e of liveEvents.value) if (e.severity in cnt) cnt[e.severity] += 1
    const max = Math.max(1, ...Object.values(cnt))
    return defs.map(([key, label]) => ({ key, label, count: cnt[key], pct: Math.round((cnt[key] / max) * 100) }))
  })
  const ovTrend = computed(() => {
    const days = []
    const now = new Date()
    for (let i = 6; i >= 0; i -= 1) {
      const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i)
      const day = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
      days.push({ day, label: `${d.getMonth() + 1}/${d.getDate()}`, count: 0, high: 0 })
    }
    const idx = Object.fromEntries(days.map((d, i) => [d.day, i]))
    let total = 0
    for (const e of liveEvents.value) {
      const i = idx[String(e.created_at || '').slice(0, 10)]
      if (i == null) continue
      days[i].count += 1
      total += 1
      if (e.severity === 'high' || e.severity === 'critical') days[i].high += 1
    }
    const max = Math.max(1, ...days.map((d) => d.count))
    return { total, days: days.map((d) => ({ ...d, pct: Math.round((d.count / max) * 100), hpct: Math.round((d.high / max) * 100) })) }
  })
  const ovTopHosts = computed(() => {
    const m = new Map()
    for (const e of liveEvents.value) {
      const r = m.get(e.agent_id) || { agent_id: e.agent_id, hostname: e.hostname || short(e.agent_id), count: 0, high: 0 }
      r.count += 1
      if (e.severity === 'high' || e.severity === 'critical') r.high += 1
      m.set(e.agent_id, r)
    }
    return [...m.values()].sort((a, b) => b.high - a.high || b.count - a.count).slice(0, 5)
  })
  return { onlineCount, ovAgentTotal, overviewSparkTl, overviewSparkDns, overviewTopMalware, recentThreats, ovStatus, ovSevDist, ovTrend, ovTopHosts }
}
