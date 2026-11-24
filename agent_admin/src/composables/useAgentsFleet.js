import { computed, ref, watch } from 'vue'
import { paginateSections } from '../sectionPagination.js'
import { componentHealthChips } from '../componentHealth.js'
import { assignAgentGroup, listAgentGroups } from '../api.js'

const POLICY_STATUS_LABELS = {
  applied: '已应用',
  rejected: '已拒绝',
  pending: '待应用',
  rolled_back: '已回滚',
  unchanged: '未变',
}

export { POLICY_STATUS_LABELS }

/** 终端舰队：列表筛选、分组、健康芯片与主机传感器面板。 */
export function useAgentsFleet({
  agents,
  q,
  error,
  okMsg,
  isAdmin,
  short = (id) => String(id || '').slice(0, 8),
} = {}) {
  const groupItems = ref([])
  const hostGroupFilter = ref('')
  const hostPage = ref(1)
  const hostPageSize = ref(50)
  const hostHdrMore = ref(false)
  const hostHealthOpen = ref(false)
  const groupBusy = ref(false)
  const groupEditId = ref('')
  const groupName = ref('')
  const groupNote = ref('')
  const groupIds = ref('')
  const groupPickedIds = ref([])
  const groupPickOnlineOnly = ref(false)

  function groupsOfAgent(agentId) {
    const id = String(agentId || '')
    return (groupItems.value || []).filter((g) => (g.agent_ids || []).map(String).includes(id))
  }

  function agentGroupLabel(agentId) {
    const gs = groupsOfAgent(agentId)
    return gs.length ? gs.map((g) => g.name).join('、') : '未分组'
  }

  const filteredAgents = computed(() => {
    let list = agents?.value || []
    const gf = hostGroupFilter.value
    if (gf === '__none__') {
      list = list.filter((a) => !groupsOfAgent(a.agent_id).length)
    } else if (gf) {
      const g = (groupItems.value || []).find((x) => String(x.id) === String(gf))
      const ids = new Set((g?.agent_ids || []).map(String))
      list = list.filter((a) => ids.has(String(a.agent_id)))
    }
    const s = String(q?.value || '').trim().toLowerCase()
    if (!s) return list
    return list.filter((a) => `${a.hostname || ''} ${a.ip || ''} ${a.agent_id || ''} ${agentGroupLabel(a.agent_id)}`.toLowerCase().includes(s))
  })

  const hostSections = computed(() => {
    const list = filteredAgents.value
    if (hostGroupFilter.value) {
      const name = hostGroupFilter.value === '__none__'
        ? '未分组'
        : ((groupItems.value || []).find((g) => String(g.id) === String(hostGroupFilter.value))?.name || '分组')
      return [{ key: hostGroupFilter.value, name, agents: list }]
    }
    if (!(groupItems.value || []).length) {
      return [{ key: 'all', name: '全部终端', agents: list }]
    }
    const secs = []
    for (const g of groupItems.value || []) {
      const ids = new Set((g.agent_ids || []).map(String))
      const agentsIn = list.filter((a) => ids.has(String(a.agent_id)))
      if (agentsIn.length) secs.push({ key: String(g.id), name: g.name, agents: agentsIn })
    }
    const rest = list.filter((a) => !groupsOfAgent(a.agent_id).length)
    if (rest.length) secs.push({ key: '__none__', name: '未分组', agents: rest })
    return secs.length ? secs : [{ key: 'all', name: '全部终端', agents: list }]
  })

  const hostPageData = computed(() => paginateSections(hostSections.value, hostPage.value, hostPageSize.value))
  watch([() => q?.value, hostGroupFilter, hostPageSize], () => { hostPage.value = 1 })
  watch(() => hostPageData.value.page, (value) => { hostPage.value = value })

  function agentPrimaryGroupId(agentId) {
    const g = groupsOfAgent(agentId)[0]
    return g ? String(g.id) : ''
  }

  async function onHostGroupChange(agent, groupId) {
    if (!isAdmin?.value) {
      if (error) error.value = '仅管理员可更改分组'
      return
    }
    const aid = agent?.agent_id
    if (!aid) return
    const prev = agentPrimaryGroupId(aid)
    const next = String(groupId || '')
    if (prev === next) return
    groupBusy.value = true
    try {
      await assignAgentGroup(aid, next)
      await loadGroups()
      const gname = next
        ? ((groupItems.value || []).find((g) => String(g.id) === next)?.name || '目标分组')
        : '未分组'
      if (okMsg) {
        okMsg.value = `「${agent.hostname || short(aid)}」已${next ? `移入「${gname}」` : '移出分组'}`
        setTimeout(() => { if (okMsg.value) okMsg.value = '' }, 2200)
      }
    } catch (e) {
      if (error) error.value = e?.message || String(e)
    } finally {
      groupBusy.value = false
    }
  }

  async function loadGroups() {
    try {
      const r = await listAgentGroups()
      groupItems.value = r?.items || []
    } catch (e) {
      if (error) error.value = e?.message || String(e)
    }
  }

  const groupPickAgents = computed(() => {
    let list = agents?.value || []
    if (groupPickOnlineOnly.value) list = list.filter((a) => a.online)
    return list
  })

  function agentOnline(agentId) {
    return !!(agents?.value || []).find((a) => String(a.agent_id) === String(agentId) && a.online)
  }

  function agentHostLabel(agentId) {
    const a = (agents?.value || []).find((x) => String(x.agent_id) === String(agentId))
    if (!a) return short(agentId)
    return a.hostname ? `${a.hostname}（${a.ip || short(agentId)}）` : (a.ip || short(agentId))
  }

  function isGroupHostPicked(agentId) {
    const id = String(agentId || '')
    return (groupPickedIds.value || []).map(String).includes(id)
  }

  function toggleGroupHost(agentId, on) {
    const id = String(agentId || '')
    const set = new Set((groupPickedIds.value || []).map(String))
    if (on) set.add(id)
    else set.delete(id)
    groupPickedIds.value = [...set]
  }

  function selectAllGroupHosts(on) {
    groupPickedIds.value = on ? groupPickAgents.value.map((a) => String(a.agent_id)) : []
  }

  function resetGroupForm() {
    groupEditId.value = ''
    groupName.value = ''
    groupNote.value = ''
    groupIds.value = ''
    groupPickedIds.value = []
  }

  function selectHostGroup(gid) {
    hostGroupFilter.value = String(gid || '')
    hostPage.value = 1
  }

  function healthChips(a) {
    const h = a?.health || {}
    if (!h || !Object.keys(h).length) return []
    const o = h.outbox || {}
    const chips = []
    if (h.resource_metrics_platform && h.resource_metrics_platform !== 'windows') {
      const label = h.resource_metrics_platform === 'linux' ? 'Linux /proc' : '平台基础指标'
      chips.push({ k: '资源指标', v: label, warn: false })
    }
    if (h.cpu_pct != null) chips.push({ k: 'CPU', v: `${Number(h.cpu_pct).toFixed(1)}%`, warn: h.cpu_pct > 5 })
    if (h.rss_mb != null) chips.push({ k: '内存', v: `${Number(h.rss_mb).toFixed(0)} MB`, warn: h.rss_mb > 250 })
    if (o.depth != null) chips.push({ k: '待发队列', v: `${o.depth}`, warn: o.depth > 5000 })
    if (o.dropped) chips.push({ k: '已丢弃', v: `${o.dropped}`, warn: true })
    if (o.rejected) chips.push({ k: '被拒', v: `${o.rejected}`, warn: true })
    if (h.protocol) chips.push({ k: '协议', v: `v${h.protocol}`, warn: false })
    if (h.auth) chips.push({ k: '鉴权', v: h.auth === 'agent_secret' ? '专属凭据' : '共享密钥', warn: h.auth !== 'agent_secret' })
    if (a?.clock_skew_sec != null && Math.abs(a.clock_skew_sec) > 60) chips.push({ k: '时钟偏差', v: `${Math.round(a.clock_skew_sec)}s`, warn: true })
    const pol = h.policy
    if (pol && typeof pol === 'object') {
      const st = POLICY_STATUS_LABELS[pol.status] || pol.status
      chips.push({ k: '策略', v: `rev ${pol.applied_rev || '—'} · ${st}`, warn: pol.status === 'rejected' || pol.status === 'rolled_back', title: pol.error || '' })
    }
    const cs = h.sensors?.capture_status || h.capture_status
    if (cs && typeof cs === 'object') {
      if (cs.entities_rev != null) chips.push({ k: '实体 rev', v: String(cs.entities_rev), warn: false })
    }
    return chips
  }

  function captureStatusOf(agent) {
    const h = agent?.health || {}
    return h.sensors?.capture_status || h.capture_status || {}
  }

  function hostSensorsPanel(agent) {
    const s = agent?.health?.sensors || {}
    const ch = s.capture_health || {}
    const pipe = s.sensor_pipeline || {}
    const tele = s.telemetry || {}
    const disks = s.host_metrics?.disks
    let diskLine = ''
    if (Array.isArray(disks) && disks.length) {
      const worst = disks.reduce((a, b) => ((a?.used_pct || 0) > (b?.used_pct || 0) ? a : b))
      if (worst?.mount) diskLine = `${worst.mount}${worst.used_pct}%`
    }
    const outbox = agent?.health?.outbox || {}
    const byKind = outbox.by_kind || s.outbox?.by_kind || null
    let byKindLine = ''
    if (byKind && typeof byKind === 'object') {
      byKindLine = Object.entries(byKind)
        .sort((a, b) => (b[1] || 0) - (a[1] || 0))
        .slice(0, 6)
        .map(([k, v]) => `${k}:${v}`)
        .join(' ')
    }
    const net = s.host_metrics?.net_io || {}
    let netLine = ''
    if (net.nic_in_bytes != null || net.nic_out_bytes != null) {
      const fmt = (n) => {
        const x = Number(n) || 0
        if (x > 1e9) return `${(x / 1e9).toFixed(1)}G`
        if (x > 1e6) return `${(x / 1e6).toFixed(1)}M`
        if (x > 1e3) return `${(x / 1e3).toFixed(0)}K`
        return String(x)
      }
      netLine = `NIC ↓${fmt(net.nic_in_bytes)} ↑${fmt(net.nic_out_bytes)}`
    } else if (net.tcp_curr_estab != null) {
      netLine = `tcp estab ${net.tcp_curr_estab}`
    }
    const hostMetrics = s.host_metrics || {}
    const loadParts = [hostMetrics.load_avg_1, hostMetrics.load_avg_5, hostMetrics.load_avg_15]
    const loadLine = loadParts.every((v) => v != null)
      ? `系统负载 ${loadParts.map((v) => Number(v).toFixed(2)).join(' / ')}`
      : ''
    const hostMemory = hostMetrics.memory || {}
    const hostMemoryLine = hostMemory.used_pct != null
      ? `主机内存 ${Number(hostMemory.used_pct).toFixed(1)}%`
      : ''
    const cs = captureStatusOf(agent)
    const sm = cs?.sysmon || {}
    const statusChips = []
    const windowsCapture = cs?.platform !== 'non-windows'
    if (!windowsCapture) statusChips.push({ label: 'Windows 采集指标不适用', title: '当前平台不是 Windows' })
    if (windowsCapture) {
      if (cs?.etw_session_ok) statusChips.push({ label: 'ETW 正常', ok: true })
      else if (cs && Object.keys(cs).length) statusChips.push({ label: 'ETW 回退 Winlog', warn: true })
      if (cs && Object.keys(cs).length) {
        statusChips.push(cs.audit_4688_enabled
          ? { label: '4688 已开', ok: true }
          : { label: '4688 未开', warn: true, title: '进程创建审计未开，命令行补全可能不足' })
        statusChips.push(cs.sysmon_present
          ? { label: 'Sysmon', ok: true }
          : { label: '无 Sysmon', title: '可选增强' })
      }
    }
    if (windowsCapture && s.elastic_parity?.defend_kernel_tier === false) {
      statusChips.push({ label: '非 Defend 内核档', title: '对齐 Elastic Agent 编排，非 Defend 内核传感器' })
    }
    let channelChips = []
    const manifest = s.winevent_manifest
    if (Array.isArray(manifest) && manifest.length) channelChips = manifest.slice(0, 16)
    else if (typeof s.winevent_channels === 'number' && s.winevent_channels > 0) {
      channelChips = [`${s.winevent_channels} 通道`]
    }
    const sysmonChips = []
    if (cs?.sysmon_present || sm.present || sm.installed) {
      const eids = Array.isArray(sm.subscribed_eids) ? sm.subscribed_eids : []
      if (eids.length) sysmonChips.push({ label: `EID ${eids.join(',')}`, title: '订阅的 Sysmon EventID' })
      if (sm.config_version || (sm.config_sha256 && String(sm.config_sha256).length >= 12)) {
        sysmonChips.push({
          label: `配置 ${sm.config_version || String(sm.config_sha256).slice(0, 12)}`,
          title: `config_source=${sm.config_source || '—'} sha256=${sm.config_sha256 || '—'}`,
        })
      }
      const collected = sm.events_collected ?? tele.events_sysmon
      if (collected != null) sysmonChips.push({ label: `采集 ${collected}`, title: '本进程累计 Sysmon 事件数' })
      if (sm.action) sysmonChips.push({ label: String(sm.action), title: sm.error || '' })
    }
    return {
      score: windowsCapture ? (ch.score ?? null) : null,
      level: windowsCapture ? (ch.level || 'unknown') : 'unsupported',
      advise: ch.advise || [],
      pipeline: [pipe.primary, pipe.secondary].filter(Boolean).join('+') || s.etw || '—',
      cmdFill: tele.proc_cmd_fill_pct,
      disks: diskLine,
      loadLine,
      hostMemoryLine,
      byKind,
      byKindLine,
      netIo: net,
      netLine,
      parity: s.elastic_parity || null,
      statusChips,
      channelChips,
      sysmonChips,
    }
  }

  function captureCaptureHint(agent) {
    const cs = captureStatusOf(agent)
    if (!cs || !Object.keys(cs).length) return ''
    const parts = []
    const pipe = agent?.health?.sensors?.sensor_pipeline || agent?.health?.fleet?.sensor_pipeline
    if (pipe?.primary) parts.push(`主:${pipe.primary}`)
    if (pipe?.secondary) parts.push(`辅:${pipe.secondary}`)
    const tele = agent?.health?.sensors?.telemetry || agent?.health?.fleet?.telemetry
    if (tele?.proc_cmd_fill_pct != null) parts.push(`cmd填充 ${tele.proc_cmd_fill_pct}%`)
    if (cs.etw_session_ok) parts.push('ETW 正常')
    else parts.push('ETW 未就绪，Winlog 补偿')
    parts.push(cs.audit_4688_enabled ? '4688 审计已开' : '4688 未开')
    if (cs.sysmon_present) {
      const act = cs.sysmon?.action ? `（${cs.sysmon.action}）` : ''
      parts.push(`Sysmon 已装${act}`)
    } else {
      parts.push(cs.sysmon?.action === 'need_binary' ? '缺 Sysmon64.exe' : '未检测到 Sysmon')
    }
    const ch = agent?.health?.sensors?.winevent_channels
    if (ch) parts.push(`Winlog通道 ${ch}`)
    const manifest = agent?.health?.sensors?.winevent_manifest
    if (Array.isArray(manifest) && manifest.length) parts.push(manifest.join('+'))
    const disks = agent?.health?.sensors?.host_metrics?.disks
    if (Array.isArray(disks) && disks.length) {
      const worst = disks.reduce((a, b) => ((a?.used_pct || 0) > (b?.used_pct || 0) ? a : b))
      if (worst?.mount) parts.push(`盘 ${worst.mount} ${worst.used_pct}%`)
    }
    const ep = agent?.health?.sensors?.elastic_parity
    if (ep?.defend_kernel_tier === false) parts.push('非Defend内核档')
    return parts.join(' · ')
  }

  function componentWarnChips(agent) {
    return componentHealthChips(agent).filter((c) => ['DEGRADED', 'FAILED', 'UNAUTHORIZED'].includes(c.state))
  }

  function hostQuickStats(agent) {
    return healthChips(agent).filter((c) => ['CPU', '内存', '待发队列', '已丢弃', '被拒', '时钟偏差'].includes(c.k))
  }

  return {
    POLICY_STATUS_LABELS,
    groupItems,
    hostGroupFilter,
    hostPage,
    hostPageSize,
    hostHdrMore,
    hostHealthOpen,
    groupBusy,
    groupEditId,
    groupName,
    groupNote,
    groupIds,
    groupPickedIds,
    groupPickOnlineOnly,
    groupsOfAgent,
    agentGroupLabel,
    filteredAgents,
    hostSections,
    hostPageData,
    agentPrimaryGroupId,
    onHostGroupChange,
    loadGroups,
    groupPickAgents,
    agentOnline,
    agentHostLabel,
    isGroupHostPicked,
    toggleGroupHost,
    selectAllGroupHosts,
    resetGroupForm,
    selectHostGroup,
    healthChips,
    captureStatusOf,
    hostSensorsPanel,
    captureCaptureHint,
    componentWarnChips,
    hostQuickStats,
  }
}
