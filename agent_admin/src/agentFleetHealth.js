/** 终端健康 / 采集面板纯函数（从 App.vue 抽出，与备份版行为对齐）。 */

export const POLICY_STATUS_LABELS = {
  applied: '已应用',
  rejected: '已拒绝',
  pending: '待应用',
  rolled_back: '已回滚',
  unchanged: '未变',
}

export function healthChips(a, policyStatusLabels = POLICY_STATUS_LABELS) {
  const h = a?.health || {}
  if (!h || !Object.keys(h).length) return []
  const o = h.outbox || {}
  const chips = []
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
    const st = policyStatusLabels[pol.status] || pol.status
    chips.push({ k: '策略', v: `rev ${pol.applied_rev || '—'} · ${st}`, warn: pol.status === 'rejected' || pol.status === 'rolled_back', title: pol.error || '' })
  }
  const cs = h.sensors?.capture_status || h.capture_status
  if (cs && typeof cs === 'object') {
    if (cs.entities_rev != null) chips.push({ k: '实体 rev', v: String(cs.entities_rev), warn: false })
  }
  return chips
}

export function captureStatusOf(agent) {
  const h = agent?.health || {}
  return h.sensors?.capture_status || h.capture_status || {}
}

export function hostSensorsPanel(agent) {
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
  const cs = captureStatusOf(agent)
  const statusChips = []
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
  if (s.elastic_parity?.defend_kernel_tier === false) {
    statusChips.push({ label: '非 Defend 内核档', title: '对齐 Elastic Agent 编排，非 Defend 内核传感器' })
  }
  let channelChips = []
  const manifest = s.winevent_manifest
  if (Array.isArray(manifest) && manifest.length) channelChips = manifest.slice(0, 16)
  else if (typeof s.winevent_channels === 'number' && s.winevent_channels > 0) {
    channelChips = [`${s.winevent_channels} 通道`]
  }
  return {
    score: ch.score ?? null,
    level: ch.level || 'good',
    advise: ch.advise || [],
    pipeline: [pipe.primary, pipe.secondary].filter(Boolean).join('+') || s.etw || '—',
    cmdFill: tele.proc_cmd_fill_pct,
    disks: diskLine,
    byKind,
    byKindLine,
    netIo: net,
    netLine,
    parity: s.elastic_parity || null,
    statusChips,
    channelChips,
  }
}

export function captureCaptureHint(agent) {
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
  parts.push(cs.sysmon_present ? 'Sysmon 已装' : '未检测到 Sysmon')
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

export function hostQuickStats(agent) {
  return healthChips(agent).filter((c) => ['CPU', '内存', '待发队列', '已丢弃', '被拒', '时钟偏差'].includes(c.k))
}
