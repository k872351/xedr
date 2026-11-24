const labels = {
  OK: '已报告正常',
  OFF: '未启用或不可用',
  DISABLED: '未启用',
  DEGRADED: '降级',
  FAILED: '初始化失败',
  UNSUPPORTED: '平台不支持',
  UNAUTHORIZED: '策略未授权',
  STARTING: '初始化中',
  UNKNOWN: '状态未知',
}

export function componentHealthChips(agent) {
  const health = agent?.health || {}
  const raw = [
    ...(Array.isArray(health.components) ? health.components : []),
    ...(Array.isArray(health.sensors?.components) ? health.sensors.components : []),
    ...(Array.isArray(health.inventory_components) ? health.inventory_components : []),
  ]
  const rows = new Map()
  for (const component of raw) {
    if (!component || typeof component !== 'object') continue
    const k = String(component.name || component.k || '').trim()
    if (!k) continue
    const reported = String(component.state || '').toUpperCase()
    const state = Object.hasOwn(labels, reported) ? reported : 'UNKNOWN'
    rows.set(k, { k, state, label: labels[state], message: String(component.message || ''), observedAt: String(component.observed_at || ''), resourceUsage: component.resource_usage || null })
  }
  return [...rows.values()]
}

const capStatusLabels = {
  running: '已支持且运行中',
  built_disabled: '已支持但未编入/未启用',
  init_failed: '已支持但初始化失败',
  os_unsupported: '当前操作系统不支持',
  policy_denied: '当前策略未授权',
}

/** 能力五态：来自 heartbeat health.capability_status */
export function capabilityStatusChips(agent) {
  const raw = agent?.health?.capability_status
  if (!Array.isArray(raw) || !raw.length) return []
  return raw.map((row) => {
    const id = String(row?.id || '').trim()
    const status = String(row?.status || 'running').toLowerCase()
    return {
      id,
      status,
      label: capStatusLabels[status] || status,
      message: String(row?.message || ''),
      warn: status !== 'running',
    }
  }).filter((r) => r.id)
}
