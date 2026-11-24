// Separate transport state, collection evidence, data gaps and policy evidence.
export function hostEvidenceStatus(agent) {
  const health = agent?.health || {}
  const inventory = Object.values(health.inventory_quality || {})
  const capture = Object.values(health.capture_quality || {})
  const counters = ['buffer_dropped', 'rate_limited', 'durability_unconfirmed', 'bookmark_gap', 'notification_gap', 'read_failed', 'cursor_commit_failed', 'queue_full', 'expired']
  const gap = capture.some(row => counters.some(key => Number(row?.[key]) > 0)) || inventory.some(row => row?.possible_truncation || ['failed', 'possible_truncation'].includes(row?.status)) || Number(health.outbox?.dropped) > 0
  const hasEvidence = inventory.length > 0 || capture.length > 0 || !!health.outbox
  const latest = [agent?.last_telemetry_at, ...inventory.map(row => row?.last_success_at)].filter(Boolean).sort().at(-1)
  const policy = health.policy || {}
  const fleet = health.fleet || {}
  const state = String(policy.status || '')
  const policyText = ({ rejected: '策略拒绝', rolled_back: '已回滚', probation: '试用中' })[state] || (fleet.policy_applied === true ? '策略及同步已确认' : fleet.policy_applied === false ? '尚未完全收敛' : '状态未知')
  return [
    { key: 'connection', label: '连接', value: agent?.revoked ? '凭据已吊销' : agent?.online === true ? '在线' : agent?.last_heartbeat_at ? '心跳超时或离线' : '尚无心跳', detail: agent?.last_heartbeat_at || '—' },
    { key: 'collection', label: '最近采集', value: latest || '尚无采集证据', detail: agent?.telemetry_received === true ? '服务端已接收遥测' : '服务端尚无接收确认' },
    { key: 'integrity', label: '数据完整度', value: gap ? '存在已报告缺口' : hasEvidence && !health.health_truncated ? '未报告缺口' : '证据不足', detail: '未报告缺口不等于全量采集' },
    { key: 'policy', label: '策略生效', value: policyText, detail: policy.error || (policy.applied_rev != null ? `rev ${policy.applied_rev}` : '—') },
  ]
}
