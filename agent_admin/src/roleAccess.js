/** EDR 三角色能力说明与前端门禁（与 backend/edr_auth.ROLES 对齐）。 */

export const ROLE_LABELS = {
  admin: '管理员',
  analyst: '分析员',
  readonly: '只读',
}

/** 能力矩阵：用于账号页展示；前端门禁用下方 helpers。 */
export const ROLE_MATRIX = [
  { id: 'view', label: '查看告警 / 终端 / 情报 / 审计', admin: true, analyst: true, readonly: true },
  { id: 'hunt', label: '调查、狩猎、智能分析', admin: true, analyst: true, readonly: true },
  { id: 'respond', label: '处置下发（结束进程 / 隔离等）', admin: '直发', analyst: '进审批', readonly: false },
  { id: 'approve', label: '审批高危处置', admin: true, analyst: false, readonly: false },
  { id: 'rules', label: '改规则 / 白名单 / 行为序列', admin: true, analyst: false, readonly: false },
  { id: 'policy', label: '改 EDR 策略 / 通知 / 存储', admin: true, analyst: false, readonly: false },
  { id: 'ioc_write', label: '维护本地自定义 IOC', admin: true, analyst: false, readonly: false },
  { id: 'deploy', label: '安装包 / 灰度升级', admin: true, analyst: false, readonly: false },
  { id: 'accounts', label: '账号管理', admin: true, analyst: false, readonly: false },
]

export function normalizeRole(role) {
  const r = String(role || '').trim().toLowerCase()
  return r === 'admin' || r === 'analyst' || r === 'readonly' ? r : 'readonly'
}

export function isAdminRole(role) {
  return normalizeRole(role) === 'admin'
}

export function canRespondRole(role) {
  const r = normalizeRole(role)
  return r === 'admin' || r === 'analyst'
}

export function canManageConfigRole(role) {
  return normalizeRole(role) === 'admin'
}

export function roleLabel(role) {
  const r = normalizeRole(role)
  return ROLE_LABELS[r] || r
}
