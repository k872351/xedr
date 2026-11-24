// Display-only reference budgets; these do not change endpoint policy.
export const RESOURCE_BUDGETS = [
  { key: 'cpu_pct', label: 'CPU', limit: 5, unit: '%' },
  { key: 'rss_mb', label: '内存', limit: 250, unit: ' MB' },
]

export function resourceBudgetRows(health) {
  return RESOURCE_BUDGETS.map(budget => {
    const raw = health?.[budget.key]
    const number = raw == null || typeof raw === 'boolean' ||
      (typeof raw === 'string' && !raw.trim()) ? NaN : Number(raw)
    const value = Number.isFinite(number) && number >= 0 &&
      (budget.key !== 'cpu_pct' || number <= 100) ? number : null
    const state = value == null ? 'unknown' : value > budget.limit ? 'above' : 'within'
    return { ...budget, value, state }
  })
}

export function diagnosticTimingRows(health) {
  const values = health?.diagnostic_timings || {}
  return [
    { key: 'process_resources', label: '进程资源诊断' },
    { key: 'go_runtime', label: 'Go 运行时诊断' },
  ].map(item => {
    const raw = values[item.key]
    const elapsed = raw?.available === true && typeof raw.elapsed_us === 'number' &&
      Number.isFinite(raw.elapsed_us) && raw.elapsed_us >= 0 ? raw.elapsed_us : null
    return { ...item, elapsed }
  })
}
