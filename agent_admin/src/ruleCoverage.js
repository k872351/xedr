/** 规则覆盖率五态展示辅助。 */

export const RULE_COVERAGE_ORDER = [
  'imported',
  'compilable',
  'fields_complete',
  'replayed',
  'production_hit',
]

export const RULE_COVERAGE_LABELS = {
  imported: '已导入',
  compilable: '可编译',
  fields_complete: '字段齐全',
  replayed: '已回放',
  production_hit: '生产有命中',
}

export function ruleCoverageChips(coverage) {
  const states = Array.isArray(coverage?.states) ? coverage.states : null
  if (states?.length) {
    return states.map((s) => ({
      key: s.key,
      label: s.label || RULE_COVERAGE_LABELS[s.key] || s.key,
      count: Number(s.count) || 0,
    }))
  }
  const ladder = coverage?.ladder || {}
  return RULE_COVERAGE_ORDER.map((key) => ({
    key,
    label: (coverage?.labels && coverage.labels[key]) || RULE_COVERAGE_LABELS[key] || key,
    count: Number(ladder[key]) || 0,
  }))
}
