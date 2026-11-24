/** Agent 规则分类 / 过滤纯函数（从 App.vue 抽出）。 */

export function isAbfileRule(r) {
  return !!(r && (r.abfile === true || String(r.category || '').toLowerCase() === 'abfile'))
}

export function isEvmDisplayRule(r) {
  return String(r?.rule_channel || '').toLowerCase() === 'evm' || /\.(evm|fim)$/i.test(String(r?.id || ''))
}

export function isLinuxRule(r) {
  if (!r) return false
  const id = String(r.id || '').toLowerCase()
  const note = String(r.note || '').toLowerCase()
  const platform = String(r.platform || r.os || '').trim().toLowerCase()
  if (platform === 'linux') return true
  if (platform === 'windows' || platform === 'macos') return false
  return /(?:^|[-_.])linux(?:$|[-_.])/.test(id) || /elastic(?: evm)?:\s*linux\//.test(note)
}

export function isLinuxEvmRule(r) {
  return isLinuxRule(r) && isEvmDisplayRule(r)
}

export function isElasticRule(r) {
  if (!r) return false
  if (r.source === 'elastic') return true
  const id = String(r.id || '')
  if (id.startsWith('elastic-')) return true
  if (r.elastic_rule_id) return true
  const note = String(r.note || '')
  return note.startsWith('Elastic:') || note.startsWith('Elastic EVM')
}

export function linuxRuleCountsOf(agentRules) {
  const rules = (agentRules || []).filter(isLinuxRule)
  const evm = rules.filter((r) => isLinuxEvmRule(r)).length
  return { total: rules.length, evm, agent: rules.length - evm }
}

export function filterAgentRules(agentRules, rulesFilter) {
  // 异常文件规则有独立 Tab，不混入检出规则列表
  const all = (agentRules || []).filter((r) => !isAbfileRule(r))
  if (rulesFilter === 'linux') return all.filter((r) => isLinuxRule(r))
  if (rulesFilter === 'sensor') return all.filter((r) => r.builtin || r.source === 'sensor')
  if (rulesFilter === 'windows') return all.filter((r) => !isLinuxRule(r) && !(r.builtin || r.source === 'sensor'))
  if (rulesFilter === 'elastic') return all.filter((r) => isElasticRule(r))
  return all
}

export function groupAgentRules(filteredRows) {
  return [
    { key: 'general', label: 'Windows / 通用规则', rows: filteredRows.filter((r) => !isLinuxRule(r)) },
    { key: 'linux', label: 'Linux 规则', rows: filteredRows.filter(isLinuxRule) },
  ].filter((group) => group.rows.length)
}

export function filterSettingsRules(ruleStatsItems, settingsRulesFilter) {
  const all = ruleStatsItems || []
  if (settingsRulesFilter === 'linux') return all.filter(isLinuxRule)
  if (settingsRulesFilter === 'sensor') return all.filter((r) => r.builtin || r.source === 'sensor')
  if (settingsRulesFilter === 'windows') return all.filter((r) => !isLinuxRule(r) && !(r.builtin || r.source === 'sensor'))
  return all
}

export function ruleBulkTargets(rows) {
  const snapshotIds = []
  const evmIds = []
  for (const rule of rows || []) {
    if (!rule?.id) continue
    const ids = isElasticRule(rule) && isEvmDisplayRule(rule) ? evmIds : snapshotIds
    ids.push(rule.id)
  }
  return { snapshotIds, evmIds }
}
