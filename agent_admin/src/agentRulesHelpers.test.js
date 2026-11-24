import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  isAbfileRule, isElasticRule, filterAgentRules, filterSettingsRules, groupAgentRules,
  isLinuxRule, linuxRuleCountsOf, ruleBulkTargets,
} from './agentRulesHelpers.js'
import { looksBadName, ancestorChainFromTree, ancestorChainFromEvidence } from './threatChainHelpers.js'
import { ruleCoverageChips } from './ruleCoverage.js'

test('classifies abfile / elastic', () => {
  assert.equal(isAbfileRule({ category: 'abfile' }), true)
  assert.equal(isElasticRule({ source: 'elastic' }), true)
  assert.equal(isElasticRule({ note: 'Elastic: foo' }), true)
})

test('filters and groups agent rules', () => {
  const rules = [
    { id: 'a', builtin: true },
    { id: 'b', source: 'custom' },
    { id: 'linux-x', note: 'Elastic: linux/foo' },
    { id: 'ab', category: 'abfile' },
  ]
  assert.equal(filterAgentRules(rules, 'sensor').length, 1)
  // abfile 规则从检测规则列表剥离，单独进「异常文件」页签
  assert.equal(filterAgentRules(rules, 'all').length, 3)
  assert.equal(rules.filter(isAbfileRule).length, 1)
  assert.ok(groupAgentRules(filterAgentRules(rules, 'all')).length > 0)
  assert.equal(linuxRuleCountsOf(rules).total, 1)
})

test('Windows and Linux filters separate existing snapshot and EVM rules without duplication', () => {
  const rules = [
    { id: 'sensor-win', builtin: true },
    { id: 'legacy-windows', source: 'custom' },
    { id: 'agent-linux-temp-exec', source: 'custom' },
    { id: 'elastic-example-linux.evm', source: 'elastic', rule_channel: 'evm' },
    { id: 'import-by-note', note: 'Elastic: linux/example' },
    { id: 'explicit-platform', os: ' Linux ' },
  ]
  const windows = ['legacy-windows']
  const linux = rules.slice(2).map(r => r.id)
  for (const filter of [filterAgentRules, filterSettingsRules]) {
    assert.deepEqual(filter(rules, 'windows').map(r => r.id), windows)
    assert.deepEqual(filter(rules, 'linux').map(r => r.id), linux)
  }
  const groups = groupAgentRules(filterAgentRules(rules, 'all'))
  assert.deepEqual(groups.map(g => g.key), ['general', 'linux'])
  assert.deepEqual(groups.flatMap(g => g.rows.map(r => r.id)), rules.map(r => r.id))
  assert.deepEqual(linuxRuleCountsOf(rules), { total: 4, evm: 1, agent: 3 })
  assert.equal(isLinuxRule({ id: 'windows-rule-mentions-linux', platform: 'windows' }), false)
  assert.deepEqual(ruleBulkTargets(filterAgentRules(rules, 'linux')), {
    snapshotIds: ['agent-linux-temp-exec', 'import-by-note', 'explicit-platform'],
    evmIds: ['elastic-example-linux.evm'],
  })
})

test('looksBadName and ancestor chain helpers', () => {
  assert.equal(looksBadName('Program Files'), true)
  assert.equal(looksBadName('cmd.exe'), false)
  const chain = ancestorChainFromTree({
    hit_id: 'c',
    nodes: [
      { id: 'a', parent_id: '' },
      { id: 'b', parent_id: 'a' },
      { id: 'c', parent_id: 'b', is_hit: true },
    ],
  })
  assert.deepEqual(chain.map((n) => n.id), ['a', 'b', 'c'])
  const evChain = ancestorChainFromEvidence({
    flat: { pid: 2, ppid: 1, parent_name: 'explorer.exe' },
    ev: {},
    name: 'cmd.exe',
    path: 'C:\\Windows\\System32\\cmd.exe',
  })
  assert.equal(evChain.length, 2)
  assert.equal(evChain[1].is_hit, true)
})

test('rule coverage chips', () => {
  const chips = ruleCoverageChips({
    states: [{ key: 'imported', label: '已导入', count: 3 }],
  })
  assert.equal(chips[0].count, 3)
})
