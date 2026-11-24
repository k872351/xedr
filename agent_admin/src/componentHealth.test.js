import { test } from 'node:test'
import assert from 'node:assert/strict'
import { componentHealthChips } from './componentHealth.js'

test('unreported status is unknown and latest report wins', () => {
  const rows = componentHealthChips({ health: { components: [
    { name: 'example', state: 'OK' },
    { name: 'example', state: 'OFF', message: 'disabled' },
    { name: 'unknown' },
    null,
  ] } })
  assert.equal(rows.length, 2)
  assert.equal(rows[0].state, 'OFF')
  assert.equal(rows[1].state, 'UNKNOWN')
  assert.deepEqual(componentHealthChips({}), [])
})

test('inventory module health is included with per-component resource estimates', () => {
  const rows = componentHealthChips({ health: { inventory_components: [
    { name: 'inventory_process', state: 'OK', message: 'collected 12 items', resource_usage: { calls_total: 2 } },
  ] } })
  assert.equal(rows.length, 1)
  assert.equal(rows[0].state, 'OK')
  assert.equal(rows[0].resourceUsage.calls_total, 2)
})
