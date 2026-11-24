import { test } from 'node:test'
import assert from 'node:assert/strict'
import { appendResourceSample, resourceSegments } from './resourceHistory.js'

test('history is bounded, deduplicated and separated by host', () => {
  let history = { id: null, rows: [] }
  for (let i = 0; i < 3; i++) {
    history = appendResourceSample(history, { agent_id: 'a', health_at: `2026-01-01T00:00:0${i}Z`, health: { cpu_pct: i } }, 2)
  }
  assert.deepEqual(history.rows.map(row => row.cpu), [1, 2])
  assert.equal(appendResourceSample(history, { agent_id: 'a', health_at: '2026-01-01T00:00:02Z' }), history)
  const next = appendResourceSample(history, { agent_id: 'b', health_at: '2026-01-01T00:00:02Z' })
  assert.equal(next.rows.length, 1)
  assert.equal(next.rows[0].cpu, null)
})

test('missing data breaks trend segments', () => {
  const rows = [{ time: 1, cpu: 0 }, { time: 2, cpu: null }, { time: 3, cpu: 100 }]
  assert.deepEqual(resourceSegments(rows, 'cpu', 100), ['0.0,60.0', '240.0,0.0'])
})
