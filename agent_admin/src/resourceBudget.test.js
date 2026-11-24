import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resourceBudgetRows, diagnosticTimingRows } from './resourceBudget.js'

test('budget states distinguish unknown, valid zero and above reference', () => {
  assert.deepEqual(resourceBudgetRows({ cpu_pct: null, rss_mb: ' ' }).map(x => x.state), ['unknown', 'unknown'])
  assert.deepEqual(resourceBudgetRows({ cpu_pct: 0, rss_mb: 251 }).map(x => x.state), ['within', 'above'])
  assert.deepEqual(resourceBudgetRows({ cpu_pct: 101, rss_mb: -1 }).map(x => x.state), ['unknown', 'unknown'])
})

test('diagnostic timings preserve zero and reject unavailable measurements', () => {
  const rows = diagnosticTimingRows({ diagnostic_timings: {
    process_resources: { available: true, elapsed_us: 0 },
    go_runtime: { available: false, elapsed_us: 20 },
  } })
  assert.deepEqual(rows.map(row => row.elapsed), [0, null])
})
