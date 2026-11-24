import test from 'node:test'
import assert from 'node:assert/strict'
import { hostEvidenceStatus } from './hostEvidenceStatus.js'

test('online endpoint without telemetry or policy evidence remains unknown', () => {
  const rows = hostEvidenceStatus({ online: true })
  assert.equal(rows[0].value, '在线')
  assert.equal(rows[1].value, '尚无采集证据')
  assert.equal(rows[2].value, '证据不足')
  assert.equal(rows[3].value, '状态未知')
})

test('inventory gaps and rejected policies are independent of connection', () => {
  const rows = hostEvidenceStatus({ online: true, telemetry_received: true, health: {
    inventory_quality: { software: { status: 'possible_truncation', last_success_at: '2026-11-22T12:00:00' } },
    policy: { status: 'rejected', error: 'fixture' }, fleet: { policy_applied: false },
  } })
  // Both older reports with a status string and newer boolean flags carry a gap.
  assert.equal(rows[1].value, '2026-11-22T12:00:00')
  assert.equal(rows[2].value, '存在已报告缺口')
  assert.equal(rows[3].value, '策略拒绝')
})
