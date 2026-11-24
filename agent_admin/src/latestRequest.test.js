import { test } from 'node:test'
import assert from 'node:assert/strict'
import { latestRequest } from './latestRequest.js'

test('later requests supersede older responses and unmount invalidates them', () => {
  const gate = latestRequest()
  const first = gate.begin()
  const second = gate.begin()
  assert.equal(first(), false)
  assert.equal(second(), true)
  gate.invalidate()
  assert.equal(second(), false)
})
