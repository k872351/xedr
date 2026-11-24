import test from 'node:test'
import assert from 'node:assert/strict'
import { useHunt } from './composables/useHunt.js'

test('older query cannot overwrite a newer synthetic result', async t => {
  const pending = []
  t.mock.method(globalThis, 'fetch', () => new Promise(resolve => pending.push(resolve)))
  const hunt = useHunt()
  hunt.huntQ.value = 'old fixture'
  const first = hunt.runHunt()
  hunt.huntQ.value = 'new fixture'
  const second = hunt.runHunt()
  pending[1](new Response(JSON.stringify({ items: [{ title: 'new fixture' }] })))
  await second
  pending[0](new Response(JSON.stringify({ items: [{ title: 'old fixture' }] })))
  await first
  assert.equal(hunt.huntHits.value[0].title, 'new fixture')
  assert.equal(hunt.huntBusy.value, false)
})
