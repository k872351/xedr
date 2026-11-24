import test from 'node:test'
import assert from 'node:assert/strict'
import { getSnapshot } from './api.js'

test('snapshot pages preserve full-list consumers and restart on version conflict', async () => {
  const original = globalThis.fetch
  let calls = 0
  const rows = Array.from({ length: 1501 }, (_, i) => ({ name: `fixture-${i}` }))
  globalThis.fetch = async url => {
    const q = new URL(url, 'http://fixture').searchParams
    const offset = Number(q.get('offset'))
    calls++
    if (calls === 2) return new Response(JSON.stringify({ detail: 'snapshot_version_changed' }), { status: 409 })
    const version = calls === 1 ? 'old' : 'new'
    const items = rows.slice(offset, offset + 500)
    return new Response(JSON.stringify({ item: { items }, page: { total: rows.length, snapshot_version: version, next_offset: offset + items.length < rows.length ? offset + items.length : null } }))
  }
  try {
    assert.deepEqual((await getSnapshot('fixture', 'software')).item.items, rows)
    assert.equal(calls, 6)
  } finally { globalThis.fetch = original }
})

test('legacy unpaged response is preserved', async () => {
  const original = globalThis.fetch
  const result = { item: { items: [{ name: 'fixture' }] } }
  globalThis.fetch = async () => new Response(JSON.stringify(result))
  try { assert.deepEqual(await getSnapshot('fixture', 'software'), result) }
  finally { globalThis.fetch = original }
})
