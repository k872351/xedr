import assert from 'node:assert/strict'
import test from 'node:test'
import { safeRailIcon } from './safeRailIcon.js'

test('safeRailIcon allows plain svg and rejects script/handlers', () => {
  assert.equal(safeRailIcon('<svg viewBox="0 0 8 8"><circle cx="4" cy="4" r="3"/></svg>').startsWith('<svg'), true)
  assert.equal(safeRailIcon('<svg onclick="alert(1)"></svg>'), '')
  assert.equal(safeRailIcon('<script>x</script>'), '')
  assert.equal(safeRailIcon('javascript:alert(1)'), '')
  assert.equal(safeRailIcon(''), '')
})

test('status tone mapping covers online/offline/warn/error aliases', async () => {
  const { parse } = await import('vue/compiler-sfc')
  const { readFileSync } = await import('node:fs')
  const source = readFileSync(new URL('./ConsoleStatusTag.vue', import.meta.url), 'utf8')
  const { descriptor, errors } = parse(source)
  assert.deepEqual(errors, [])
  assert.match(descriptor.scriptSetup.content, /online|offline|error|warn/)
})
