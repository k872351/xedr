import { test } from 'node:test'
import assert from 'node:assert/strict'
import { paginateSections, paginateSnapshotRows } from './sectionPagination.js'

test('preserves grouping across page boundaries', () => {
  const sections = [{ key: 'a', agents: [1, 2, 3] }, { key: 'b', agents: [4, 5] }]
  const result = paginateSections(sections, 2, 2)
  assert.deepEqual(result.sections.map(section => section.agents), [[3], [4]])
  assert.deepEqual(result.sections.map(section => section.total), [3, 2])
  assert.equal(result.pageCount, 3)
  assert.equal(paginateSections(sections, 10, 2).page, 3)
  assert.deepEqual(paginateSections([], 1, 2).sections, [])
  assert.equal(paginateSections(sections, Infinity, Infinity).page, 1)
  assert.equal(paginateSections(sections, 1.9, 2.9).end, 2)
})

test('large synthetic lists expose only the requested page', () => {
  const sections = Array.from({ length: 100 }, (_, i) => ({
    key: String(i), agents: Array.from({ length: 100 }, (_, n) => i * 100 + n),
  }))
  const result = paginateSections(sections, 155, 50)
  assert.equal(result.total, 10000)
  assert.equal(result.sections.reduce((sum, section) => sum + section.agents.length, 0), 50)
  assert.equal(result.sections[0].agents[0], 7700)
})

test('snapshot paging does not hide the records after the old 800-row cap', () => {
  const rows = Array.from({ length: 1000 }, (_, i) => ({ id: i + 1 }))
  const last = paginateSnapshotRows(rows, 20, 50)
  assert.equal(last.total, 1000)
  assert.equal(last.rows[0].id, 951)
  assert.equal(last.rows.at(-1).id, 1000)
  assert.equal(paginateSnapshotRows(rows.slice(0, 5), 20, 50).page, 1)
})
