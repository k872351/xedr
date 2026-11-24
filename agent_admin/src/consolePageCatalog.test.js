import test from 'node:test'
import assert from 'node:assert/strict'
import { breadcrumbsFor, buildPageCatalog, pageLabelOf } from './consolePageCatalog.js'

test('page catalog includes core console pages', () => {
  const pages = buildPageCatalog(true)
  const ids = new Set(pages.map(p => p.id))
  assert.ok(ids.has('overview'))
  assert.ok(ids.has('hosts'))
  assert.ok(ids.has('events'))
  assert.ok(ids.has('deploy'))
  assert.equal(pageLabelOf('hosts'), '终端列表')
})

test('breadcrumbs pair section and page', () => {
  const crumbs = breadcrumbsFor('asset', 'hosts', true)
  assert.equal(crumbs.length, 2)
  assert.equal(crumbs[0].label, '终端资产')
  assert.equal(crumbs[1].label, '终端列表')
})
