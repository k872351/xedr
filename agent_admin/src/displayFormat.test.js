import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fmtNum, fmtSize } from './displayFormat.js'
import * as consoleDisplay from './consoleDisplay.js'

test('size units and invalid inputs', () => {
  assert.equal(fmtSize(0), '0 B')
  assert.equal(fmtSize(1024), '1.0 KB')
  assert.equal(fmtSize(1024 ** 3), '1.0 GB')
  assert.equal(fmtSize(1024 ** 4), '1.0 TB')
  assert.equal(fmtSize(-1), '—')
  assert.equal(fmtSize('invalid'), '—')
  assert.equal(fmtNum('invalid'), '—')
})

test('console labels preserve identifiers, existing translations and unknown value fallbacks', () => {
  const d = consoleDisplay
  assert.equal(d.modLabel('sysinfo'), '系统')
  assert.equal(d.modLabel('timeline'), '时间线')
  assert.equal(d.modLabel('fixture-module'), 'fixture-module')
  assert.equal(d.modLabel(null), '')
  assert.equal(d.colLabel('pid'), 'PID')
  assert.equal(d.colLabel('fixture-column'), 'fixture-column')
  assert.equal(d.statusLabel('ignored'), '无需处置')
  assert.equal(d.sevLabel('critical'), '严重')
  assert.equal(d.sevLabel(null), '—')
})

test('console formatting preserves existing time, number, size and cell rendering', () => {
  const d = consoleDisplay
  assert.equal(d.short('123456789'), '12345678')
  assert.equal(d.shortPath(''), '—')
  assert.equal(d.shortPath('x'.repeat(50)), '…' + 'x'.repeat(46))
  assert.equal(d.shortHash('x'.repeat(30)), 'x'.repeat(16) + '…' + 'x'.repeat(8))
  assert.equal(d.fmtTime('2026-11-23T09:00:00.000Z'), '2026-11-23 09:00:00')
  assert.equal(d.fmtTime(null), '—')
  assert.equal(d.fmtEpoch(null), '—')
  assert.match(d.fmtEpoch(1_700_000_000), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)
  assert.equal(d.fmtNum(undefined), '0')
  assert.equal(d.fmtSize(1024 ** 3), '1024.0 MB')
  assert.equal(d.cell({ value: 0 }, 'value'), '0')
  assert.equal(d.cell({ value: 'a\uFFFDb' }, 'value'), 'ab')
  assert.equal(d.cell({ value: 'x'.repeat(121) }, 'value'), 'x'.repeat(118) + '…')
  assert.equal(d.formatDetail(false), '否')
  assert.equal(d.formatDetail(null), '—')
})
