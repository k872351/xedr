import test from 'node:test'
import assert from 'node:assert/strict'
import { canRespondRole, isAdminRole, canManageConfigRole, ROLE_MATRIX } from './roleAccess.js'

test('role helpers distinguish admin analyst readonly', () => {
  assert.equal(isAdminRole('admin'), true)
  assert.equal(isAdminRole('analyst'), false)
  assert.equal(canRespondRole('admin'), true)
  assert.equal(canRespondRole('analyst'), true)
  assert.equal(canRespondRole('readonly'), false)
  assert.equal(canManageConfigRole('analyst'), false)
  assert.equal(canManageConfigRole('admin'), true)
})

test('role matrix covers respond and accounts', () => {
  const ids = ROLE_MATRIX.map((r) => r.id)
  assert.ok(ids.includes('respond'))
  assert.ok(ids.includes('accounts'))
  assert.ok(ids.includes('ioc_write'))
})
