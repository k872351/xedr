import test from 'node:test'
import assert from 'node:assert/strict'
import { forwardSetupContext } from './setupContext.js'

test('forwarded page context reads and writes parent setup bindings', () => {
  const state = { count: 2, label: 'overview', _internal: true, $private: true }
  const publicInstance = new Proxy({}, {
    get(_target, key) { return state[key] },
    set(_target, key, value) { state[key] = value; return true },
    has(_target, key) { return key in state },
  })
  const parent = forwardSetupContext({ proxy: publicInstance, setupState: state })
  const child = forwardSetupContext(parent)

  assert.equal(child.label, 'overview')
  child.count += 1
  assert.equal(state.count, 3)
  assert.equal('_internal' in child, false)
  assert.equal('$private' in child, false)
  assert.deepEqual(Object.keys(child).sort(), ['count', 'label'])
})
