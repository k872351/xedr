const reserved = (key) => typeof key !== 'string' || key.startsWith('_') || key.startsWith('$')

export function forwardSetupContext(source) {
  const read = (key) => source?.proxy ? source.proxy[key] : source?.[key]
  const has = (key) => !reserved(key) && (source?.proxy ? key in source.proxy : key in (source || {}))
  const keys = () => {
    const raw = source?.proxy ? source.setupState : source
    return Reflect.ownKeys(raw || {}).filter((key) => !reserved(key))
  }
  return new Proxy({}, {
    get(_target, key) { return reserved(key) ? undefined : read(key) },
    set(_target, key, value) {
      if (reserved(key)) return false
      if (source?.proxy) source.proxy[key] = value
      else source[key] = value
      return true
    },
    has(_target, key) { return has(key) },
    ownKeys() { return keys() },
    getOwnPropertyDescriptor(_target, key) {
      if (!has(key)) return undefined
      return { configurable: true, enumerable: true, get() { return read(key) }, set(value) {
        if (source?.proxy) source.proxy[key] = value
        else source[key] = value
      } }
    },
  })
}
