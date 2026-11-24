import { isRef } from 'vue'

/** 把 setup 里的 ref/函数袋装成 AppPages 可用的 context（兼容 forwardSetupContext）。 */
export function buildPageContext(bag) {
  const ctx = Object.create(null)
  for (const key of Object.keys(bag || {})) {
    Object.defineProperty(ctx, key, {
      enumerable: true,
      configurable: true,
      get: () => bag[key],
      set: (value) => {
        const binding = bag[key]
        if (isRef(binding)) binding.value = value
      },
    })
  }
  return ctx
}
