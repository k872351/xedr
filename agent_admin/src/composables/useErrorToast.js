import { onScopeDispose, watch } from 'vue'

// Own only the display timer; the caller owns message state.
export function useErrorToast(error, timeoutMs = 5000) {
  let timer = null
  function cancelTimer() {
    if (timer) clearTimeout(timer)
    timer = null
  }
  function clearErrorToast() {
    error.value = ''
    cancelTimer()
  }
  watch(error, msg => {
    cancelTimer()
    if (!msg) return
    timer = setTimeout(() => {
      error.value = ''
      timer = null
    }, timeoutMs)
  })
  onScopeDispose(cancelTimer)
  return { clearErrorToast }
}
