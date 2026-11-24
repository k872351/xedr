// Apply asynchronous results only while their request is still current.
export function latestRequest() {
  let revision = 0
  return {
    begin() {
      const current = ++revision
      return () => revision === current
    },
    invalidate() { revision++ },
  }
}
