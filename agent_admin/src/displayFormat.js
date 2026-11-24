export function fmtNum(n) {
  const x = Number(n)
  return Number.isFinite(x) ? x.toLocaleString('zh-CN') : '—'
}

export function fmtSize(n) {
  let x = Number(n)
  if (!Number.isFinite(x) || x < 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let unit = 0
  while (x >= 1024 && unit < units.length - 1) {
    x /= 1024
    unit++
  }
  return `${unit === 0 ? x : x.toFixed(1)} ${units[unit]}`
}
