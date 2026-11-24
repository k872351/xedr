function numberOrNull(value) {
  if (value == null || typeof value === 'boolean' || (typeof value === 'string' && !value.trim())) return null
  const number = Number(value)
  return Number.isFinite(number) && number >= 0 ? number : null
}

export function appendResourceSample(history, agent, limit = 60) {
  const id = agent?.agent_id
  const time = Date.parse(agent?.health_at || '')
  if (!id || !Number.isFinite(time)) return history
  const cpu = numberOrNull(agent.health?.cpu_pct)
  const sample = { time, cpu: cpu != null && cpu <= 100 ? cpu : null, rss: numberOrNull(agent.health?.rss_mb) }
  const rows = history.id === id ? history.rows : []
  if (rows.length && time <= rows.at(-1).time) return history.id === id ? history : { id, rows: [] }
  return { id, rows: [...rows, sample].slice(-limit) }
}

export function resourceSegments(rows, field, ceiling, width = 240, height = 60) {
  if (!rows.length) return []
  const duration = rows.at(-1).time - rows[0].time || 1
  const segments = []
  let segment = []
  for (const row of rows) {
    if (row[field] == null) {
      if (segment.length) segments.push(segment.join(' '))
      segment = []
      continue
    }
    const x = (row.time - rows[0].time) / duration * width
    const y = height - Math.min(1, row[field] / ceiling) * height
    segment.push(`${x.toFixed(1)},${y.toFixed(1)}`)
  }
  if (segment.length) segments.push(segment.join(' '))
  return segments
}
