export function paginateSections(sections, requestedPage, pageSize) {
  const safeInteger = (value, fallback) => {
    const number = Number(value)
    return Number.isFinite(number) && number > 0 ? Math.max(1, Math.floor(number)) : fallback
  }
  const size = safeInteger(pageSize, 50)
  const total = sections.reduce((sum, section) => sum + section.agents.length, 0)
  const pageCount = Math.max(1, Math.ceil(total / size))
  const page = Math.min(pageCount, safeInteger(requestedPage, 1))
  const start = (page - 1) * size
  const end = Math.min(start + size, total)
  let cursor = 0
  const visible = []
  for (const section of sections) {
    const sectionEnd = cursor + section.agents.length
    const from = Math.max(0, start - cursor)
    const to = Math.min(section.agents.length, end - cursor)
    if (from < to) visible.push({ ...section, total: section.agents.length, agents: section.agents.slice(from, to) })
    cursor = sectionEnd
    if (cursor >= end) break
  }
  return { sections: visible, page, pageCount, total, start, end }
}

export function paginateSnapshotRows(rows, requestedPage, pageSize) {
  const result = paginateSections([{ agents: rows }], requestedPage, pageSize)
  return { ...result, rows: result.sections[0]?.agents || [] }
}
