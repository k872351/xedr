import { menuMap, railItems, sectionTitleFor } from './consoleNavigation.js'

/** Flatten menu entries for search / breadcrumbs / tabs. */
export function buildPageCatalog(isAdmin = false) {
  const out = []
  const seen = new Set()
  for (const rail of railItems) {
    const groups = menuMap[rail.id] || []
    for (const g of groups) {
      for (const item of g.items || []) {
        if (item.adminOnly && !isAdmin) continue
        if (seen.has(item.id)) continue
        seen.add(item.id)
        out.push({
          id: item.id,
          label: item.label,
          section: rail.id,
          sectionLabel: sectionTitleFor(rail.id),
          group: g.title || '',
          keywords: `${item.label} ${rail.label} ${g.title || ''} ${item.id}`.toLowerCase(),
        })
      }
    }
  }
  // Extra pages reachable outside secondary menu
  const extras = [
    { id: 'threat-view', label: '威胁视图', section: 'detect', sectionLabel: '终端安全', group: '检测响应' },
    { id: 'attck', label: 'ATT&CK 看板', section: 'detect', sectionLabel: '终端安全', group: '威胁概览' },
    { id: 'approvals', label: '处置审批', section: 'detect', sectionLabel: '终端安全', group: '检测响应' },
    { id: 'lineage-risk', label: '异常进程', section: 'detect', sectionLabel: '终端安全', group: '调查' },
    { id: 'network-awareness', label: '异常外联', section: 'detect', sectionLabel: '终端安全', group: '调查' },
    { id: 'abnormal-files', label: '异常文件', section: 'detect', sectionLabel: '终端安全', group: '调查' },
  ]
  for (const e of extras) {
    if (seen.has(e.id)) continue
    seen.add(e.id)
    out.push({ ...e, keywords: `${e.label} ${e.sectionLabel} ${e.id}`.toLowerCase() })
  }
  return out
}

export function pageLabelOf(pageId, isAdmin = false) {
  const hit = buildPageCatalog(isAdmin).find(p => p.id === pageId)
  return hit?.label || pageId || ''
}

export function breadcrumbsFor(sectionId, pageId, isAdmin = false) {
  const sectionLabel = sectionTitleFor(sectionId) || '控制台'
  const pageLabel = pageLabelOf(pageId, isAdmin)
  if (!pageLabel || pageLabel === sectionLabel) return [{ label: sectionLabel }]
  return [{ label: sectionLabel }, { label: pageLabel }]
}
