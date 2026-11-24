// Presentation-only navigation configuration; identifiers and visibility stay unchanged.
const I = {
  grid: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
  detect: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2"/></svg>',
  rules: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M8 6h13M8 12h13M8 18h13"/><circle cx="4" cy="6" r="1.2" fill="currentColor" stroke="none"/><circle cx="4" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="4" cy="18" r="1.2" fill="currentColor" stroke="none"/></svg>',
  asset: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="14" rx="2"/><path d="M8 20h8M12 18v2"/></svg>',
  deploy: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3v12M8 11l4 4 4-4"/><path d="M5 19h14"/></svg>',
  config: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  ai: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l2.2 4.5L19 9l-4.2 2.1L12 16l-2.8-4.9L5 9l4.8-1.5L12 3z"/><circle cx="12" cy="19" r="1.6"/></svg>',
  intel: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l7 4v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V7l7-4z"/><path d="M9.5 12.2l1.8 1.8 3.4-3.8"/></svg>',
}
export const railItems = [
  { id: 'overview', label: '数据概览', short: '概览', ico: I.grid },
  { id: 'detect', label: '终端安全', short: '终端', ico: I.detect },
  { id: 'intel', label: '威胁情报', short: '情报', ico: I.intel },
  { id: 'rules', label: '规则管理', short: '规则', ico: I.rules },
  { id: 'asset', label: '终端资产', short: '资产', ico: I.asset },
  { id: 'deploy', label: '部署运营', short: '部署', ico: I.deploy },
  { id: 'config', label: '平台配置', short: '配置', ico: I.config },
]
export const NAV_STORE_KEY = 'edr_admin_nav'
// 合法一级分区：AI 模块删除后，旧浏览器缓存可能残留 section:'ai'，
// menuMap 查不到该分组会让二级菜单整片空白，恢复时统一归一到 overview。
export const NAV_SECTIONS = new Set(railItems.map(item => item.id))
export const NAV_PAGES = new Set([
  'overview', 'events', 'malware', 'behaviors', 'attck', 'investigate', 'timeline',
  'hunt', 'dns', 'ioc', 'rules', 'seq', 'hosts', 'groups', 'deploy', 'upgrade',
  'audit', 'settings', 'policy', 'notify', 'storage', 'accounts', 'threat-view',
  'lineage-risk', 'network-awareness', 'abnormal-files', 'approvals', 'cases', 'archive',
])

// Storage access and reactive assignments stay with the caller.
export function encodeNavState({ section, page, eventListReturnPage, activeEventId, rulesSection }) {
  return JSON.stringify({ section, page, eventListReturnPage, threatEventId: page === 'threat-view' && activeEventId ? activeEventId : null, rulesSection })
}

export function decodeNavState(serialized) {
  const raw = JSON.parse(serialized || 'null')
  if (!raw?.page || !NAV_PAGES.has(raw.page)) return null
  // 归一化非法 section，但保留 page 与事件上下文，避免整份导航状态被丢弃。
  return { ...raw, section: NAV_SECTIONS.has(raw.section) ? raw.section : 'overview' }
}

export const menuMap = {
  // 概览为单页直达：点左侧图标直接看总览看板，不再浮出二级菜单。
  // 保留本组以确保 defaultPageForSection('overview') 仍能解析出默认页；
  // 其余入口由总览页下钻、终端安全/终端资产分区菜单及页头 ATT&CK 按钮提供。
  overview: [
    {
      title: '态势',
      items: [
        { id: 'overview', label: '总览看板' },
      ],
    },
  ],
  detect: [
    {
      title: '检测响应',
      items: [{ id: 'events', label: '威胁事件' }],
    },
    {
      title: '威胁概览',
      items: [{ id: 'overview', label: '终端安全概览' }],
    },
    {
      title: '入侵防护',
      items: [{ id: 'malware', label: '恶意文件' }],
    },
    {
      title: '调查',
      items: [
        { id: 'behaviors', label: '检出行为' },
        { id: 'lineage-risk', label: '异常进程' },
        { id: 'network-awareness', label: '异常外联' },
        { id: 'abnormal-files', label: '异常文件' },
        { id: 'investigate', label: '日志调查' },
        { id: 'timeline', label: '主机时间线' },
      ],
    },
    {
      title: '狩猎',
      items: [
        { id: 'hunt', label: '威胁狩猎' },
        { id: 'dns', label: 'DNS 狩猎' },
      ],
    },
    {
      title: '策略配置',
      items: [{ id: 'whitelist', label: '信任名单' }],
    },
  ],
  intel: [{
    title: '威胁情报',
    items: [
      { id: 'ioc', label: '情报库与 IOC' },
    ],
  }],
  rules: [{
    title: '规则管理',
    items: [
      { id: 'rules', label: 'Agent 规则' },
      { id: 'seq', label: '行为序列' },
    ],
  }],
  asset: [{
    title: '调查资产',
    items: [
      { id: 'hosts', label: '终端列表' },
      { id: 'groups', label: '终端分组' },
    ],
  }],
  deploy: [{ title: '部署运营', items: [{ id: 'deploy', label: '安装包下载' }, { id: 'upgrade', label: '灰度升级' }, { id: 'audit', label: '审计日志' }] }],
  config: [{
    title: '平台配置',
    items: [
      { id: 'settings', label: '接入与模型' },
      { id: 'policy', label: 'EDR 策略' },
      { id: 'notify', label: '通知渠道' },
      { id: 'storage', label: '存储与保留' },
      { id: 'archive', label: '遥测归档' },
      { id: 'accounts', label: '账号管理', adminOnly: true },
    ],
  }],
}

export function sectionTitleFor(sectionId) {
  return ({
    overview: '数据概览', detect: '终端安全', intel: '威胁情报', rules: '规则管理',
    asset: '终端资产', deploy: '部署运营', config: '平台配置',
  }[sectionId] || '')
}

export function visibleMenuGroups(sectionId, isAdmin) {
  return (menuMap[sectionId] || []).map(g => ({
    ...g,
    items: g.items.filter(m => !m.adminOnly || isAdmin),
  }))
}

/** 一级导航默认页：跳过会跳到其它 rail 分区的二级项（如检测里的「终端安全概览」→ 概览分区） */
export function defaultPageForSection(sectionId) {
  const skipCross = {
    detect: new Set(['overview', 'whitelist', 'malware']),
    rules: new Set(['whitelist']),
    intel: new Set(),
    ai: new Set(),
    asset: new Set(),
    deploy: new Set(),
    config: new Set(),
    overview: new Set(),
  }
  const skip = skipCross[sectionId] || new Set()
  for (const g of menuMap[sectionId] || []) {
    for (const m of g.items || []) {
      if (m.adminOnly) continue
      if (!skip.has(m.id)) return m.id
    }
  }
  return null
}
