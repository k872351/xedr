/** 威胁进程链兜底 / 名称清洗纯函数（从 App.vue 抽出）。 */

export function looksBadName(s) {
  const t = String(s || '').trim()
  if (!t) return true
  // Program Files 被空格截断后的常见残片
  if (/^(Program|Program Files|Windows|System32|SysWOW64|Users|AppData)$/i.test(t)) return true
  // 残缺片段：如 \SU84O、无扩展名的短乱码
  if (/^\\?[A-Za-z0-9_-]{1,10}$/.test(t) && !/\.(exe|dll|sys|bat|ps1|cmd)$/i.test(t)) return true
  return false
}

export function parseHashBag(src) {
  const out = { sha256: '', md5: '', sha1: '', raw: '' }
  if (!src || typeof src !== 'object') return out
  out.sha256 = String(src.sha256 || '').trim()
  out.md5 = String(src.md5 || '').trim()
  out.sha1 = String(src.sha1 || '').trim()
  const raw = String(src.hashes || src.hash || '').trim()
  out.raw = raw
  if ((!out.sha256 || !out.md5) && raw) {
    for (const part of raw.split(',')) {
      const i = part.indexOf('=')
      if (i <= 0) continue
      const k = part.slice(0, i).trim().toLowerCase()
      const v = part.slice(i + 1).trim()
      if (!v) continue
      if (k === 'sha256' && !out.sha256) out.sha256 = v
      else if (k === 'md5' && !out.md5) out.md5 = v
      else if (k === 'sha1' && !out.sha1) out.sha1 = v
    }
  }
  // 纯 64 位十六进制当 SHA256
  if (!out.sha256 && /^[a-f0-9]{64}$/i.test(raw)) out.sha256 = raw
  if (!out.md5 && /^[a-f0-9]{32}$/i.test(raw)) out.md5 = raw
  return out
}

/**
 * 从威胁树节点沿 parent_id 回根；无树时返回 []。
 * @param {{ nodes?: any[], hit_id?: string, ancestor_chain?: any[] }} tree
 */
export function ancestorChainFromTree(tree) {
  const fromApi = tree?.ancestor_chain
  if (Array.isArray(fromApi) && fromApi.length) return fromApi
  const nodes = tree?.nodes || []
  const hitId = tree?.hit_id
  if (!nodes.length || !hitId) return []
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]))
  const chain = []
  let cur = byId[hitId]
  const seen = new Set()
  while (cur && !seen.has(cur.id) && chain.length < 16) {
    seen.add(cur.id)
    chain.push(cur)
    cur = cur.parent_id ? byId[cur.parent_id] : null
  }
  return chain.length ? chain.reverse() : []
}

/**
 * 无进程树时，用告警证据拼一条最小祖先链（发起进程 ± 父进程）。
 */
export function ancestorChainFromEvidence({
  flat = {},
  ev = {},
  path = '',
  name = '',
  commandLine = '',
  targets = [],
  fileBaseName,
} = {}) {
  let n = name
  let p = path
  if (looksBadName(n)) n = ''
  if (!n && p && typeof fileBaseName === 'function') n = fileBaseName(p)
  const pid = flat.pid ?? ev.pid
  const ppid = flat.ppid ?? ev.ppid
  const parentName = flat.parent_name || ev.parent_name || ''
  const parentPath = flat.parent_path || ev.parent_path || ''
  if (!n && !p && pid == null && !parentName && !(targets || []).length && !flat.ioc_value) return []
  const hit = {
    id: 'ev-hit',
    name: n || (pid != null ? `PID ${pid}` : ((targets || []).length ? '访问进程（待关联）' : '发起进程')),
    path: p,
    pid,
    ppid,
    command_line: commandLine || flat.command_line || ev.command_line || '',
    user: flat.user || ev.user || '',
    is_hit: true,
    missing: !n && !p && pid == null,
    synthetic: !n && !p && pid == null,
  }
  const chain = []
  if (parentName || parentPath || ppid != null) {
    chain.push({
      id: 'ev-parent',
      name: parentName || (parentPath ? String(parentPath).split(/[\\/]/).pop() : `父进程 PID ${ppid}`),
      path: parentPath || '',
      pid: ppid,
      command_line: flat.parent_command_line || '',
      is_hit: false,
      missing: !parentName && !parentPath,
      synthetic: !parentName && !parentPath,
    })
  }
  chain.push(hit)
  return chain
}
