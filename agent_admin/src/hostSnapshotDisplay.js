// Pure, read-only formatting for snapshot detail fields.
export function rowTitle(row) {
  if (!row) return '条目'
  return row.name || row.task_name || row.display_name || row.path || row.local || '条目详情'
}

export function detailGroups(row) {
  if (!row) return []
  const groups = [
    { title: '基本信息', keys: ['name', 'task_name', 'display_name', 'status', 'state', 'enabled', 'pid', 'ppid', 'parent_name', 'process_name', 'user', 'account', 'session_id', 'session', 'source', 'ext', 'proto', 'risk_score', 'risk_tags'] },
    { title: '路径 / 命令', keys: ['path', 'command', 'command_line', 'execute', 'arguments', 'working_directory', 'directory', 'location', 'local', 'remote'] },
    { title: '签名 / 哈希', keys: ['signed', 'signer', 'company', 'file_version', 'sha256'] },
    { title: '模块 / 资源', keys: ['module_count', 'module_third_count', 'modules_summary', 'uptime', 'uptime_sec', 'create_time', 'created', 'modified', 'last_run', 'next_run', 'last_logon', 'last_result', 'memory_mb', 'size', 'size_kb', 'handles'] },
    { title: '其他', keys: [] },
  ]
  const used = new Set(['modules', 'noise'])
  const out = []
  for (const g of groups.slice(0, 4)) {
    const fields = {}
    for (const k of g.keys) {
      if (k in row) {
        fields[k] = row[k]
        used.add(k)
      }
    }
    if (Object.keys(fields).length) out.push({ title: g.title, fields })
  }
  const rest = {}
  for (const [k, v] of Object.entries(row)) {
    if (!used.has(k)) rest[k] = v
  }
  if (Object.keys(rest).length) out.push({ title: '其他字段', fields: rest })
  return out
}
