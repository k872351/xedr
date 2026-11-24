// Console-only display vocabulary and formatting. Keep existing fallback and units unchanged.
export const LABELS = {
  sysinfo: '系统', process: '进程', service: '服务', task: '计划任务',
  startup: '启动项', network: '网络', listen: '监听端口',
  software: '已装软件', hotfix: '补丁', file: '文件', user: '用户', driver: '驱动',
  netif: '网卡', groups: '用户组', firewall: '防火墙', shares: '共享',
  certs: '证书', usb: 'USB',
}

export const COL_LABELS = {
  name: '名称', display_name: '显示名', status: '状态', path: '路径',
  pid: 'PID', ppid: '父PID', command: '命令', command_line: '命令行',
  task_name: '任务名', author: '作者', next_run: '下次运行', last_run: '上次运行',
  last_result: '上次结果', working_directory: '工作目录', execute: '执行程序', arguments: '参数',
  triggers: '触发器', description: '描述', account: '运行账户', start_type: '启动类型',
  exit_code: '退出码', user: '用户', session_id: '会话', create_time: '创建时间',
  memory_mb: '内存(MB)', handles: '句柄数',
  local: '本地', remote: '远程', proto: '协议', state: '连接状态',
  location: '位置', caption: '系统', hostname: '主机名', domain: '域',
  agent_ver: 'Agent 版本', build: '内部版本', collected_at: '采集时间',
  goarch: '架构', goos: '操作系统',
  ext: '扩展名', size: '大小(字节)', size_kb: '大小(KB)', modified: '修改时间',
  created: '创建时间', directory: '所在目录', session: '会话名',
  enabled: '启用', last_logon: '上次登录', password_required: '需密码',
  principal: 'SID', source: '来源', manufacturer: '厂商', model: '型号',
  total_ram_mb: '内存(MB)', last_boot: '上次开机', install_date: '安装日期',
  version: '版本', ip: 'IP', num_cpu: 'CPU 核数', os_family: '系统族',
  parent_name: '父进程', parent_path: '父路径', uptime: '运行时长', uptime_sec: '运行秒数',
  signed: '签名状态', signer: '签名者', sha256: 'SHA256', company: '公司名',
  file_version: '文件版本', process_name: '进程名',
  risk_score: '风险分', risk_tags: '风险标签', noise: '系统噪声',
  module_count: '模块总数', module_third_count: '第三方DLL', modules_summary: '已加载DLL',
  modules: '模块列表',
  publisher: '发布者', arch: '位数', install_path: '安装路径', uninstall: '卸载命令',
  kb: '补丁号', installed_on: '安装时间', installed_by: '安装者', inventory: '清单类型',
  mac: 'MAC', gateway: '网关', dns: 'DNS', members: '成员', member_count: '成员数',
  package: '包名', sid: 'SID',
  direction: '方向', action: '动作', profile: '配置文件', share_type: '共享类型',
  current_users: '当前连接', encrypt: '加密', caching: '缓存',
  issuer: '颁发者', thumbprint: '指纹', store: '证书存储', not_before: '生效', not_after: '过期',
  has_private: '私钥', class: '设备类', manufacturer: '厂商', instance_id: '实例 ID',
  ext_id: '扩展 ID', browser: '浏览器',
  process_guid: '进程GUID', parent_guid: '父进程GUID', elevated: '已提权', integrity: '完整性级别',
  script_block: '脚本块', payload: '载荷',
  module: '模块', module_name: '模块名', host_process: '宿主进程', process_path: '进程路径',
  image: '映像路径',
  hive: 'Hive', key: '完整路径', reg_key: '注册表键', value_name: '值名', value: '写入值', old_value: '原值',
  value_type: '值类型', change: '变更类型', label: '监控点', category: '类别', watch: '监控规则', user_sid: '用户 SID',
  etype: '事件类型', event_id: '事件 ID', channel: '日志通道', script_block_id: '脚本块 ID',
  target_path: '目标进程', target_pid: '目标 PID', access: '访问权限', start_address: '起始地址', call_trace: '调用栈',
  member: '成员', group: '组', by: '操作者', logon_type: '登录类型', substatus: '子状态码', target: '目标服务器',
  privileges: '特权', process: '进程', task: '任务', content: '任务定义',
  ioc_value: '情报值', ioc_type: '情报类型', malware: '恶意家族', intel_source: '情报来源', matched_from: '匹配字段',
  trigger: '触发事件', lib: '情报库', ioc_id: '情报 ID',
  remote_ip: '远程 IP', remote_port: '远程端口', old_sha256: '原 SHA256', old_size: '原大小(字节)',
  query: '查询域名', qtype: '记录类型码', qtype_name: '记录类型', status_name: '解析结果', answers: '解析地址',
  cnames: 'CNAME', dga_score: 'DGA 分数', nx_count: '失败数', window_sec: '统计窗口(秒)', samples: '样本域名',
  entity_id: '进程实体', parent_create_time: '父进程创建时间', duration_sec: '存活(秒)', from: '原值', to: '新值',
}

const EVENT_MODULE_LABELS = {
  memory: '内存扫描', kernel: '内核驱动', etw: 'ETW', timeline: '时间线',
  sequence: '行为序列', response: '处置', ioc: '威胁情报', registry: '注册表',
  image: 'DLL / 驱动加载', inject: '注入 / 进程访问', dns: 'DNS', account: '账号与登录',
  audit: '审计日志', script: '脚本执行',
}

export function modLabel(m) { return LABELS[m] || EVENT_MODULE_LABELS[m] || m || '' }

export function colLabel(c) { return COL_LABELS[c] || c }

export function statusLabel(s) { return ({ open: '未处置', closed: '已处置', ignored: '无需处置' })[s] || s }

export function sevLabel(s) { return ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' })[s] || s || '—' }

export function short(id) { return String(id || '').slice(0, 8) }

export function shortPath(p) {
  const s = String(p || '')
  if (s.length <= 48) return s || '—'
  return `…${s.slice(-46)}`
}

export function shortHash(h) {
  const s = String(h || '')
  if (s.length < 24) return s || '—'
  return `${s.slice(0, 16)}…${s.slice(-8)}`
}

export function cell(row, c) {
  const v = row?.[c]
  if (v == null || v === '') return '—'
  const s = String(v).replace(/\uFFFD/g, '')
  return s.length > 120 ? `${s.slice(0, 118)}…` : s
}

export function fmtTime(t) {
  if (!t) return '—'
  return String(t).replace('T', ' ').slice(0, 19)
}

export function fmtEpoch(sec) {
  if (!sec) return '—'
  const d = new Date(Number(sec) * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

export function fmtNum(n) {
  const x = Number(n) || 0
  return x.toLocaleString('zh-CN')
}

export function fmtSize(n) {
  const x = Number(n) || 0
  if (x < 1024) return `${x} B`
  if (x < 1024 * 1024) return `${(x / 1024).toFixed(1)} KB`
  return `${(x / 1024 / 1024).toFixed(1)} MB`
}

export function formatDetail(v) {
  if (v == null || v === '') return '—'
  if (typeof v === 'boolean') return v ? '是' : '否'
  return String(v)
}
