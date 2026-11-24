<template>
  <section class="page page-stack">
    <ConsolePageHeader title="账号管理" description="xedr 后台独立账号，与分析平台账号互不相通"><slot name="header-actions" /></ConsolePageHeader>

    <div class="panel pad role-matrix">
      <h3>三角色权限</h3>
      <p class="hint">管理员全权；分析员可调查与提交处置（高危进审批）；只读仅查看。</p>
      <div class="table-scroll">
        <table class="matrix-table">
          <thead>
            <tr>
              <th>能力</th>
              <th>管理员</th>
              <th>分析员</th>
              <th>只读</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in matrix" :key="row.id">
              <td>{{ row.label }}</td>
              <td><span class="cell" :data-v="cellTone(row.admin)">{{ cellText(row.admin) }}</span></td>
              <td><span class="cell" :data-v="cellTone(row.analyst)">{{ cellText(row.analyst) }}</span></td>
              <td><span class="cell" :data-v="cellTone(row.readonly)">{{ cellText(row.readonly) }}</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="panel pad fill-rest">
      <div v-if="items.length" class="table-scroll">
        <table class="acct-table">
          <thead><tr><th>账号</th><th>角色</th><th>状态</th><th>最近登录</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="u in items" :key="u.id">
              <td><div class="acct-name">
                <span class="ru-avatar sm">{{ (u.display_name || u.username || '?').slice(0, 1).toUpperCase() }}</span>
                <div><strong>{{ u.display_name || u.username }}</strong><small>{{ u.username }}<i v-if="u.id === selfId" class="acct-me">我</i></small></div>
              </div></td>
              <td><slot name="role" :account="u" /></td>
              <td>
                <ConsoleStatusTag :status="u.enabled ? 'online' : 'offline'" :label="u.enabled ? '启用' : '已禁用'" />
                <ConsoleStatusTag v-if="u.must_change" status="warn" label="待改密" />
              </td>
              <td class="muted">{{ u.last_login_at ? fmtEpoch(u.last_login_at) : '从未登录' }}<small v-if="u.last_login_ip" class="acct-ip">{{ u.last_login_ip }}</small></td>
              <td class="ops"><slot name="actions" :account="u" /></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="empty">暂无账号</p>
    </div>
  </section>
</template>

<script setup>
import ConsolePageHeader from './ConsolePageHeader.vue'
import ConsoleStatusTag from './ConsoleStatusTag.vue'
import { ROLE_MATRIX } from './roleAccess.js'

defineProps({ items: { type: Array, required: true }, selfId: [String, Number], fmtEpoch: { type: Function, required: true } })

const matrix = ROLE_MATRIX

function cellText(v) {
  if (v === true) return '允许'
  if (v === false) return '禁止'
  return String(v)
}

function cellTone(v) {
  if (v === true) return 'ok'
  if (v === false) return 'no'
  return 'soft'
}
</script>

<style scoped>
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; }
.panel.pad { padding: 18px 20px; }
.role-matrix { flex-shrink: 0; }
.role-matrix h3 { margin: 0 0 6px; font-size: 15px; }
.table-scroll { overflow: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; border-bottom: 1px solid var(--line); white-space: nowrap; max-width: 320px; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
th { padding: var(--row-pad-y, 10px) 12px; font-size: 12px; font-weight: 650; position: sticky; top: 0; z-index: 1; background: var(--bg-elevated); color: var(--muted); letter-spacing: .02em; }
td { padding: var(--row-pad-y, 9px) 12px; font-size: 12.5px; }
tbody tr:nth-child(even) td { background: var(--bg-elevated); }
tbody tr:hover td { background: var(--accent-soft); }
.matrix-table td:not(:first-child) { text-align: center; }
.cell { display: inline-block; min-width: 3.5em; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.cell[data-v="ok"] { background: #ecfdf3; color: #067647; }
.cell[data-v="no"] { background: #fef3f2; color: #b42318; }
.cell[data-v="soft"] { background: #eff8ff; color: #175cd3; }
.acct-name { display: flex; align-items: center; gap: 10px; }
.acct-name strong { display: block; font-size: 13px; }
.acct-name small { color: var(--muted); font-size: 12px; }
.ru-avatar.sm { width: 28px; height: 28px; border-radius: 50%; display: grid; place-items: center; flex: none; font-size: 12px; font-weight: 700; background: var(--accent-soft); color: var(--accent); }
.acct-me { margin-left: 6px; padding: 0 6px; border-radius: 4px; font-style: normal; font-size: 11px; background: var(--accent-soft); color: var(--accent); }
.acct-ip { display: block; font-size: 11px; color: var(--muted); }
.muted { color: var(--muted); }
.ops { white-space: nowrap; }
.hint { color: var(--muted); font-size: 12px; margin: 0 0 12px; }
.empty { padding: 4px 20px 40px; text-align: center; color: var(--muted); font-size: 12.5px; line-height: 1.7; }
.status-tag + .status-tag { margin-left: 6px; }
</style>
