<template>
  <div v-if="health?.capture_quality" class="capture-quality-box">
    <strong>采集质量（本次 Agent 运行累计）</strong>
    <div class="table-scroll"><table>
      <thead><tr><th>来源/阶段</th><th>接收</th><th>主动过滤</th><th>队列丢弃</th><th>限流</th><th>入队</th><th>已取出</th><th>持久化</th><th>未确认落盘</th><th>预算到达次数</th><th>缺口/错误</th></tr></thead>
      <tbody>
        <tr v-for="(q, source) in health.capture_quality" :key="source">
          <td>{{ source }}</td><td>{{ q.received ?? '—' }}</td><td>{{ q.filtered ?? '—' }}</td>
          <td>{{ q.buffer_dropped ?? '—' }}</td><td>{{ q.rate_limited ?? '—' }}</td>
          <td>{{ q.queued ?? '—' }}</td><td>{{ q.drained ?? '—' }}</td><td>{{ q.persisted ?? '—' }}</td><td>{{ q.durability_unconfirmed ?? '—' }}</td>
          <td>{{ q.budget_limited_polls ?? '—' }}</td>
          <td>{{ (q.bookmark_gap || 0) + (q.notification_gap || 0) + (q.render_failed || 0) + (q.parse_failed || 0) + (q.bookmark_save_failed || 0) + (q.read_failed || 0) + (q.cursor_read_failed || 0) + (q.cursor_commit_failed || 0) }}</td>
        </tr>
      </tbody>
    </table></div>
    <p class="hint">原生 WinEvent 与上层缓冲是不同阶段，不相加计算总接收量；持久化不等于服务端已接收。</p>
  </div>
  <div v-if="Object.keys(health?.loop_quality || {}).length" class="capture-quality-box">
    <strong>采集循环调度质量</strong>
    <div class="table-scroll"><table><thead><tr><th>阶段</th><th>最近 (ms)</th><th>最大 (ms)</th><th>参考预算 (ms)</th><th>超预算次数</th><th>样本</th></tr></thead>
      <tbody><tr v-for="(r, stage) in health.loop_quality" :key="stage"><td>{{ stage === 'live_cycle' ? '实时采集周期' : (stage === 'heartbeat_schedule_delay' ? '心跳调度延迟' : stage) }}</td><td>{{ r.last_ms }}</td><td>{{ r.max_ms }}</td><td>{{ r.budget_ms }}</td><td>{{ r.over_budget || 0 }}</td><td>{{ r.samples }}</td></tr></tbody></table></div>
    <p class="hint">本地调度延迟采样不等于服务端心跳丢失次数。</p>
  </div>
  <div v-if="Object.keys(health?.fim_root_health || {}).length" class="capture-quality-box">
    <strong>FIM 目录状态：{{ Object.values(health.fim_root_health).filter(r => r.watch === 'active' || (r.watch === 'polling' && r.reconcile === 'complete')).length }} / {{ Object.keys(health.fim_root_health).length }} 当前有效</strong>
    <div class="table-scroll"><table><thead><tr><th>目录</th><th>监听 / 轮询</th><th>对账</th><th>基线保存</th><th>最近完整遍历</th></tr></thead>
      <tbody><tr v-for="(r, path) in health.fim_root_health" :key="path"><td class="mono">{{ path }}</td><td>{{ r.watch === 'polling' ? '轮询' : (r.watch || '未知') }}</td><td>{{ r.reconcile || '未知' }}</td><td>{{ r.baseline || '—' }}</td><td>{{ r.last_complete_at || '—' }}</td></tr></tbody></table></div>
  </div>
  <div v-if="Object.keys(health?.inventory_quality || {}).length" class="capture-quality-box">
    <strong>资产清单采集完整度</strong>
    <div class="table-scroll"><table><thead><tr><th>模块</th><th>平台</th><th>返回/上限</th><th>状态</th><th>最近成功</th><th>原因</th></tr></thead>
      <tbody><tr v-for="(r, module) in health.inventory_quality" :key="module"><td>{{ moduleLabel(module) }}</td><td>{{ r.platform }}</td><td>{{ r.returned }} / {{ r.limit }}</td><td>{{ r.possible_truncation ? '可能截断，保留上次清单' : r.status }}</td><td>{{ r.last_success_at || '—' }}</td><td>{{ r.error || '—' }}</td></tr></tbody></table></div>
  </div>
  <div v-if="health?.memory_scan_quality?.observed_at" class="capture-quality-box">
    <strong>最近内存扫描质量</strong>
    <p>状态 {{ health.memory_scan_quality.scan_status || '未知' }} · 尝试 {{ health.memory_scan_quality.attempted ?? '—' }} · 有效读取 {{ health.memory_scan_quality.scanned ?? '—' }} · 打开失败 {{ health.memory_scan_quality.open_failed ?? '—' }} · 权限拒绝 {{ health.memory_scan_quality.access_denied ?? '—' }} · 部分读取 {{ health.memory_scan_quality.partial ?? '—' }} · 预算截断 {{ health.memory_scan_quality.budget_limited ?? '—' }}</p>
  </div>
  <p v-if="health?.health_truncated" class="hint">本次健康上报存在超限省略，部分指标可能未展示。</p>
</template>

<script setup>
defineProps({ health: Object, moduleLabel: { type: Function, required: true } })
</script>

<style scoped>
.capture-quality-box { margin-top: 12px; border: 1px solid var(--line, #dce5ec); border-radius: 8px; padding: 10px; }
.capture-quality-box .table-scroll { max-height: 250px; overflow: auto; margin-top: 8px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; border-bottom: 1px solid var(--line); white-space: nowrap; max-width: 280px; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
th { padding: 10px 12px; font-weight: 600; font-size: 12px; position: sticky; top: 0; z-index: 1; background: linear-gradient(180deg, #f5f6f8, #eef0f3); color: #575f6c; border-bottom-color: #dfe2e8; letter-spacing: .02em; }
.capture-quality-box td { padding: 9px 12px; font-size: 12px; overflow-wrap: anywhere; border-bottom-color: #eceef2; }
tbody tr:nth-child(even) td { background: #fafbfc; }
tbody tr:hover td { background: #fdf0ea; }
.hint { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
.mono { font-variant-numeric: tabular-nums; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
</style>
