<template>
  <div ref="rootEl" class="notify">
    <button
      type="button"
      class="notify-btn"
      :class="{ on: open || badgeCount }"
      title="消息通知"
      @click="emit('toggle')"
    >
      <span class="bell" aria-hidden="true">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8">
          <path d="M6 9a6 6 0 0 1 12 0c0 7 3 7 3 7H3s3 0 3-7" />
          <path d="M10 19a2 2 0 0 0 4 0" />
        </svg>
      </span>
      <span class="lab">通知</span>
      <em v-if="badgeCount" class="badge">{{ badgeCount > 99 ? '99+' : badgeCount }}</em>
    </button>

    <div
      v-if="open"
      class="panel"
      role="dialog"
      aria-label="消息通知"
      @click.stop
      @mousedown.stop
    >
      <header class="hd">
        <b>消息通知</b>
        <div class="acts">
          <button type="button" class="link" @click="emit('refresh')">刷新</button>
          <button type="button" class="link" @click="emit('mark-all-read')">全部已读</button>
          <button type="button" class="link" @click="emit('clear-ready')">清除完成</button>
          <button type="button" class="x" title="关闭" @click="emit('toggle')">×</button>
        </div>
      </header>

      <p class="tip">处置回执与恶意样本提取结果会出现在这里；成功项可直接下载或跳转告警。</p>

      <ul v-if="notifications.length" class="list">
        <li
          v-for="n in notifications"
          :key="n.id"
          :class="{ unread: n.unread, open: expanded === n.id }"
          :data-s="n.status"
        >
          <button type="button" class="row" @click="onOpen(n)">
            <span class="ico" :data-k="n.kind" :data-s="n.status" aria-hidden="true">
              <i v-if="n.unread" class="dot" />
              <svg v-if="n.kind === 'sample'" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7">
                <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5z" />
                <path d="M14 3v5h5M9 13h6M9 17h4" />
              </svg>
              <svg v-else viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7">
                <path d="M12 3l8 4v5c0 5-3.5 8-8 10-4.5-2-8-5-8-10V7l8-4z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
            </span>
            <span class="body">
              <strong>{{ n.title }}</strong>
              <small>{{ n.detail }}</small>
            </span>
            <span class="meta">
              <time>{{ relative(n.createdAt) }}</time>
              <em class="chev">›</em>
            </span>
          </button>

          <div v-if="expanded === n.id" class="detail">
            <template v-if="n.kind === 'sample' && n.sample">
              <p v-if="n.status === 'ok'" class="ok-line">恶意样本已提取成功，可下载到本机。</p>
              <p v-else-if="n.status === 'err'" class="err-line">{{ n.sample.error || '提取失败' }}</p>
              <p v-else-if="n.status === 'wait'" class="wait-line">指令已下发，等待终端回传样本…</p>
              <dl>
                <div><dt>主机</dt><dd>{{ n.sample.hostname || n.sample.agentId || '—' }}</dd></div>
                <div><dt>文件</dt><dd class="mono">{{ n.sample.filename || n.sample.path || '—' }}</dd></div>
                <div v-if="n.sample.size"><dt>大小</dt><dd>{{ fmtSize(n.sample.size) }}</dd></div>
              </dl>
              <div class="ops">
                <button
                  v-if="n.sample.status === 'done' && n.sample.stored"
                  type="button"
                  class="btn primary sm"
                  @click="emit('download', n.sample)"
                >下载样本</button>
                <button
                  v-if="n.sample.eventId"
                  type="button"
                  class="btn sm"
                  @click="emit('open-event', n.sample)"
                >查看告警</button>
                <button type="button" class="btn-text" @click="emit('dismiss', n.id)">忽略</button>
              </div>
            </template>
            <template v-else>
              <p class="info-line">{{ n.detail || '远程处置回执' }}</p>
              <dl>
                <div v-if="n.action"><dt>动作</dt><dd>{{ n.action }}</dd></div>
                <div v-if="n.agentId"><dt>终端</dt><dd class="mono">{{ n.agentId }}</dd></div>
                <div v-if="n.commandId"><dt>任务</dt><dd class="mono">{{ n.commandId }}</dd></div>
              </dl>
              <div class="ops">
                <button
                  v-if="n.eventId"
                  type="button"
                  class="btn sm"
                  @click="emit('open-event', { eventId: n.eventId })"
                >查看告警</button>
                <button type="button" class="btn-text" @click="emit('dismiss', n.id)">忽略</button>
              </div>
            </template>
          </div>
        </li>
      </ul>

      <div v-else class="empty">
        <p>暂无通知</p>
        <small>威胁详情里「采集样本 / 结束进程 / 隔离文件 / 网络隔离」完成后会出现在这里。</small>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'

const props = defineProps({
  open: Boolean,
  notifications: { type: Array, default: () => [] },
  badgeCount: { type: Number, default: 0 },
})
const emit = defineEmits([
  'toggle', 'close', 'download', 'dismiss', 'clear-ready', 'refresh',
  'open-event', 'mark-read', 'mark-all-read',
])

const expanded = ref('')
const rootEl = ref(null)

watch(() => props.open, (v) => {
  if (!v) expanded.value = ''
})

function onPointerDown(e) {
  if (!props.open) return
  const root = rootEl.value
  if (root && root.contains(e.target)) return
  emit('close')
}

onMounted(() => {
  document.addEventListener('pointerdown', onPointerDown, true)
})
onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', onPointerDown, true)
})

function onOpen(n) {
  expanded.value = expanded.value === n.id ? '' : n.id
  if (n.unread) emit('mark-read', n.id)
}

function relative(ts) {
  const t = Number(ts) || 0
  if (!t) return ''
  const sec = Math.max(0, Math.floor((Date.now() - t) / 1000))
  if (sec < 45) return '刚刚'
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟前`
  if (sec < 86400) return `${Math.floor(sec / 3600)} 小时前`
  return `${Math.floor(sec / 86400)} 天前`
}

function fmtSize(n) {
  const v = Number(n) || 0
  if (v < 1024) return `${v} B`
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`
  return `${(v / (1024 * 1024)).toFixed(1)} MB`
}
</script>

<style scoped>
.notify { position: relative; z-index: 70; }
.notify-btn {
  display: inline-flex; align-items: center; gap: 6px;
  border: 1px solid var(--line, #dfe5ec); background: var(--bg-elevated, #f7f9fc); color: var(--ink-2, #445263);
  border-radius: 8px; padding: 5px 10px; font-size: 12px; font-weight: 600; cursor: pointer;
}
.notify-btn.on { border-color: #f0b6a0; background: #fff7f5; color: #c8451e; }
.notify-btn .bell { display: grid; place-items: center; }
.notify-btn .lab { font-weight: 700; }
.badge {
  min-width: 18px; height: 18px; padding: 0 5px; border-radius: 999px;
  display: inline-grid; place-items: center; font-size: 11px; font-style: normal; font-weight: 700;
  background: #e11d2e; color: #fff;
}

.panel {
  position: fixed; right: 16px; top: 56px; z-index: 95;
  width: min(440px, calc(100vw - 24px));
  background: #fff; border: 1px solid #e4e7ec; border-radius: 12px;
  box-shadow: 0 16px 48px rgba(16, 24, 40, .16); overflow: hidden;
}
.hd {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 12px 14px; border-bottom: 1px solid #eef2f6;
}
.hd b { font-size: 15px; color: #101828; }
.acts { display: flex; align-items: center; gap: 8px; }
.link {
  border: 0; background: transparent; color: #667085; font-size: 12px; font-weight: 650; cursor: pointer; padding: 0;
}
.link:hover { color: #c8451e; }
.x { border: 0; background: transparent; font-size: 18px; color: #98a2b3; cursor: pointer; line-height: 1; padding: 0 2px; }
.tip {
  margin: 0; padding: 8px 14px 4px; font-size: 12px; color: #667085; line-height: 1.45;
}

.list {
  list-style: none; margin: 0; padding: 4px 0 8px; max-height: min(520px, 62vh); overflow: auto;
}
.list li { border-bottom: 1px solid #f2f4f7; }
.list li:last-child { border-bottom: 0; }
.row {
  width: 100%; display: grid; grid-template-columns: 36px minmax(0, 1fr) auto;
  gap: 10px; align-items: start; text-align: left;
  border: 0; background: transparent; padding: 12px 14px; cursor: pointer;
}
.row:hover { background: #f8fafc; }
.list li.unread .row { background: #fffaf7; }
.list li.open .row { background: #f8fafc; }

.ico {
  position: relative; width: 34px; height: 34px; border-radius: 10px;
  display: grid; place-items: center; color: #475467;
  background: #f2f4f7; flex: none;
}
.ico[data-k="sample"] { background: #fff1eb; color: #c8451e; }
.ico[data-k="response"][data-s="ok"] { background: #ecfdf3; color: #027a48; }
.ico[data-k="response"][data-s="err"] { background: #fef3f2; color: #b42318; }
.ico .dot {
  position: absolute; top: -2px; left: -2px; width: 8px; height: 8px; border-radius: 50%;
  background: #e11d2e; box-shadow: 0 0 0 2px #fff;
}

.body { min-width: 0; display: grid; gap: 3px; padding-top: 2px; }
.body strong {
  font-size: 13px; font-weight: 700; color: #101828;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.body small {
  font-size: 12px; color: #667085; line-height: 1.4;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}
.meta {
  display: flex; flex-direction: column; align-items: flex-end; gap: 6px; padding-top: 2px;
  color: #98a2b3; font-size: 11px; white-space: nowrap;
}
.chev { font-style: normal; font-size: 16px; line-height: 1; color: #98a2b3; }

.detail {
  margin: 0 14px 12px 60px; padding: 10px 12px;
  border: 1px solid #eef2f6; border-radius: 10px; background: #fcfcfd;
}
.ok-line { margin: 0 0 8px; color: #027a48; font-size: 12.5px; font-weight: 650; }
.err-line { margin: 0 0 8px; color: #b42318; font-size: 12.5px; font-weight: 650; }
.wait-line, .info-line { margin: 0 0 8px; color: #667085; font-size: 12.5px; }
.detail dl { margin: 0; display: grid; gap: 4px; }
.detail dl > div { display: grid; grid-template-columns: 42px 1fr; gap: 8px; font-size: 12px; }
.detail dt { color: #98a2b3; }
.detail dd { margin: 0; color: #344054; word-break: break-all; }
.detail .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11.5px; }
.ops { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }

.empty {
  padding: 36px 20px 40px; text-align: center; color: #98a2b3;
}
.empty p { margin: 0 0 6px; font-size: 13.5px; font-weight: 650; color: #667085; }
.empty small { font-size: 12px; line-height: 1.5; }
</style>
