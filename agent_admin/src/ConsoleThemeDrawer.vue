<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="td-root"
      role="presentation"
      @keydown.esc.prevent="emit('close')"
    >
      <div class="td-mask" @click="emit('close')" />
      <aside
        class="td-panel"
        role="dialog"
        aria-modal="true"
        aria-label="界面偏好"
        tabindex="-1"
        @click.stop
        @mousedown.stop
      >
        <header class="td-hd">
          <div>
            <h3>界面偏好</h3>
            <p>主题、密度、圆角与水印（本地保存，即时生效）</p>
          </div>
          <button type="button" class="btn sm" @click="emit('close')">关闭</button>
        </header>
        <div class="td-bd">
          <section class="td-sec">
            <h4>外观</h4>
            <div class="td-row">
              <span>主题</span>
              <div class="td-seg">
                <button type="button" :class="{ on: theme === 'light' }" @click="emit('set-theme', 'light')">浅色</button>
                <button type="button" :class="{ on: theme === 'dark' }" @click="emit('set-theme', 'dark')">深色</button>
              </div>
            </div>
            <div class="td-row">
              <span>表格密度</span>
              <div class="td-seg">
                <button type="button" :class="{ on: density === 'comfortable' }" @click="emit('set-density', 'comfortable')">标准</button>
                <button type="button" :class="{ on: density === 'compact' }" @click="emit('set-density', 'compact')">紧凑</button>
              </div>
            </div>
            <div class="td-row">
              <span>字号</span>
              <div class="td-seg">
                <button type="button" :class="{ on: fontScale === 'small' }" @click="emit('set-font', 'small')">小</button>
                <button type="button" :class="{ on: fontScale === 'medium' }" @click="emit('set-font', 'medium')">中</button>
                <button type="button" :class="{ on: fontScale === 'large' }" @click="emit('set-font', 'large')">大</button>
              </div>
            </div>
            <label class="td-row">
              <span>圆角 {{ radius }}px</span>
              <input
                class="td-range"
                type="range"
                min="0"
                max="16"
                step="1"
                :value="radius"
                @input="emit('set-radius', Number($event.target.value))"
              />
            </label>
          </section>
          <section class="td-sec">
            <h4>工作区</h4>
            <label class="td-check">
              <input type="checkbox" :checked="showTabs" @change="emit('set-show-tabs', $event.target.checked)" />
              <span>显示顶部页签栏（可关闭/右键批量关）</span>
            </label>
          </section>
          <section class="td-sec">
            <h4>安全展示</h4>
            <label class="td-check">
              <input type="checkbox" :checked="watermark" @change="emit('set-watermark', $event.target.checked)" />
              <span>显示页面水印（账号 · 时间）</span>
            </label>
          </section>
        </div>
      </aside>
    </div>
  </Teleport>
</template>

<script setup>
import { nextTick, watch } from 'vue'

const props = defineProps({
  open: Boolean,
  theme: { type: String, default: 'light' },
  density: { type: String, default: 'comfortable' },
  radius: { type: Number, default: 10 },
  fontScale: { type: String, default: 'medium' },
  watermark: Boolean,
  showTabs: { type: Boolean, default: true },
})
const emit = defineEmits(['close', 'set-theme', 'set-density', 'set-radius', 'set-font', 'set-watermark', 'set-show-tabs'])

watch(() => props.open, async (open) => {
  if (!open) return
  await nextTick()
  const panel = document.querySelector('.td-panel')
  panel?.focus?.()
})
</script>

<style scoped>
.td-root {
  position: fixed;
  inset: 0;
  z-index: 5200;
  pointer-events: none;
}
.td-mask {
  position: absolute;
  inset: 0;
  pointer-events: auto;
  background: rgba(10, 14, 22, 0.48);
  backdrop-filter: blur(2px);
}
.td-panel {
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  z-index: 1;
  width: min(380px, 100vw);
  pointer-events: auto;
  background: var(--panel, #fff);
  color: var(--ink, #1c2430);
  border-left: 1px solid var(--line, #dfe5ec);
  box-shadow: var(--shadow-lg, 0 18px 48px rgba(20, 22, 28, 0.22));
  display: flex;
  flex-direction: column;
  outline: none;
  animation: td-in .18s ease-out;
}
.td-hd {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--line, #dfe5ec);
  background: var(--bg-elevated, #f7f9fc);
}
.td-hd h3 { margin: 0; font-size: 16px; font-weight: 700; color: var(--ink, #1c2430); }
.td-hd p { margin: 4px 0 0; font-size: 12px; color: var(--muted, #6b7a8c); }
.td-bd { flex: 1; overflow: auto; padding: 16px; display: grid; gap: 18px; }
.td-sec h4 {
  margin: 0 0 10px;
  font-size: 12px;
  font-weight: 700;
  color: var(--muted, #6b7a8c);
  letter-spacing: .04em;
  text-transform: uppercase;
}
.td-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
  font-size: 13px;
  color: var(--ink-2, #445263);
  font-weight: 600;
}
.td-seg {
  display: inline-flex;
  border: 1px solid var(--line, #dfe5ec);
  border-radius: 8px;
  overflow: hidden;
  background: var(--bg-elevated, #f7f9fc);
}
.td-seg button {
  border: 0;
  background: transparent;
  padding: 6px 12px;
  font-size: 12px;
  font-weight: 650;
  color: var(--muted, #6b7a8c);
  cursor: pointer;
}
.td-seg button.on {
  background: var(--accent-soft, #fdefe8);
  color: var(--accent-2, #c9431d);
}
.td-range { width: 140px; accent-color: var(--accent, #e2562c); }
.td-check {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: var(--ink-2, #445263);
  font-weight: 600;
}
@keyframes td-in {
  from { transform: translateX(12px); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}
</style>
