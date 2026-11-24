<template>
  <div class="ws-tabs-wrap">
    <div class="ws-tabs" role="tablist" aria-label="工作区页签">
      <div
        v-for="t in items"
        :key="t.id"
        class="ws-tab"
        :class="{ on: t.id === active }"
        role="presentation"
      >
        <button
          type="button"
          class="ws-lab-btn"
          role="tab"
          :aria-selected="t.id === active"
          :title="t.pinned ? `${t.label}（固定）` : `${t.label} · 中键关闭`"
          @click="emit('activate', t.id)"
          @click.middle.prevent="!t.pinned && emit('close', t.id)"
          @dblclick.prevent="!t.pinned && emit('close', t.id)"
          @contextmenu.prevent="onCtx($event, t)"
        >{{ t.label }}</button>
        <button
          v-if="!t.pinned && items.length > 1"
          type="button"
          class="ws-x"
          title="关闭页签"
          aria-label="关闭页签"
          @click="emit('close', t.id)"
        >×</button>
      </div>
    </div>
    <div
      v-if="ctx.visible"
      class="ws-ctx"
      :style="{ left: ctx.x + 'px', top: ctx.y + 'px' }"
      @click.stop
    >
      <button v-if="!ctx.pinned" type="button" @click="doClose">关闭</button>
      <button type="button" @click="doCloseOthers">关闭其他</button>
      <button type="button" @click="doCloseAll">全部关闭</button>
    </div>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, reactive } from 'vue'

defineProps({
  items: { type: Array, required: true },
  active: String,
})
const emit = defineEmits(['activate', 'close', 'close-others', 'close-all'])

const ctx = reactive({ visible: false, x: 0, y: 0, id: '', pinned: false })

function onCtx(e, t) {
  ctx.visible = true
  ctx.x = Math.min(e.clientX, window.innerWidth - 140)
  ctx.y = Math.min(e.clientY, window.innerHeight - 120)
  ctx.id = t.id
  ctx.pinned = !!t.pinned
}

function hideCtx() { ctx.visible = false }
function doClose() { emit('close', ctx.id); hideCtx() }
function doCloseOthers() { emit('close-others', ctx.id); hideCtx() }
function doCloseAll() { emit('close-all'); hideCtx() }

onMounted(() => {
  window.addEventListener('click', hideCtx)
  window.addEventListener('scroll', hideCtx, true)
})
onBeforeUnmount(() => {
  window.removeEventListener('click', hideCtx)
  window.removeEventListener('scroll', hideCtx, true)
})
</script>

<style scoped>
.ws-tabs-wrap {
  display: flex; align-items: stretch; gap: 8px; min-width: 0; max-width: 100%;
  position: relative; z-index: 3;
}
.ws-tabs {
  display: flex; align-items: stretch; gap: 2px;
  min-width: 0; flex: 1; overflow-x: auto; scrollbar-width: thin;
  padding: 0 4px;
}
.ws-tab {
  flex: 0 0 auto; display: inline-flex; align-items: center; gap: 0;
  border-bottom: 2px solid transparent;
  border-radius: 8px 8px 0 0; white-space: nowrap;
  position: relative; z-index: 1;
}
.ws-tab:hover { background: var(--bg-elevated); }
.ws-tab.on {
  border-bottom-color: var(--accent);
  background: color-mix(in srgb, var(--accent-soft) 70%, transparent);
}
.ws-lab-btn {
  border: 0; background: transparent; color: var(--muted);
  padding: 8px 4px 8px 12px; font-size: 12.5px; font-weight: 600;
  cursor: pointer; white-space: nowrap; user-select: none;
}
.ws-tab.on .ws-lab-btn { color: var(--accent-2); }
.ws-tab:hover .ws-lab-btn { color: var(--ink); }
.ws-x {
  width: 22px; height: 22px; margin: 0 6px 0 2px; border-radius: 5px; border: 0;
  display: inline-grid; place-items: center; opacity: .7; font-size: 16px; line-height: 1;
  flex: 0 0 auto; cursor: pointer; background: transparent; color: inherit;
  padding: 0; position: relative; z-index: 5;
}
.ws-x:hover { opacity: 1; background: rgba(0,0,0,.08); color: var(--danger, #b42318); }
.ws-tab-acts {
  display: flex; align-items: center; gap: 4px; flex-shrink: 0; padding-bottom: 6px;
  position: relative; z-index: 5;
}
.ws-act {
  border: 0; background: transparent; color: var(--muted);
  font-size: 11.5px; font-weight: 650; padding: 4px 6px; border-radius: 6px; cursor: pointer;
}
.ws-act:hover { color: var(--accent-2); background: var(--accent-soft); }
.ws-ctx {
  position: fixed; z-index: 200; min-width: 128px;
  background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  box-shadow: var(--shadow-lg); padding: 4px; display: grid;
}
.ws-ctx button {
  border: 0; background: transparent; text-align: left;
  padding: 7px 10px; font-size: 12.5px; font-weight: 600; color: var(--ink-2);
  border-radius: 6px; cursor: pointer;
}
.ws-ctx button:hover { background: var(--accent-soft); color: var(--accent-2); }
</style>
