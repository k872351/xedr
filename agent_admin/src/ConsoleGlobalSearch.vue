<template>
  <Teleport to="body">
    <div v-if="open" class="gsearch-mask" @click="emit('close')">
      <div class="gsearch" role="dialog" aria-label="全局搜索" @click.stop>
        <header class="gsearch-hd">
          <input
            ref="inputEl"
            v-model="q"
            class="gsearch-input"
            placeholder="搜索功能页面…（↑↓ 选择，Enter 打开，Esc 关闭）"
            @keydown.down.prevent="move(1)"
            @keydown.up.prevent="move(-1)"
            @keydown.enter.prevent="confirm"
            @keydown.esc.prevent="emit('close')"
          />
          <kbd>Esc</kbd>
        </header>
        <ul class="gsearch-list">
          <li
            v-for="(item, i) in filtered"
            :key="item.id"
            :class="{ on: i === active }"
            @mouseenter="active = i"
            @click="pick(item)"
          >
            <strong>{{ item.label }}</strong>
            <span>{{ item.sectionLabel }}{{ item.group ? ' · ' + item.group : '' }}</span>
          </li>
          <li v-if="!filtered.length" class="empty">无匹配页面</li>
        </ul>
        <footer class="gsearch-ft">输入关键词快速跳转 · Ctrl+K</footer>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { buildPageCatalog } from './consolePageCatalog.js'

const props = defineProps({ open: Boolean, isAdmin: Boolean })
const emit = defineEmits(['close', 'select'])
const q = ref('')
const active = ref(0)
const inputEl = ref(null)
const catalog = computed(() => buildPageCatalog(!!props.isAdmin))
const filtered = computed(() => {
  const needle = q.value.trim().toLowerCase()
  if (!needle) return catalog.value.slice(0, 12)
  return catalog.value.filter(p => p.keywords.includes(needle)).slice(0, 20)
})

watch(() => props.open, async (v) => {
  if (!v) return
  q.value = ''
  active.value = 0
  await nextTick()
  inputEl.value?.focus()
})
watch(filtered, () => { active.value = 0 })

function move(delta) {
  const n = filtered.value.length
  if (!n) return
  active.value = (active.value + delta + n) % n
}
function pick(item) {
  emit('select', item.id)
  emit('close')
}
function confirm() {
  const item = filtered.value[active.value]
  if (item) pick(item)
}
</script>

<style scoped>
.gsearch-mask {
  position: fixed; inset: 0; z-index: 2100;
  background: rgba(16, 20, 28, .45); backdrop-filter: blur(2px);
  display: grid; place-items: start center; padding-top: 12vh;
}
.gsearch {
  width: min(560px, calc(100vw - 32px));
  background: var(--panel); border: 1px solid var(--line); border-radius: 14px;
  box-shadow: var(--shadow-lg); overflow: hidden; color: var(--ink);
}
.gsearch-hd {
  display: flex; align-items: center; gap: 10px; padding: 12px 14px;
  border-bottom: 1px solid var(--line);
}
.gsearch-input {
  flex: 1; min-width: 0; border: 0; outline: none; background: transparent;
  font-size: 15px; color: var(--ink); height: 32px;
}
.gsearch-hd kbd {
  font-size: 11px; padding: 2px 6px; border-radius: 6px;
  border: 1px solid var(--line); color: var(--muted); background: var(--bg-elevated);
}
.gsearch-list { list-style: none; margin: 0; padding: 8px; max-height: 360px; overflow: auto; }
.gsearch-list li {
  display: flex; flex-direction: column; gap: 2px;
  padding: 10px 12px; border-radius: 8px; cursor: pointer;
}
.gsearch-list li.on, .gsearch-list li:hover { background: var(--accent-soft); }
.gsearch-list strong { font-size: 13.5px; }
.gsearch-list span { font-size: 11.5px; color: var(--muted); }
.gsearch-list .empty { color: var(--muted); cursor: default; text-align: center; }
.gsearch-ft {
  padding: 8px 14px; border-top: 1px solid var(--line);
  font-size: 11px; color: var(--muted); background: var(--bg-elevated);
}
</style>
