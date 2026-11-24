<template>
  <div class="wb" :class="{ 'menu-open': menuOpen }">
    <div class="wb-left">
      <nav class="wb-crumb" aria-label="面包屑">
        <template v-for="(c, i) in crumbs" :key="i">
          <span v-if="i" class="wb-sep">/</span>
          <span :class="{ current: i === crumbs.length - 1 }">{{ c.label }}</span>
        </template>
        <span class="wb-build" title="前端构建号（用于确认是否已刷新到最新）">{{ buildTag }}</span>
      </nav>
      <ConsoleWorkspaceTabs
        v-if="showTabs"
        :items="tabItems"
        :active="page"
        @activate="emit('activate-tab', $event)"
        @close="emit('close-tab', $event)"
        @close-others="emit('close-other-tabs', $event)"
        @close-all="emit('close-all-tabs')"
      />
    </div>
    <div class="wb-right">
      <!-- 顶栏只保留通知（样本下载）；主题/密度/搜索改到左侧用户菜单或 Ctrl+K -->
      <slot />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import ConsoleWorkspaceTabs from './ConsoleWorkspaceTabs.vue'
defineProps({
  crumbs: { type: Array, required: true },
  tabItems: { type: Array, required: true },
  showTabs: { type: Boolean, default: true },
  page: String,
  density: { type: String, default: 'comfortable' },
  theme: { type: String, default: 'light' },
  menuOpen: { type: Boolean, default: false },
})
defineEmits(['search', 'activate-tab', 'close-tab', 'close-other-tabs', 'close-all-tabs', 'toggle-density', 'toggle-theme', 'open-theme'])
const buildTag = computed(() => {
  const v = String(import.meta.env.VITE_XEDR_BUILD || '').trim()
  return v ? `build ${v}` : ''
})
</script>

<style scoped>
.wb {
  position: fixed;
  top: 0;
  left: 76px;
  right: 0;
  z-index: 500;
  display: flex; align-items: flex-end; justify-content: space-between; gap: 12px;
  min-height: 52px; padding: 0 6px;
  border-bottom: 1px solid var(--line); background: var(--panel);
  pointer-events: auto;
  box-shadow: 0 1px 0 rgba(15, 23, 42, .04);
  transition: left .16s ease;
}
.wb.menu-open { left: 288px; }
@media (max-width: 1100px) {
  .wb.menu-open { left: 276px; }
}
.wb-left {
  min-width: 0; flex: 1; display: flex; flex-direction: column; gap: 2px; padding-top: 6px;
  overflow: visible;
  position: relative;
  z-index: 2;
  pointer-events: auto;
}
.wb-crumb {
  display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: var(--muted);
  padding: 0 4px; min-height: 18px;
}
.wb-crumb .current { color: var(--ink-2); font-weight: 650; }
.wb-sep { opacity: .45; }
.wb-build {
  margin-left: 10px; padding: 1px 7px; border-radius: 999px;
  background: var(--bg-elevated, #eef2f7); color: var(--muted, #667085); font-size: 10.5px; font-weight: 700;
  letter-spacing: .02em;
}
.wb-right {
  display: flex; align-items: center; gap: 8px; flex-shrink: 0;
  padding-bottom: 8px;
  position: relative;
  z-index: 5;
  pointer-events: auto;
}
@media (max-width: 900px) {
  .wb { flex-wrap: wrap; align-items: stretch; }
  .wb-right { width: 100%; justify-content: flex-end; padding-bottom: 6px; }
}
</style>
