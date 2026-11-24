<template>
  <div class="panel snap-list">
    <div class="panel-hd">
      <div>
        <h3>{{ moduleTitle }}</h3>
        <span v-if="snapshot" class="meta">最近同步 {{ collectedAt }} · {{ filteredCount }} / {{ (snapshot.items || []).length }} 条 · {{ liveOk ? `已连接 · ${liveAgo}` : '同步中' }}</span>
        <span v-else-if="!loading" class="meta warn">{{ statusMessage }}</span>
      </div>
      <div class="hd-acts">
        <slot name="search" />
        <button type="button" class="btn sm" :disabled="loading" @click="emit('refresh')">重新加载</button>
        <button type="button" class="btn sm" @click="emit('request-collect')">刷新采集</button>
      </div>
    </div>
    <div v-if="loading" class="empty">加载中…</div>
    <div v-else-if="error" class="empty err">
      <p>{{ error }}</p>
      <p class="hint">{{ statusMessage }}</p>
      <div class="empty-acts">
        <button type="button" class="btn sm" @click="emit('refresh')">重试加载</button>
        <button type="button" class="btn sm" @click="emit('request-collect')">下发刷新采集</button>
      </div>
    </div>
    <HostSystemInfo v-else-if="currentModule === 'sysinfo'" :items="snapshot?.items" :column-label="columnLabel" :cell="cell" />
    <template v-else-if="!snapshot?.items?.length">
      <div class="snap-empty">
        <strong>暂无清单数据</strong>
        <p>{{ statusMessage || '尚无可用快照' }}</p>
        <div class="empty-acts">
          <button type="button" class="btn sm primary" @click="emit('request-collect')">下发刷新采集</button>
          <button type="button" class="btn sm" @click="emit('refresh')">重新加载</button>
          <button type="button" class="btn sm" @click="emit('goto-policy')">查看 EDR 策略</button>
        </div>
      </div>
    </template>
    <HostSnapshotTable v-else :columns="columns" :rows="pageData.rows" :selected-row="selectedRow"
      :has-items="!!snapshot?.items?.length" :filtered-count="filteredCount" :truncated="truncated"
      :status-message="statusMessage" :column-label="columnLabel" :cell="cell" @select="emit('select', $event)" />
    <ConsoleListPager v-if="!loading && !error && currentModule !== 'sysinfo' && filteredCount" :page-data="pageData" :page-size="pageSize"
      @size-change="emit('size-change', $event)" @page-change="emit('page-change', $event)" />
  </div>
</template>

<script setup>
import HostSystemInfo from './HostSystemInfo.vue'
import HostSnapshotTable from './HostSnapshotTable.vue'
import ConsoleListPager from './ConsoleListPager.vue'
defineProps({
  currentModule: String, moduleTitle: String, snapshot: Object, selectedRow: Object, collectedAt: String,
  filteredCount: Number, liveOk: Boolean, liveAgo: String, loading: Boolean, error: String, statusMessage: String, truncated: Boolean,
  columns: { type: Array, required: true }, pageData: { type: Object, required: true }, pageSize: Number,
  columnLabel: { type: Function, required: true }, cell: { type: Function, required: true },
})
const emit = defineEmits(['select', 'size-change', 'page-change', 'refresh', 'request-collect', 'goto-policy'])
</script>

<style scoped>
.snap-list { display: flex; flex-direction: column; min-height: 0; min-width: 0; height: 100%; }
.panel-hd { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 12px 16px; border-bottom: 1px solid #eceef2; background: linear-gradient(180deg,#fcfcfd,#ffffff); flex-wrap: wrap; flex-shrink: 0; }
.panel-hd h3 { margin: 0; font-size: 14px; font-weight: 650; color: #2b3038; }
.meta { color: var(--muted); font-size: 12px; }
.meta.warn { color: #b54708; }
.hd-acts { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.empty { padding: 4px 20px 40px; text-align: center; color: #98a2b3; font-size: 12.5px; line-height: 1.7; }
.empty.err { color: var(--danger); }
.hint { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
.snap-empty {
  flex: 1; min-height: 160px; display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 8px; padding: 28px 20px; text-align: center; color: #536b80;
}
.snap-empty strong { font-size: 15px; color: #344e63; }
.snap-empty p { margin: 0; max-width: 42em; font-size: 13px; line-height: 1.6; color: #708397; }
.empty-acts { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; margin-top: 8px; }
</style>
