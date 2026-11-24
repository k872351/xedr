<template>
  <div class="list-pager">
    <span class="pg-info">第 {{ pageData.page }} / {{ pageData.pageCount }} 页 · 共 {{ pageData.total }} 条</span>
    <div class="pg-acts">
      <select :value="pageSize" class="pg-size" aria-label="每页记录数" @change="emit('size-change', Number($event.target.value))">
        <option v-for="size in pageSizes" :key="size" :value="size">{{ size }} 条/页</option>
      </select>
      <button type="button" class="btn sm" :disabled="pageData.page <= 1" @click="emit('page-change', pageData.page - 1)">上一页</button>
      <button type="button" class="btn sm" :disabled="pageData.page >= pageData.pageCount" @click="emit('page-change', pageData.page + 1)">下一页</button>
    </div>
  </div>
</template>

<script setup>
defineProps({ pageData: { type: Object, required: true }, pageSize: Number, pageSizes: { type: Array, default: () => [20, 50, 100] } })
const emit = defineEmits(['size-change', 'page-change'])
</script>

<style scoped>
.list-pager { flex-shrink: 0; display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; padding: 10px 14px; border-top: 1px solid #e8eef6; background: linear-gradient(180deg,#fafbfd 0%,#f5f8fc 100%); }
.pg-info { font-size: 12.5px; color: #667085; font-weight: 550; font-variant-numeric: tabular-nums; }
.pg-acts { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.pg-size, .btn { border: 1px solid #e4eaf3; border-radius: 8px; background: #fff; padding: 5px 10px; font-size: 12px; color: var(--ink-2); cursor: pointer; }
.pg-size { min-width: 96px; }
.btn { min-width: 68px; font-weight: 600; }
.pg-size:hover, .btn:hover:not(:disabled) { border-color: #c7d7f0; }
.btn:disabled { opacity: .45; cursor: not-allowed; background: #f1f5f9; color: #98a2b3; }
</style>
