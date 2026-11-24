<template>
  <div v-if="pageData.total" class="list-pager">
    <span class="pg-info">显示 {{ pageData.start + 1 }}–{{ pageData.end }} / {{ pageData.total }} 条分组记录</span>
    <div class="pg-acts">
      <select  :value="pageSize" @change="emit('size-change', Number($event.target.value))" class="pg-size" aria-label="每页记录数">
        <option :value="50">50 条/页</option>
        <option :value="100">100 条/页</option>
        <option :value="200">200 条/页</option>
      </select>
      <button type="button" class="btn sm" :disabled="pageData.page <= 1" @click="emit('page-change', pageData.page - 1)">上一页</button>
      <span>{{ pageData.page }} / {{ pageData.pageCount }}</span>
      <button type="button" class="btn sm" :disabled="pageData.page >= pageData.pageCount" @click="emit('page-change', pageData.page + 1)">下一页</button>
    </div>
  </div>
</template>

<script setup>
defineProps({ pageData: { type: Object, required: true }, pageSize: Number })
const emit = defineEmits(['size-change', 'page-change'])
</script>

<style scoped>
.list-pager { flex-shrink: 0; display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; padding: 10px 14px; border-top: 1px solid var(--line); background: #f7fafc; }
.pg-info { color: var(--muted); font-size: 12px; }
.pg-acts { display: flex; gap: 8px; align-items: center; font-size: 12px; }
.pg-size, .btn { padding: 6px 10px; border: 1px solid var(--line); border-radius: 6px; color: var(--ink-2); background: white; }
.btn:disabled { opacity: .5; }
.pg-info, .pg-acts { font-variant-numeric: tabular-nums; }
.pg-acts button:hover:not(:disabled) { background: #edf6fd; border-color: #8bb2d6; }
.pg-acts :is(button, select):focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; }
</style>
