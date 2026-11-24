<template>
  <div class="table-scroll snap-table">
    <table>
      <thead><tr><th v-for="c in columns" :key="c">{{ columnLabel(c) }}</th></tr></thead>
      <tbody>
        <tr v-for="(row, i) in rows" :key="i" class="row-click" :class="{ active: selectedRow === row }" @click="emit('select', row)">
          <td v-for="c in columns" :key="c" :title="cell(row, c)">{{ cell(row, c) }}</td>
        </tr>
      </tbody>
    </table>
    <p v-if="!hasItems" class="empty">{{ statusMessage }}</p>
    <template v-else>
      <p v-if="truncated" class="hint">{{ statusMessage }}</p>
      <p v-if="!filteredCount" class="empty">无匹配结果</p>
    </template>
  </div>
</template>

<script setup>
defineProps({ columns: { type: Array, required: true }, rows: { type: Array, required: true }, selectedRow: Object, hasItems: Boolean, filteredCount: Number, truncated: Boolean, statusMessage: String, columnLabel: { type: Function, required: true }, cell: { type: Function, required: true } })
const emit = defineEmits(['select'])
</script>

<style scoped>
.snap-table { flex: 1 1 0; min-height: 0; max-height: none; overflow: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; border-bottom: 1px solid #eceef2; white-space: nowrap; max-width: 280px; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
th { padding: 10px 12px; font-size: 12px; font-weight: 600; position: sticky; top: 0; z-index: 1; background: linear-gradient(180deg,#f5f6f8,#eef0f3); color: #575f6c; border-bottom-color: #dfe2e8; letter-spacing: .02em; }
td { padding: 9px 12px; font-size: 12.5px; }
tbody tr:nth-child(even) td { background: #fafbfc; }
.row-click { cursor: pointer; }
.row-click.active td { background: #eef4ff; }
.row-click:hover td { background: #fdf0ea; }
.hint { color: var(--muted); font-size: 12px; margin: 8px 14px; }
.empty { padding: 4px 20px 40px; text-align: center; color: #98a2b3; font-size: 12.5px; line-height: 1.7; }
</style>
