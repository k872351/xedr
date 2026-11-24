<template>
  <div v-if="rows.length" class="table-scroll">
    <table>
      <thead><tr><th v-for="column in columns" :key="column.label">{{ column.label }}</th></tr></thead>
      <tbody>
        <tr v-for="(row, index) in rows" :key="row.id ?? index">
          <td v-for="column in columns" :key="column.label" :class="column.class" :title="column.title?.(row)">{{ column.value(row) }}</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p v-else-if="emptyText" class="empty">{{ emptyText }}</p>
</template>

<script setup>
defineProps({ rows: { type: Array, required: true }, columns: { type: Array, required: true }, emptyText: String })
</script>

<style scoped>
.table-scroll { overflow: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; border-bottom: 1px solid #eceef2; white-space: nowrap; max-width: 280px; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
th { padding: 10px 12px; font-size: 12px; font-weight: 600; position: sticky; top: 0; z-index: 1; background: linear-gradient(180deg,#f5f6f8,#eef0f3); color: #575f6c; border-bottom-color: #dfe2e8; letter-spacing: .02em; }
td { padding: 9px 12px; font-size: 12.5px; }
tbody tr:nth-child(even) td { background: #fafbfc; }
tbody tr:hover td { background: #fdf0ea; }
.muted { color: var(--muted); }
.mono { font-variant-numeric: tabular-nums; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.empty { padding: 4px 20px 40px; text-align: center; color: #98a2b3; font-size: 12.5px; line-height: 1.7; }
</style>
