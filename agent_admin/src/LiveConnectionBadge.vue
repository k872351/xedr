<template>
  <span class="live-hint" :class="{ on: connected }"><i class="live-dot" />{{ connected ? (compact ? age : `已连接 · ${age}`) : (compact ? '连接中' : '连接中…') }}</span>
</template>

<script setup>
defineProps({ connected: Boolean, age: String, compact: Boolean })
</script>

<style scoped>
.live-hint { display: inline-flex; align-items: center; gap: 7px; font-size: 12px; color: var(--muted); font-weight: 550; padding: 6px 10px; border-radius: 999px; background: #f2f4f7; }
.live-hint.on { color: #027a48; background: #ecfdf3; }
.live-dot { width: 7px; height: 7px; border-radius: 50%; background: #98a2b3; display: inline-block; }
.live-hint.on .live-dot { background: #12b76a; box-shadow: 0 0 0 3px rgba(18,183,106,.18); }
</style>
