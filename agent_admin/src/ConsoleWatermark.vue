<template>
  <div v-if="active" class="wm" aria-hidden="true">
    <span v-for="n in 18" :key="n" class="wm-item">{{ text }}</span>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'

const props = defineProps({
  enabled: Boolean,
  username: { type: String, default: '' },
})

const now = ref(Date.now())
let timer

onMounted(() => {
  timer = setInterval(() => { now.value = Date.now() }, 60_000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})

const active = computed(() => props.enabled && !!props.username)
const text = computed(() => {
  const d = new Date(now.value)
  const ts = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
  return `${props.username} · ${ts}`
})
</script>

<style scoped>
.wm {
  pointer-events: none; position: fixed; inset: 0; z-index: 70; overflow: hidden;
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 80px 40px;
  padding: 40px 20px; opacity: .07;
}
.wm-item {
  font-size: 14px; font-weight: 650; color: var(--ink);
  transform: rotate(-22deg); white-space: nowrap; user-select: none;
}
html[data-theme="dark"] .wm { opacity: .09; }
</style>
