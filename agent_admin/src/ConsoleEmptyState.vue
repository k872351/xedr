<template>
  <div class="console-empty" :data-kind="kind">
    <span class="console-empty-mark" aria-hidden="true">{{ mark }}</span>
    <strong>{{ title }}</strong>
    <p v-if="description">{{ description }}</p>
    <slot />
  </div>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({
  kind: { type: String, default: 'empty' }, // empty | error | unsupported | loading
  title: { type: String, required: true },
  description: { type: String, default: '' },
})
const mark = computed(() => ({
  empty: '—',
  error: '!',
  unsupported: '○',
  loading: '…',
}[props.kind] || '—'))
</script>
