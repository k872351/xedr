<template>
  <div class="console-skel" :aria-busy="true" aria-label="加载中">
    <div class="console-skel-line lg" />
    <div v-for="n in rows" :key="n" class="console-skel-line" :class="n % 2 ? 'md' : 'sm'" />
  </div>
</template>

<script setup>
defineProps({ rows: { type: Number, default: 4 } })
</script>
