<template>
  <header class="page-hd" :class="{ 'overview-header': dark }">
    <div>
      <h1>{{ title }}</h1>
      <p v-if="description && !hideDescription" class="desc">{{ description }}</p>
    </div>
    <slot />
  </header>
</template>

<script setup>
defineProps({ title: { type: String, required: true }, description: String, dark: Boolean, hideDescription: Boolean })
</script>

<style scoped>
.page-hd {
  display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 14px;
  border: 1px solid var(--line); border-left: 3px solid var(--accent);
  background: var(--panel); border-radius: var(--radius); padding: 14px 18px; box-shadow: var(--shadow);
}
h1 { margin: 0; font-size: var(--fs-title, 22px); font-weight: 700; letter-spacing: -.02em; color: var(--ink); }
.desc { margin: 5px 0 0; color: var(--muted); font-size: var(--fs-meta, 12px); max-width: 72ch; line-height: 1.55; }
.overview-header {
  border: 1px solid var(--line); border-left: 3px solid var(--accent);
  background: #fff; color: var(--ink); box-shadow: var(--shadow);
}
.overview-header h1 { color: var(--ink); }
.overview-header .desc { color: var(--muted); }
</style>
