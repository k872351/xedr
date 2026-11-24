<template>
  <Teleport to="body">
    <div v-if="open" class="console-drawer-mask" @click="emit('close')" />
    <aside v-if="open" class="console-drawer" :class="{ wide }" role="dialog" :aria-label="title" @keydown.esc="emit('close')">
      <header class="console-drawer-hd">
        <div>
          <h3>{{ title }}</h3>
          <p v-if="subtitle" class="desc" style="margin:4px 0 0;font-size:12px;color:var(--muted)">{{ subtitle }}</p>
        </div>
        <button type="button" class="btn sm" @click="emit('close')">关闭</button>
      </header>
      <div class="console-drawer-bd"><slot /></div>
      <footer v-if="$slots.footer" class="console-drawer-ft"><slot name="footer" /></footer>
    </aside>
  </Teleport>
</template>

<script setup>
defineProps({
  open: Boolean,
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
  wide: Boolean,
})
const emit = defineEmits(['close'])
</script>
