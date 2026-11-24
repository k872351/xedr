<template>
  <div v-if="error || okMsg || respToast || sampleToast" class="toast-stack">
    <div v-if="error" class="toast err toast-with-x" role="alert">
      <span class="toast-main" @click="emit('clear-error')">{{ error }}</span>
      <button type="button" class="toast-x" title="关闭" @click="emit('clear-error')">×</button>
    </div>
    <p v-if="okMsg" class="toast ok">{{ okMsg }}</p>
    <div v-if="respToast" class="toast float" :class="respToast.cls" @click="emit('dismiss')">
      <div class="toast-main">
        <b>{{ respToast.title }}</b>
        <span>{{ respToast.detail }}</span>
      </div>
      <button type="button" class="toast-x" @click.stop="emit('dismiss')">×</button>
    </div>
    <div v-if="sampleToast" class="toast float ok toast-with-x">
      <div class="toast-main">
        <b>{{ sampleToast.title }}</b>
        <span>{{ sampleToast.detail }}</span>
      </div>
      <button v-if="sampleToast.actionLabel" type="button" class="toast-act" @click="emit('sample-action')">{{ sampleToast.actionLabel }}</button>
      <button type="button" class="toast-x" @click="emit('dismiss-sample')">×</button>
    </div>
  </div>
</template>

<script setup>
defineProps({ error: String, okMsg: String, respToast: Object, sampleToast: Object })
const emit = defineEmits(['clear-error', 'dismiss', 'sample-action', 'dismiss-sample'])
</script>

<style scoped>
.toast-stack {
  position: fixed; top: 82px; right: 24px; z-index: 2200;
  display: flex; flex-direction: column; gap: 8px; width: min(420px, calc(100vw - 48px));
  pointer-events: none;
}
.toast {
  margin: 0; padding: 12px 14px; border-radius: 10px; font-size: 13px;
  border: 1px solid var(--line); background: #fff; box-shadow: var(--shadow);
  pointer-events: auto; cursor: pointer;
}
.toast.err { background: #fff5f5; border-color: #f3c1c5; color: var(--danger); }
.toast.ok { background: #f0fdf6; border-color: #b7ebc9; color: #027a48; }
.toast.wait { background: #fffaeb; border-color: #fedf89; color: #b54708; }
.toast.float, .toast-with-x {
  display: flex; align-items: flex-start; gap: 10px; cursor: default;
}
.toast-with-x .toast-main { cursor: pointer; }
.toast-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 4px; }
.toast-main b { font-weight: 700; }
.toast-main span { font-size: 12px; line-height: 1.45; word-break: break-word; opacity: .92; }
.toast-x {
  border: 0; background: transparent; color: inherit; opacity: .55;
  font-size: 18px; line-height: 1; padding: 0 2px; cursor: pointer;
}
.toast-x:hover { opacity: 1; }
.toast-act {
  border: 0; border-radius: 8px; padding: 6px 10px; font-size: 12px; font-weight: 700;
  background: #166534; color: #fff; cursor: pointer; flex-shrink: 0; align-self: center;
}
.toast { box-shadow: 0 10px 30px rgba(20, 22, 28, .18); border-radius: 12px; }
</style>
