<template>
  <section class="ex" :data-code="code">
    <div class="ex-card">
      <p class="ex-code">{{ code }}</p>
      <h1>{{ title }}</h1>
      <p class="ex-desc">{{ description }}</p>
      <div class="ex-acts">
        <button v-if="showHome" type="button" class="btn primary" @click="emit('home')">返回总览</button>
        <button type="button" class="btn" @click="emit('back')">返回上一页</button>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  code: { type: [String, Number], default: 404 },
})
defineEmits(['home', 'back'])

const meta = {
  403: { title: '无权访问', description: '当前账号没有访问该页面的权限，请联系管理员开通。' },
  404: { title: '页面不存在', description: '链接可能已失效，或功能尚未开放。' },
  500: { title: '服务暂时不可用', description: '服务端出现异常，请稍后重试；若持续出现请联系运维。' },
}

const title = computed(() => meta[String(props.code)]?.title || '页面异常')
const description = computed(() => meta[String(props.code)]?.description || '请返回后重试。')
const showHome = computed(() => String(props.code) !== '403')
</script>

<style scoped>
.ex {
  min-height: 100%; display: grid; place-items: center; padding: 40px 20px;
  background:
    radial-gradient(60% 50% at 50% 0%, rgba(226, 86, 44, .08), transparent 70%),
    var(--bg);
}
.ex-card {
  width: min(440px, 100%); text-align: center;
  background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--shadow); padding: 36px 28px;
}
.ex-code {
  margin: 0 0 8px; font-size: 48px; font-weight: 800; letter-spacing: -.04em;
  color: var(--accent); line-height: 1;
}
h1 { margin: 0 0 8px; font-size: 22px; color: var(--ink); }
.ex-desc { margin: 0 0 22px; color: var(--muted); font-size: 13.5px; line-height: 1.6; }
.ex-acts { display: flex; justify-content: center; gap: 10px; flex-wrap: wrap; }
.ex[data-code="403"] .ex-code { color: #b54708; }
.ex[data-code="500"] .ex-code { color: var(--sev-critical, #b42318); }
</style>
