<template>
  <div v-if="booting" class="boot"><span class="boot-dot" />正在连接 xedr…</div>
  <div v-else-if="sessionError" class="boot boot-error" role="alert">
    <strong>暂时无法连接管理服务</strong>
    <p>请检查服务状态或网络连接，然后重试。</p>
    <button type="button" @click="loadSession">重新连接</button>
  </div>
  <Login v-else-if="!user || user.must_change" :user="user" @done="onLogin" @logout="logout" />
  <App v-else :user="user" @logout="logout" @user-updated="onLogin" />
</template>

<script setup>
import { defineAsyncComponent, h, onBeforeUnmount, onMounted, ref } from 'vue'
import Login from './Login.vue'
import { AUTH_EVENT, edrLogout, edrSession } from './api.js'

// 登录页不需要下载或解析管理控制台的大型组件。
const App = defineAsyncComponent({
  loader: () => import('./App.vue'),
  delay: 150,
  timeout: 30000,
  loadingComponent: { render: () => h('div', { class: 'boot', role: 'status' }, '正在加载管理控制台…') },
  errorComponent: { render: () => h('div', { class: 'boot boot-error', role: 'alert' }, [
    h('strong', '控制台加载失败'),
    h('button', { type: 'button', onClick: () => window.location.reload() }, '刷新页面'),
  ]) },
})

const user = ref(null)
const booting = ref(true)
const sessionError = ref(false)
let sessionController = null

function onLogin(u) {
  user.value = u || null
}

async function logout() {
  try { await edrLogout() } catch { /* ignore */ }
  user.value = null
}

function onUnauthorized() {
  const controller = sessionController
  sessionController = null
  controller?.abort()
  booting.value = false
  sessionError.value = false
  user.value = null
}

async function loadSession() {
  sessionController?.abort()
  const controller = new AbortController()
  sessionController = controller
  const timer = setTimeout(() => controller.abort(), 15000)
  booting.value = true
  sessionError.value = false
  try {
    const r = await edrSession(controller.signal)
    if (sessionController !== controller) return
    user.value = r.user
  } catch (error) {
    if (sessionController !== controller) return
    user.value = null
    sessionError.value = error?.status !== 401
  } finally {
    clearTimeout(timer)
    if (sessionController === controller) {
      sessionController = null
      booting.value = false
    }
  }
}

onMounted(() => {
  window.addEventListener(AUTH_EVENT, onUnauthorized)
  loadSession()
})

onBeforeUnmount(() => {
  window.removeEventListener(AUTH_EVENT, onUnauthorized)
  const controller = sessionController
  sessionController = null
  controller?.abort()
})
</script>

<style scoped>
.boot {
  height: 100%; display: flex; align-items: center; justify-content: center; gap: 10px;
  color: var(--muted); font-size: 14px;
}
.boot-dot {
  width: 10px; height: 10px; border-radius: 50%; background: var(--accent);
  animation: boot-pulse 1s ease-in-out infinite;
}
@keyframes boot-pulse { 50% { opacity: .3; transform: scale(.7); } }
.boot-error { flex-direction: column; text-align: center; padding: 24px; }
.boot-error strong { color: var(--ink); font-size: 18px; }
.boot-error p { margin: 0; }
.boot-error button { background: var(--accent); color: white; border: 0; border-radius: 8px; padding: 9px 18px; }
</style>
