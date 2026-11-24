<script setup>
/**
 * 处置审批页：从 PlatformExtras 解耦的独立入口（仍可被 PlatformExtras 复用）。
 */
import { computed, onMounted, ref, watch } from 'vue'
import { decideResponseApproval, listResponseApprovals } from './api.js'

const props = defineProps({
  isAdmin: { type: Boolean, default: false },
})
const emit = defineEmits(['flash', 'goto'])

const approvals = ref([])
const apprStatus = ref('pending')
const busy = ref(false)
const err = ref('')

const pendingCount = computed(() =>
  approvals.value.filter((x) => x.status === 'pending').length
  || (apprStatus.value === 'pending' ? approvals.value.length : 0),
)

async function loadApprovals() {
  busy.value = true
  err.value = ''
  try {
    const r = await listResponseApprovals({ status: apprStatus.value, limit: 100 })
    approvals.value = r.items || []
    emit('flash', `已加载 ${approvals.value.length} 条`)
  } catch (e) {
    err.value = e?.message || String(e)
  } finally {
    busy.value = false
  }
}

async function decide(id, approve) {
  if (!props.isAdmin) return
  busy.value = true
  try {
    await decideResponseApproval(id, { approve, note: approve ? '批准' : '驳回' })
    await loadApprovals()
    emit('flash', approve ? '已批准并下发' : '已驳回')
  } catch (e) {
    err.value = e?.message || String(e)
  } finally {
    busy.value = false
  }
}

watch(apprStatus, () => loadApprovals())
onMounted(() => loadApprovals())
</script>

<template>
  <div class="mod-page approvals-page">
    <header class="mod-hd">
      <div>
        <h1>处置审批</h1>
        <p class="desc">高危处置先审批再下发；批准后写入终端指令队列。</p>
      </div>
      <div class="mod-hd-actions">
        <select v-model="apprStatus" class="search">
          <option value="pending">待审批</option>
          <option value="approved">已批准</option>
          <option value="rejected">已驳回</option>
          <option value="">全部</option>
        </select>
        <button type="button" class="btn" :disabled="busy" @click="loadApprovals">刷新</button>
        <button type="button" class="btn ghost" @click="emit('goto', 'resp-results')">处置结果</button>
      </div>
    </header>

    <div class="mod-stats">
      <div class="stat"><label>待审批</label><b>{{ pendingCount }}</b></div>
      <div class="stat"><label>本页</label><b>{{ approvals.length }}</b></div>
    </div>

    <p v-if="err" class="err-text">{{ err }}</p>

    <div class="panel">
      <div class="panel-hd">
        <h3>审批列表 <em>（{{ approvals.length }}）</em></h3>
      </div>
      <div v-if="approvals.length" class="mod-list">
        <article v-for="a in approvals" :key="a.id" class="mod-card">
          <div class="mod-card-main">
            <strong>{{ a.action || a.title || a.id }}</strong>
            <small>{{ a.hostname || a.agent_id }} · {{ a.status }} · {{ a.created_at || a.updated_at || '—' }}</small>
            <p v-if="a.reason || a.note" class="muted">{{ a.reason || a.note }}</p>
          </div>
          <div v-if="props.isAdmin && a.status === 'pending'" class="mod-card-actions">
            <button type="button" class="btn sm primary" :disabled="busy" @click="decide(a.id, true)">批准</button>
            <button type="button" class="btn sm ghost" :disabled="busy" @click="decide(a.id, false)">驳回</button>
          </div>
        </article>
      </div>
      <div v-else class="record-empty">
        <strong>{{ busy ? '加载中…' : '暂无记录' }}</strong>
      </div>
    </div>
  </div>
</template>

<style scoped>
.approvals-page { display: grid; gap: 12px; }
.mod-hd { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; flex-wrap: wrap; }
.mod-hd h1 { margin: 0; font-size: 22px; }
.mod-hd .desc { margin: 4px 0 0; color: #657a8e; }
.mod-hd-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.mod-stats { display: flex; gap: 10px; flex-wrap: wrap; }
.stat { border: 1px solid #d8e3ed; border-radius: 10px; background: #fff; padding: 10px 14px; min-width: 96px; }
.stat label { display: block; font-size: 12px; color: #657a8e; }
.stat b { font-size: 18px; }
.panel { border: 1px solid #d8e3ed; border-radius: 10px; background: #fff; padding: 12px; }
.panel-hd h3 { margin: 0; font-size: 14px; }
.panel-hd em { font-style: normal; color: #657a8e; font-weight: 500; }
.mod-list { display: grid; gap: 8px; margin-top: 10px; }
.mod-card { display: flex; justify-content: space-between; gap: 12px; border: 1px solid #e4edf3; border-radius: 10px; padding: 10px 12px; }
.mod-card-main { display: grid; gap: 2px; min-width: 0; }
.mod-card-main small, .muted { color: #657a8e; }
.mod-card-actions { display: flex; gap: 6px; align-items: center; flex-shrink: 0; }
.err-text { color: #b91c1c; }
.record-empty { padding: 24px; text-align: center; color: #657a8e; }
</style>
