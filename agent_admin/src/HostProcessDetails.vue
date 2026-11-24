<template>
  <div class="sd-actions">
    <h4>进程关系</h4>
    <dl class="sd-dl compact-gap">
      <div>
        <dt>父进程</dt>
        <dd>
          <button
            v-if="snapRow.parent_name || snapRow.ppid"
            type="button"
            class="btn-text"
            @click="emit('pid', snapRow.ppid)"
          >{{ snapRow.parent_name || '—' }} ({{ snapRow.ppid }})</button>
          <span v-else>—</span>
        </dd>
      </div>
      <div v-if="snapRow.risk_tags">
        <dt>风险标签</dt>
        <dd>{{ snapRow.risk_tags }}</dd>
      </div>
      <div v-if="snapRow.module_count != null">
        <dt>模块数</dt>
        <dd>共 {{ snapRow.module_count }} · 第三方/可疑 {{ snapRow.module_third_count || processDlls.length }}</dd>
      </div>
    </dl>
    <div v-if="childProcesses.length" class="child-list">
      <small>子进程 ({{ childProcesses.length }})</small>
      <button
        v-for="c in childProcesses"
        :key="c.pid"
        type="button"
        class="child-row"
        @click="emit('select-row', c)"
      >
        <b>{{ c.name }}</b>
        <em>PID {{ c.pid }}</em>
      </button>
    </div>
    <div v-if="processDlls.length" class="dll-list">
      <small>已加载 DLL（已过滤 System32）· {{ processDlls.length }} · 点击查看详情</small>
      <button
        v-for="(d, i) in processDlls"
        :key="i"
        type="button"
        class="dll-row"
        :class="{ hot: d.hot || d.unsigned, on: selectedDll === d }"
        @click="emit('select-dll', d)"
      >
        <b :title="d.path">{{ d.name || '—' }}</b>
        <em :title="d.path">{{ shortPath(d.path || '') }}</em>
        <span v-if="d.hot" class="sev" data-s="high">可疑路径</span>
        <span v-else-if="d.unsigned" class="sev" data-s="medium">未签名</span>
        <span v-else-if="d.signed" class="sev" data-s="info">{{ d.signed }}</span>
      </button>
      <div v-if="selectedDll" class="dll-detail">
        <h5>{{ selectedDll.name || '模块详情' }}</h5>
        <dl class="sd-dl compact-gap">
          <div><dt>模块名</dt><dd>{{ selectedDll.name || '—' }}</dd></div>
          <div><dt>完整路径</dt><dd class="mono" :title="selectedDll.path">{{ selectedDll.path || '—' }}</dd></div>
          <div><dt>签名</dt><dd>
            <span class="sev" :data-s="selectedDll.unsigned ? 'medium' : (selectedDll.signed === 'Valid' ? 'info' : 'low')">
              {{ selectedDll.signed || '—' }}
            </span>
          </dd></div>
          <div v-if="selectedDll.signer"><dt>签名者</dt><dd :title="selectedDll.signer">{{ selectedDll.signer }}</dd></div>
          <div v-if="selectedDll.company"><dt>公司</dt><dd>{{ selectedDll.company }}</dd></div>
          <div v-if="selectedDll.file_version"><dt>文件版本</dt><dd>{{ selectedDll.file_version }}</dd></div>
          <div v-if="selectedDll.size"><dt>大小</dt><dd>{{ fmtSize(selectedDll.size) }}</dd></div>
          <div v-if="selectedDll.sha256"><dt>SHA256</dt><dd class="mono" :title="selectedDll.sha256">{{ selectedDll.sha256 }}</dd></div>
          <div v-if="selectedDll.hot"><dt>风险</dt><dd><span class="sev" data-s="high">可疑路径</span></dd></div>
        </dl>
        <div class="row" style="margin-top:8px;gap:8px">
          <button v-if="selectedDll.path" type="button" class="btn sm" @click="emit('copy', selectedDll.path)">复制路径</button>
          <button v-if="selectedDll.sha256" type="button" class="btn sm" @click="emit('copy', selectedDll.sha256)">复制哈希</button>
        </div>
      </div>
    </div>
    <p v-else-if="snapRow.module_count" class="hint">该进程模块均为系统目录 DLL，或尚未完成模块采集（请「立即刷新」）。</p>
  </div>
</template>

<script setup>
defineProps({ snapRow: { type: Object, required: true }, childProcesses: { type: Array, required: true }, processDlls: { type: Array, required: true }, selectedDll: Object, shortPath: { type: Function, required: true }, fmtSize: { type: Function, required: true } })
const emit = defineEmits(['pid', 'select-row', 'select-dll', 'copy'])
</script>

<style scoped>
.child-list { display: flex; flex-direction: column; gap: 4px; margin-top: 8px; }
.child-list > small { color: var(--muted); font-size: 11px; }
.child-row {
  display: flex; justify-content: space-between; gap: 8px; text-align: left;
  border: 1px solid var(--line); background: #fafbfd; border-radius: 8px;
  padding: 6px 10px; font-size: 12px; cursor: pointer;
}
.child-row:hover { border-color: #b7c9f0; background: #f4f7fb; }
.child-row em { color: var(--muted); font-style: normal; }
.dll-list {
  margin-top: 12px; display: flex; flex-direction: column; gap: 6px;
}
.dll-list > small { color: var(--muted); font-size: 12px; font-weight: 650; }
.dll-row {
  display: grid; grid-template-columns: minmax(100px, 140px) 1fr auto; gap: 8px; align-items: center;
  padding: 7px 10px; border-radius: 8px; background: #f8fafc; border: 1px solid #eef2f7;
  text-align: left; width: 100%; cursor: pointer; color: inherit;
}
.dll-row:hover { border-color: #c7d7f0; background: #f5f8ff; }
.dll-row.hot { background: #fff7ed; border-color: #fed7aa; }
.dll-row.on { border-color: #93c5fd; background: #eff6ff; box-shadow: 0 0 0 1px #bfdbfe; }
.dll-row b { font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dll-row em { font-style: normal; font-size: 11px; color: #667085; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dll-detail {
  margin-top: 4px; padding: 12px; border-radius: 10px;
  border: 1px solid #dbe7f3; background: #fff;
}
.dll-detail h5 { margin: 0 0 10px; font-size: 13px; font-weight: 700; }
.dll-detail .mono { font-family: ui-monospace, Consolas, monospace; font-size: 11.5px; word-break: break-all; }
.sd-actions { padding: 10px 12px 14px; border-top: 1px solid var(--line); }
.sd-actions h4 { margin: 0 0 8px; font-size: 12px; }
.sd-dl { margin: 0; padding: 12px 16px; overflow: auto; flex: 1; display: flex; flex-direction: column; gap: 10px; }
.sd-dl.compact-gap { padding-top: 0; }
.sd-dl > div { display: grid; grid-template-columns: 100px 1fr; gap: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--line-2); font-size: 12px; }
.sd-dl dt { color: var(--muted); margin: 0; }
.sd-dl dd { margin: 0; word-break: break-all; font-weight: 500; color: var(--ink); white-space: pre-wrap; }
.btn-text { border: 0; background: none; color: var(--accent); font-weight: 600; font-size: 13px; cursor: pointer; }
.btn { border: 1px solid var(--line); background: #fff; border-radius: 8px; padding: 5px 10px; font-size: 12px; font-weight: 600; color: var(--ink-2); cursor: pointer; }
.btn:hover { border-color: #cfd7e6; }
.row { display: flex; align-items: center; flex-wrap: wrap; }
.hint { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
.sev { display: inline-flex; align-items: center; gap: 5px; padding: 2px 9px; border-radius: 6px; font-size: 11.5px; font-weight: 700; line-height: 1.6; white-space: nowrap; }
.sev::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.sev[data-s=high] { color: var(--sev-high); background: var(--sev-high-bg); }
.sev[data-s=medium] { color: var(--sev-medium); background: var(--sev-medium-bg); }
.sev[data-s=low] { color: var(--sev-low); background: var(--sev-low-bg); }
.sev[data-s=info] { color: var(--sev-info); background: var(--sev-info-bg); }
</style>
