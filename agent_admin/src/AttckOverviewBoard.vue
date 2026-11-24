<template>
  <div class="ak-board">
    <div class="panel ak-chain">
      <div class="panel-hd">
        <div>
          <h3>攻击链路</h3>
          <span class="meta">12 战术矩阵 · 点选筛选下方技术与告警</span>
        </div>
        <button v-if="attckSel.tactic || attckSel.tech" type="button" class="btn-text" @click="emit('clear-selection')">清除筛选</button>
      </div>
      <div class="ak-steps">
        <button
          v-for="(t, i) in attckHeat"
          :key="t.tactic"
          type="button"
          class="ak-step"
          :class="{ hit: t.count, on: attckSel.tactic === t.tactic }"
          :style="attckStepStyle(t)"
          @click="emit('select-tactic', t.tactic)"
        >
          <div class="ak-step-top">
            <span class="ak-no">{{ String(i + 1).padStart(2, '0') }}</span>
            <b>{{ t.name }}</b>
          </div>
          <div class="ak-step-bot">
            <strong>{{ t.count || 0 }}</strong>
            <em>
              <template v-if="t.techniques.length">{{ t.techniques.length }} 项技术<template v-if="t.high"> · 高危 {{ t.high }}</template></template>
              <template v-else>未发现</template>
            </em>
          </div>
        </button>
      </div>
    </div>

    <div class="ak-mid">
      <div class="panel ak-tech">
        <div class="panel-hd">
          <div>
            <h3>技术分布</h3>
            <span class="meta">{{ attckSelTacticName ? `战术：${attckSelTacticName}` : '全部战术' }} · 点击筛选告警</span>
          </div>
        </div>
        <div v-if="attckTechList.length" class="ak-tech-list">
          <button
            v-for="t in attckTechList"
            :key="t.id"
            type="button"
            class="ak-tech-row"
            :class="{ on: attckSel.tech === t.id }"
            @click="emit('select-technique', t)"
          >
            <code>{{ t.id }}</code>
            <span class="ak-tech-name" :title="t.name">{{ t.name || '—' }}</span>
            <span class="ak-tac">{{ t.tactic_name || attckSelTacticName || '—' }}</span>
            <i class="rank-bar"><i :style="{ width: attckRankPct(t.count) + '%' }" /></i>
            <strong>{{ t.count }}</strong>
          </button>
        </div>
        <p v-else class="empty sm">{{ attckSel.tactic ? '该战术下暂无命中技术' : '暂无命中技术' }}</p>
      </div>

      <div class="panel ak-hosts">
        <div class="panel-hd">
          <div>
            <h3>告警主机</h3>
            <span class="meta">点击只看该主机</span>
          </div>
          <button v-if="attckAgent" type="button" class="btn-text" @click="emit('clear-host')">全部主机</button>
        </div>
        <div v-if="attckHosts.length" class="attck-rank">
          <button
            v-for="(h, i) in attckHosts"
            :key="h.host || h.agent_id || i"
            type="button"
            class="rank-row"
            :class="{ on: attckAgent && attckAgent === h.agent_id }"
            @click="emit('select-host', h)"
          >
            <em>{{ i + 1 }}</em>
            <div class="rank-main">
              <b>{{ h.host || h.hostname || short(h.agent_id) }}</b>
              <i class="rank-bar host"><i :style="{ width: attckHostPct(h.count) + '%' }" /></i>
            </div>
            <strong>{{ h.count }}</strong>
          </button>
        </div>
        <p v-else class="empty sm">暂无</p>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  attckSel: { type: Object, required: true }, attckHeat: { type: Array, required: true },
  attckTechList: { type: Array, required: true }, attckSelTacticName: String, attckAgent: String,
  attckHosts: { type: Array, required: true }, attckStepStyle: { type: Function, required: true },
  attckRankPct: { type: Function, required: true }, attckHostPct: { type: Function, required: true }, short: { type: Function, required: true },
})
const emit = defineEmits(['clear-selection', 'select-tactic', 'select-technique', 'clear-host', 'select-host'])
</script>

<style scoped>
.ak-board { flex: 0 0 auto; display: flex; flex-direction: column; gap: 10px; min-height: 0; }
.ak-chain { padding-bottom: 12px; }
.ak-steps {
  display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; padding: 4px 16px 12px;
}
.ak-step {
  position: relative; display: flex; flex-direction: column; gap: 8px;
  min-width: 0; padding: 12px 12px 10px; border: 1px solid #e6eaf0; border-radius: 10px;
  background: #fafbfc; text-align: left; cursor: pointer; overflow: hidden;
  transition: border-color .15s, box-shadow .15s, transform .15s;
}
.ak-step::before {
  content: ''; position: absolute; left: 0; right: 0; top: 0; height: 3px; background: #e6eaf0;
}
.ak-step.hit { background: var(--ak-bg, #fff5f5); border-color: rgba(225, 29, 46, .22); }
.ak-step.hit::before { background: var(--ak-bar, #e11d2e); }
.ak-step:hover { border-color: #94a3b8; transform: translateY(-1px); }
.ak-step.on { border-color: #e11d2e; box-shadow: 0 0 0 2px rgba(225, 29, 46, .18); }
.ak-step-top {
  display: flex; align-items: center; gap: 8px; min-width: 0;
}
.ak-no { font-size: 11px; font-weight: 700; color: #a0aab8; letter-spacing: .04em; flex-shrink: 0; }
.ak-step b {
  font-size: 13px; font-weight: 650; color: var(--ink); min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ak-step-bot {
  display: flex; align-items: baseline; justify-content: space-between; gap: 8px; width: 100%;
}
.ak-step strong { font-size: 22px; line-height: 1; font-weight: 700; color: #c0c8d4; }
.ak-step.hit strong { color: #b4141f; }
.ak-step em {
  font-style: normal; font-size: 11.5px; color: #98a2b3; min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: right;
}
.ak-step.hit em { color: #7a2a30; }

.ak-mid {
  display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(260px, 1fr); gap: 10px; align-items: stretch;
  min-height: 220px; max-height: 280px;
}
.ak-mid > .panel { display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
.ak-tech-list {
  display: flex; flex-direction: column; gap: 2px; padding: 4px 12px 14px; flex: 1; min-height: 0; overflow: auto;
}
.ak-tech-row {
  display: grid; grid-template-columns: 72px minmax(0, 1.2fr) minmax(64px, .7fr) minmax(60px, 1fr) 36px;
  align-items: center; gap: 10px; padding: 9px 8px; border: 0; border-radius: 8px;
  background: transparent; text-align: left; cursor: pointer;
}
.ak-tech-row:hover { background: #f8fafc; }
.ak-tech-row.on { background: #fff1f2; }
.ak-tech-row code {
  font-size: 12px; font-weight: 600; color: #b4141f; background: #fff1f2;
  padding: 2px 6px; border-radius: 6px; justify-self: start;
}
.ak-tech-name {
  font-size: 13px; font-weight: 600; color: var(--ink);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ak-tac {
  font-size: 12px; color: #667085; background: #f2f4f7; border-radius: 6px; padding: 2px 6px;
  justify-self: start; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%;
}
.ak-tech-row .rank-bar { margin-top: 0; }
.ak-tech-row strong { font-size: 15px; font-weight: 700; text-align: right; color: var(--ink); }
.ak-hosts .attck-rank { flex: 1; min-height: 0; overflow: auto; }

.attck-rank {
  padding: 8px 14px 16px; display: flex; flex-direction: column; gap: 6px;
}
.rank-row {
  display: grid; grid-template-columns: 28px 1fr auto; gap: 10px; align-items: center;
  text-align: left; border: 0; background: transparent; padding: 8px 6px; border-radius: 10px;
  cursor: pointer;
}
.rank-row:hover { background: #f8fafc; }
.rank-row.on { background: #eff8ff; }
.rank-row > em {
  font-style: normal; font-size: 12px; font-weight: 700; color: #98a2b3;
  width: 22px; height: 22px; border-radius: 7px; background: #f2f4f7;
  display: inline-flex; align-items: center; justify-content: center;
}
.rank-row:nth-child(-n+3) > em { background: #fff1f0; color: #c2410c; }
.rank-main { min-width: 0; }
.rank-main b {
  display: block; font-size: 13px; font-weight: 650; color: var(--ink);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.rank-bar {
  display: block; height: 6px; border-radius: 99px; background: #eef2f7; margin-top: 6px; overflow: hidden;
}
.rank-bar > i {
  display: block; height: 100%; border-radius: 99px;
  background: linear-gradient(90deg, #fb7185, #e11d2e);
}
.rank-bar.host > i { background: linear-gradient(90deg, #38bdf8, #0284c7); }
.rank-row strong { font-size: 15px; font-weight: 700; color: var(--ink); min-width: 28px; text-align: right; }
.panel { background: #fff; border: 1px solid #e4e7ec; border-radius: 12px; box-shadow: 0 4px 20px rgba(28,30,36,.06); overflow: hidden; }
.panel-hd { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 12px 16px; border-bottom: 1px solid #eceef2; background: linear-gradient(180deg,#fcfcfd,#ffffff); }
.panel-hd h3 { margin: 0; font-size: 14px; font-weight: 650; color: #2b3038; }
.meta { color: var(--muted); font-size: 12px; }
.btn-text { border: 0; background: none; color: var(--accent); font-weight: 600; font-size: 13px; cursor: pointer; }
.empty { padding: 4px 16px 28px; text-align: center; color: #98a2b3; font-size: 12.5px; line-height: 1.7; }
@media (max-width: 1280px) { .ak-steps { grid-template-columns: repeat(4,minmax(0,1fr)); } .ak-mid { max-height: none; } }
@media (max-width: 1100px) { .ak-mid { grid-template-columns: 1fr; max-height: none; } .ak-steps { grid-template-columns: repeat(3,minmax(0,1fr)); } }
</style>
