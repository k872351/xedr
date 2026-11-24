<template>
  <div v-if="release" class="rel-box" :class="'rel-' + release.status">
    <div class="rel-hd">
      <span class="pill" :class="{ on: release.is_latest }">{{ label }}</span>
      <b v-if="release.version">v{{ release.version }}</b>
      <span v-if="release.build_id" class="muted mono">{{ release.build_id }}</span>
      <span v-if="release.build_time" class="muted">{{ release.build_time }}</span>
    </div>
    <div class="rel-sum">
      <span v-if="release.exe_sha256">SHA256 <code class="mono">{{ release.exe_sha256.slice(0, 16) }}…</code></span>
      <span v-if="release.protocol_max">协议 v{{ release.protocol_min }}–v{{ release.protocol_max }}</span>
      <span>ZIP 安装包</span>
    </div>
    <div class="rel-warn" role="status">MSI 尚未通过独立发布验收，当前不提供 MSI 下载。</div>
    <details v-if="release.capabilities?.length || release.manifest_source_rev" class="rel-caps">
      <summary>构建详情</summary>
      <p v-if="release.manifest_source_rev" class="mono muted">源码 {{ release.manifest_source_rev }} · 当前 {{ release.source_rev }}</p>
      <p v-if="release.capabilities?.length" class="mono">{{ release.capabilities.join(' · ') }}</p>
    </details>
    <div v-for="r in (release.reasons || [])" :key="r" class="rel-warn">{{ r }}</div>
    <slot />
  </div>
</template>

<script setup>
defineProps({ release: Object, label: String })
</script>

<style scoped>
.rel-box {
  margin-top: 10px;
  padding: 10px 12px;
  border: 1px solid var(--line, #e3e6ea);
  border-radius: 8px;
  background: var(--bg-2, #f7f8fa);
}
.rel-box.rel-stale,
.rel-box.rel-unverified,
.rel-box.rel-mismatch,
.rel-box.rel-missing {
  border-color: #e0a030;
}
.rel-hd {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.rel-sum {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 14px;
  margin-top: 6px;
  font-size: 12px;
  color: var(--ink-2);
}
.rel-warn {
  margin-top: 6px;
  font-size: 12px;
  color: #b26a00;
}
.rel-caps {
  margin-top: 6px;
  font-size: 12px;
}
.rel-caps summary {
  cursor: pointer;
  color: var(--muted);
}
.rel-caps p {
  margin: 4px 0 0;
  line-height: 1.5;
}
.pill {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 2px 9px;
  font-size: 11px;
  background: #eef1f6;
  color: var(--muted);
  font-weight: 600;
}
.pill.on {
  background: #e8f8ef;
  color: var(--online, #067647);
}
.mono {
  font-variant-numeric: tabular-nums;
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px;
}
.muted { color: var(--muted); }
</style>
