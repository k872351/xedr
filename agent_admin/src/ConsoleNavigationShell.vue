<template>
  <!-- 单根包裹：避免双 root 占掉 .app 的 1fr 列，导致透明菜单层挡住顶栏页签点击 -->
  <div class="nav-shell">
  <aside
    class="rail"
    @mouseenter="emit('nav-enter')"
    @mouseleave="emit('nav-leave')"
  >
    <div class="logo" title="xedr 终端安全管理后台">
      <img class="logo-mark" src="/logo.png" alt="xedr" />
      <strong class="logo-name">xedr</strong>
    </div>
    <nav class="rail-nav">
      <button
        v-for="item in railItems"
        :key="item.id"
        type="button"
        class="rail-item"
        :class="{ on: section === item.id }"
        :title="item.label"
        @click="emit('section', item.id)"
      >
        <span class="ico" v-html="safeRailIcon(item.ico)" />
        <em>{{ item.short || item.label }}</em>
        <i v-if="item.id === 'detect' && openEventCount" class="dot-n">{{ openEventCount > 99 ? '99+' : openEventCount }}</i>
      </button>
    </nav>
    <div class="rail-bottom">
      <button type="button" class="rail-user" :title="`${user?.display_name || user?.username || ''}（${user?.role_label || ''}）`" @click.stop="emit('toggle-user')">
        <span class="ru-avatar">{{ userInitial }}</span>
        <em>{{ user?.username }}</em>
      </button>
      <div v-if="userMenuOpen" class="user-pop" @click.stop>
        <div class="up-head">
          <span class="ru-avatar lg">{{ userInitial }}</span>
          <div>
            <strong>{{ user?.display_name || user?.username }}</strong>
            <small>{{ user?.username }} · {{ user?.role_label }}</small>
          </div>
        </div>
        <p v-if="user?.last_login_ip" class="up-meta">本次登录 IP：{{ user.last_login_ip }}</p>
        <button type="button" class="up-item" @click="emit('password')">修改密码</button>
        <button v-if="isAdmin" type="button" class="up-item" @click="emit('accounts')">账号管理</button>
        <button type="button" class="up-item danger" @click="emit('logout')">退出登录</button>
      </div>
    </div>
  </aside>

  <aside
    class="menu"
    :class="{ open: menuVisible }"
    @mouseenter="emit('nav-enter')"
    @mouseleave="emit('nav-leave')"
  >
    <div class="menu-top">
      <h2>{{ sectionTitle }}</h2>
      <button
        type="button"
        class="menu-pin"
        :class="{ on: menuPinned }"
        :title="menuPinned ? '取消固定' : '固定二级菜单'"
        @click="emit('toggle-pin')"
      >{{ menuPinned ? '已固定' : '固定' }}</button>
    </div>
    <template v-for="group in menuGroups" :key="group.title || 'g'">
      <p v-if="group.title" class="menu-group">{{ group.title }}</p>
      <button
        v-for="m in group.items"
        :key="m.id"
        type="button"
        class="menu-item"
        :class="{ on: page === m.id || (m.id === 'events' && (page === 'threat-view' || page === 'events')) || (m.id === 'malware' && page === 'malware') || (m.id === 'whitelist' && page === 'rules' && rulesSection === 'whitelist') }"
        @click="emit('page', m.id)"
      >{{ m.label }}</button>
    </template>
  </aside>
  </div>
</template>

<script setup>
import { safeRailIcon } from './safeRailIcon.js'
defineProps({
  railItems: { type: Array, required: true }, section: String, page: String, rulesSection: String,
  openEventCount: Number, user: Object, userInitial: String, isAdmin: Boolean, userMenuOpen: Boolean,
  menuVisible: Boolean, menuPinned: Boolean, sectionTitle: String, menuGroups: { type: Array, required: true },
})
const emit = defineEmits(['nav-enter', 'nav-leave', 'section', 'page', 'toggle-user', 'password', 'accounts', 'logout', 'toggle-pin'])
</script>

<style scoped>
.nav-shell {
  width: 76px;
  height: 100%;
  min-height: 100vh;
  position: relative;
  /* 高于页面 sticky 表头，避免「启用/标题」等表头穿透二级菜单 */
  z-index: 520;
  flex: none;
}
.rail {
  position: relative;
  z-index: 490;
  background: linear-gradient(180deg, #0a101c 0%, #121a2a 55%, #0f1624 100%);
  color: #8b9cb3;
  display: flex;
  flex-direction: column;
  padding: 10px 6px 8px;
  border-right: 1px solid rgba(255,255,255,.04);
  height: 100%;
  box-sizing: border-box;
  overflow: visible;
  min-height: 0;
}
.logo {
  display: flex; flex-direction: column; align-items: center; gap: 6px;
  padding: 6px 4px 12px; color: #fff;
  border-bottom: 1px solid rgba(255,255,255,.06);
  margin-bottom: 8px;
  flex-shrink: 0;
}
.logo-mark {
  width: 36px; height: 36px; border-radius: 10px;
  object-fit: contain; background: #0b1220;
  box-shadow: 0 6px 16px rgba(0, 0, 0, .35);
  display: block;
}
.logo-name {
  font-size: 12px; font-weight: 700; letter-spacing: .08em;
  color: #e8eef8; line-height: 1; text-transform: lowercase;
}
.rail-nav { display: flex; flex-direction: column; gap: 2px; flex: 1; min-height: 0; overflow: auto; }
.rail-item {
  position: relative; border: 0; background: transparent; color: inherit;
  border-radius: 12px; padding: 10px 4px 9px; text-align: center;
  display: flex; flex-direction: column; gap: 5px; align-items: center;
  transition: background .15s, color .15s;
  outline: none;
  box-shadow: none;
}
.rail-item:focus,
.rail-item:focus-visible {
  outline: none;
  box-shadow: none;
}
.rail-item::before {
  content: ''; position: absolute; left: -8px; top: 50%; transform: translateY(-50%);
  width: 3px; height: 0; border-radius: 0 3px 3px 0; background: #e11d2e;
  transition: height .15s;
}
.rail-item:hover { background: rgba(255,255,255,.05); color: #dbe7f7; }
.rail-item.on {
  background: rgba(226, 86, 44, .28); color: #fff;
  box-shadow: inset 0 0 0 1px rgba(226, 86, 44, .32);
}
.rail-item.on:focus,
.rail-item.on:focus-visible {
  outline: none;
  box-shadow: inset 0 0 0 1px rgba(226, 86, 44, .32);
}
.rail-item.on::before { height: 22px; }
.rail-item .ico {
  display: grid; place-items: center; width: 24px; height: 24px; opacity: .88;
}
.rail-item.on .ico { opacity: 1; color: #fecaca; }
.rail-item em {
  font-style: normal; font-size: 11px; font-weight: 600;
  letter-spacing: .02em; line-height: 1.1; white-space: nowrap;
}
.dot-n {
  position: absolute; top: 4px; right: 4px; min-width: 16px; height: 16px;
  padding: 0 4px; border-radius: 999px; background: #f97316; color: #fff;
  font-size: 10px; font-style: normal; font-weight: 700;
  display: grid; place-items: center; box-shadow: 0 0 0 2px #0f1624;
}
.rail-bottom {
  position: relative; margin-top: auto; padding-top: 10px; padding-bottom: 4px;
  border-top: 1px solid rgba(255,255,255,.06); text-align: center;
  flex-shrink: 0;
}
.rail-user {
  width: 100%; border: 0; background: transparent; color: #a9b8cd; border-radius: 12px;
  padding: 8px 4px 10px; display: flex; flex-direction: column; align-items: center; gap: 6px;
  min-height: 64px; box-sizing: border-box;
}
.rail-user:hover { background: rgba(255,255,255,.05); color: #e8eef8; }
.rail-user em {
  font-style: normal; font-size: 11px; font-weight: 600; max-width: 100%;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  line-height: 1.2; display: block;
}
.ru-avatar {
  width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center; flex: none;
  background: linear-gradient(145deg, #334155, #1e293b); color: #e2e8f0;
  font-size: 13px; font-weight: 700; box-shadow: inset 0 0 0 1px rgba(255,255,255,.12);
}
.ru-avatar.lg { width: 38px; height: 38px; font-size: 15px; background: linear-gradient(145deg, #3b82f6, #1d4ed8); color: #fff; }
.ru-avatar.sm { width: 28px; height: 28px; font-size: 12px; background: var(--accent-soft); color: var(--accent); box-shadow: none; }
.user-pop {
  position: absolute; left: calc(100% + 10px); bottom: 4px; z-index: 50; width: 230px;
  background: var(--panel, #fff); color: var(--ink); text-align: left; border-radius: 12px; padding: 8px;
  border: 1px solid var(--line); box-shadow: 0 12px 36px rgba(15, 23, 36, .18);
}
.up-head { display: flex; align-items: center; gap: 10px; padding: 8px 8px 10px; border-bottom: 1px solid var(--line-2); }
.up-head strong { display: block; font-size: 14px; color: var(--ink); }
.up-head small { color: var(--muted); font-size: 12px; }
.up-meta { margin: 8px 8px 4px; font-size: 11px; color: var(--muted); }
.up-item {
  display: block; width: 100%; text-align: left; border: 0; background: transparent;
  padding: 9px 10px; border-radius: 8px; font-size: 13px; color: var(--ink-2);
}
.up-item:hover { background: var(--line-2); color: var(--ink); }
.up-item.danger { color: var(--danger, #e11d48); }
.up-item.danger:hover { background: color-mix(in srgb, var(--danger, #e11d48) 12%, transparent); }
.menu {
  /* 顶到顶：避免白底页签压在二级菜单列上形成「主机」白条 */
  position: fixed; left: 76px; top: 0; bottom: 0; width: 212px; z-index: 40;
  background: linear-gradient(180deg, #23262c 0%, #1b1e23 100%);
  border-right: 1px solid rgba(255, 255, 255, .07);
  padding: 16px 12px 20px; overflow: auto;
  box-shadow: none;
  transform: translateX(-8px); opacity: 0; visibility: hidden;
  pointer-events: none;
  transition: opacity .16s ease, transform .16s ease, visibility .16s;
}
.menu.open {
  display: block;
  z-index: 480;
  opacity: 1; visibility: visible; pointer-events: auto; transform: translateX(0);
}
.menu:not(.open) {
  /* 彻底退出命中测试，避免部分浏览器对 opacity:0 层仍拦截点击 */
  display: none !important;
}
.menu-top {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  margin-bottom: 10px; padding: 0 4px;
}
.menu h2 { margin: 0; font-size: 15px; font-weight: 700; }
.menu-pin {
  border: 1px solid var(--line); background: #fff; border-radius: 999px;
  padding: 3px 9px; font-size: 11px; font-weight: 650; color: var(--muted); cursor: pointer;
}
.menu-pin.on { border-color: #93c5fd; background: #eff6ff; color: #1d4ed8; }
.menu-group {
  margin: 14px 12px 6px; font-size: 11px; font-weight: 700; color: #98a2b3;
  letter-spacing: .04em;
}
.menu-item {
  width: 100%; text-align: left; border: 0; background: transparent;
  border-radius: 8px; padding: 9px 12px; color: var(--ink-2); font-size: 13px; font-weight: 500;
}
.menu-item:hover { background: var(--line-2); }
.menu-item.on { background: var(--accent-soft); color: var(--accent); font-weight: 650; }
.menu-hint {
  margin-top: 18px; padding: 10px 12px; border-radius: 8px;
  background: #f7f9fc; color: var(--muted); font-size: 11px; line-height: 1.55;
}
.menu-hint.soft { background: #f8fafc; border: 1px dashed #e4e7ec; }
.rail {
  background:
    radial-gradient(130% 55% at 0% 0%, rgba(226, 86, 44, .14), transparent 60%),
    linear-gradient(180deg, #23262c 0%, #1c1f24 55%, #17191e 100%);
  border-right-color: rgba(255, 255, 255, .06);
}
.logo { border-bottom-color: rgba(255, 255, 255, .08); }
.logo-mark {
  background: #12161c;
  box-shadow: 0 6px 18px rgba(0, 0, 0, .45), inset 0 0 0 1px rgba(255, 255, 255, .08);
}
.logo-name { color: #eef1f5; letter-spacing: .12em; }
.rail-item { color: #98a3b0; }
.rail-item:hover { background: rgba(255, 255, 255, .07); color: #f4f6f9; }
.rail-item.on {
  background: linear-gradient(100deg, rgba(226, 86, 44, .34), rgba(226, 86, 44, .08));
  color: #fff;
  box-shadow: inset 0 0 0 1px rgba(244, 122, 82, .36);
}
.rail-item.on:focus,
.rail-item.on:focus-visible {
  outline: none !important;
  box-shadow: inset 0 0 0 1px rgba(244, 122, 82, .36);
}
.rail-item.on .ico { color: #ffb094; }
.rail-item::before { background: #f47a52; box-shadow: 0 0 10px rgba(226, 86, 44, .75); }
.dot-n { box-shadow: 0 0 0 2px #17191e, 0 0 10px rgba(249, 115, 22, .5); }
.rail-bottom { border-top-color: rgba(255, 255, 255, .08); }
.ru-avatar { background: linear-gradient(145deg, #4b515b, #2b2f37); color: #eef1f5; }

/* Secondary menu: graphite panel with the exact reference styling —
   grouped dividers, right chevrons, vermilion active item */
.menu {
  background: linear-gradient(180deg, #23262c 0%, #1b1e23 100%);
  border-right-color: rgba(255, 255, 255, .07);
  box-shadow: 10px 0 30px rgba(12, 14, 20, .3);
}
.menu-top { border-bottom-color: rgba(255, 255, 255, .08); padding-bottom: 12px; }
.menu h2 { color: #f2f4f7; font-weight: 700; letter-spacing: .02em; }
.menu-pin { border-color: rgba(255, 255, 255, .18); background: rgba(255, 255, 255, .06); color: #b6c0cc; }
.menu-pin:hover { border-color: #f47a52; color: #ffb094; }
.menu-pin.on { border-color: #e2562c; background: rgba(226, 86, 44, .22); color: #ffc0a8; }
.menu-group {
  color: #7d8896; letter-spacing: .05em;
  border-top: 1px solid rgba(255, 255, 255, .08);
  padding-top: 12px;
}
.menu-item { position: relative; padding-right: 30px; color: #b9c2cd; border-radius: 8px; }
.menu-item::after {
  content: '›'; position: absolute; right: 11px; top: 50%; transform: translateY(-54%);
  font-size: 18px; line-height: 1; color: #6c7683; font-weight: 400;
}
.menu-item:hover { background: rgba(255, 255, 255, .06); color: #f4f6f9; }
.menu-item:hover::after { color: #b9c2cd; }
.menu-item.on {
  background: linear-gradient(100deg, #e2562c 0%, #c8451e 100%);
  color: #fff; font-weight: 650;
  box-shadow: 0 4px 14px rgba(226, 86, 44, .38), inset 0 1px 0 rgba(255, 255, 255, .2);
}
.menu-item.on::after { color: #fff; }
.menu-hint { background: rgba(255, 255, 255, .06); color: #aab4c0; border: 1px solid rgba(255, 255, 255, .07); }
.menu-hint.soft { border-style: dashed; color: #9aa5b2; }
@media (max-width: 1100px) { .menu { width: 200px; } }
</style>
