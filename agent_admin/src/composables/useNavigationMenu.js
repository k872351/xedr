import { computed, onScopeDispose, ref } from 'vue'

// The shell only owns its local visibility and delayed hover state.
export function useNavigationMenu() {
  const menuPinned = ref(false)
  const menuHover = ref(false)
  let menuLeaveTimer = null
  const menuVisible = computed(() => menuPinned.value || menuHover.value)
  function onNavEnter() {
    if (menuLeaveTimer) {
      clearTimeout(menuLeaveTimer)
      menuLeaveTimer = null
    }
    menuHover.value = true
  }
  function onNavLeave() {
    if (menuLeaveTimer) clearTimeout(menuLeaveTimer)
    menuLeaveTimer = setTimeout(() => {
      menuHover.value = false
      menuLeaveTimer = null
    }, 180)
  }
  onScopeDispose(() => {
    if (menuLeaveTimer) clearTimeout(menuLeaveTimer)
    menuLeaveTimer = null
  })
  return { menuPinned, menuHover, menuVisible, onNavEnter, onNavLeave }
}
