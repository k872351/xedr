import { onMounted, ref, watch } from 'vue'

const DENSITY_KEY = 'edr.console.density'
const THEME_KEY = 'edr.console.theme'
const RADIUS_KEY = 'edr.console.radius'
const FONT_KEY = 'edr.console.fontScale'
const WATERMARK_KEY = 'edr.console.watermark'

function applyChrome({ density, theme, radius, fontScale, watermark }) {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  root.dataset.density = density
  root.dataset.theme = theme
  root.dataset.watermark = watermark ? 'on' : 'off'
  root.style.setProperty('--radius', `${radius}px`)
  root.style.setProperty('--radius-sm', `${Math.max(4, Math.round(radius * 0.6))}px`)
  const scale = fontScale === 'large' ? 1.08 : fontScale === 'small' ? 0.92 : 1
  root.style.setProperty('--fs-scale', String(scale))
  root.style.fontSize = `${13.5 * scale}px`
}

/** Persist density, theme, radius, font scale, watermark on <html>. */
export function useConsoleChrome() {
  const density = ref('comfortable')
  const theme = ref('light')
  const radius = ref(10)
  const fontScale = ref('medium')
  const watermark = ref(false)
  const themeDrawerOpen = ref(false)

  onMounted(() => {
    try {
      const d = localStorage.getItem(DENSITY_KEY)
      const t = localStorage.getItem(THEME_KEY)
      const r = Number(localStorage.getItem(RADIUS_KEY))
      const f = localStorage.getItem(FONT_KEY)
      const w = localStorage.getItem(WATERMARK_KEY)
      if (d === 'compact' || d === 'comfortable') density.value = d
      if (t === 'dark' || t === 'light') theme.value = t
      if (Number.isFinite(r) && r >= 0 && r <= 16) radius.value = r
      if (f === 'small' || f === 'medium' || f === 'large') fontScale.value = f
      if (w === '1' || w === 'true') watermark.value = true
    } catch { /* ignore */ }
    applyChrome({
      density: density.value,
      theme: theme.value,
      radius: radius.value,
      fontScale: fontScale.value,
      watermark: watermark.value,
    })
  })

  watch([density, theme, radius, fontScale, watermark], ([d, t, r, f, w]) => {
    applyChrome({ density: d, theme: t, radius: r, fontScale: f, watermark: w })
    try {
      localStorage.setItem(DENSITY_KEY, d)
      localStorage.setItem(THEME_KEY, t)
      localStorage.setItem(RADIUS_KEY, String(r))
      localStorage.setItem(FONT_KEY, f)
      localStorage.setItem(WATERMARK_KEY, w ? '1' : '0')
    } catch { /* ignore */ }
  })

  function toggleDensity() {
    density.value = density.value === 'compact' ? 'comfortable' : 'compact'
  }
  function toggleTheme() {
    const next = theme.value === 'dark' ? 'light' : 'dark'
    theme.value = next
    // 立即写 DOM，避免仅依赖 watch 时偶发不同步
    applyChrome({
      density: density.value,
      theme: next,
      radius: radius.value,
      fontScale: fontScale.value,
      watermark: watermark.value,
    })
  }
  function setTheme(next) {
    if (next !== 'dark' && next !== 'light') return
    theme.value = next
    applyChrome({
      density: density.value,
      theme: next,
      radius: radius.value,
      fontScale: fontScale.value,
      watermark: watermark.value,
    })
  }
  function setDensity(next) {
    if (next === 'compact' || next === 'comfortable') density.value = next
  }
  function setRadius(next) {
    const n = Number(next)
    if (Number.isFinite(n)) radius.value = Math.min(16, Math.max(0, Math.round(n)))
  }
  function setFontScale(next) {
    if (next === 'small' || next === 'medium' || next === 'large') fontScale.value = next
  }
  function setWatermark(next) {
    watermark.value = !!next
  }
  function openThemeDrawer() {
    themeDrawerOpen.value = true
  }
  function closeThemeDrawer() {
    themeDrawerOpen.value = false
  }

  return {
    density, theme, radius, fontScale, watermark, themeDrawerOpen,
    toggleDensity, toggleTheme, setTheme, setDensity, setRadius, setFontScale, setWatermark,
    openThemeDrawer, closeThemeDrawer,
  }
}
