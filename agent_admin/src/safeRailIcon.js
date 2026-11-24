/** Allow only static SVG icon snippets for v-html rail icons. */
export function safeRailIcon(raw) {
  const s = String(raw || '')
  if (!s.startsWith('<svg') || s.length > 1200) return ''
  if (/<script|on\w+\s*=|javascript:/i.test(s)) return ''
  return s
}
