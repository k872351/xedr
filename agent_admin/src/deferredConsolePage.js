import { defineAsyncComponent, h } from 'vue'

// Only view loading is deferred; parent state and requests remain unchanged.
const LoadingPage = {
  render: () => h('div', { class: 'console-page-loading', role: 'status', style: { padding: '24px', color: 'var(--muted)' } }, '正在加载页面…'),
}
const FailedPage = {
  render: () => h('div', { class: 'console-page-loading', role: 'alert', style: { padding: '24px', color: 'var(--danger)' } }, [
    h('p', '页面加载失败，请刷新页面重试。'),
    h('button', { type: 'button', onClick: () => window.location.reload() }, '刷新页面'),
  ]),
}

export function deferredConsolePage(loader) {
  return defineAsyncComponent({ loader, delay: 150, timeout: 30000, loadingComponent: LoadingPage, errorComponent: FailedPage })
}
