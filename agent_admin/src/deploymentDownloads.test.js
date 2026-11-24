import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { downloadInstallPackage, downloadLinuxInstallPackage } from './api.js'

test('release metadata preserves build evidence and parent download guard', () => {
  const app = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  const metadata = readFileSync(new URL('./ReleaseMetadata.vue', import.meta.url), 'utf8')
  assert.match(app, /<ReleaseMetadata :release="release" :label="releaseLabel">/)
  assert.match(app, /windowsDownloadBlocked/)
  for (const field of ['exe_sha256', 'build_id', 'manifest_source_rev', 'effective_server_url', 'capabilities', 'reasons']) assert.ok(metadata.includes(`release.${field}`))
  assert.match(metadata, /<slot\s*\/>/)
  assert.match(metadata, /MSI 尚未通过独立发布验收/)
  assert.match(metadata, /当前分发格式：ZIP/)
})

test('release lookup failures are visible instead of silently disabling download', () => {
  const app = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  assert.match(app, /v-if="releaseLoadError"[^>]*role="alert"/)
  assert.match(app, /windowsDownloadBlocked/)
  assert.match(app, /request !== releaseRequest \|\| arch !== releaseArch\.value/)
  assert.match(app, /releaseLoadError\.value = error\?\.message/)
  assert.match(app, /:disabled="!!windowsDownloadBlocked \|\| dlBusy"/)
  assert.match(app, /async function refreshDeployAddress/)
  assert.match(app, /async function loadDeployPage/)
  assert.match(app, /loadDeployPage\(\)/)
  assert.match(app, /dlError\.value = blocked/)
  assert.doesNotMatch(app, /release\.value = null/)
})

test('deployment downloads use platform-specific architecture routes', async (t) => {
  const requests = []
  const filenames = []
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    requests.push([url, options.credentials])
    return new Response(new Uint8Array([1, 2, 3]), {
      headers: { 'content-length': '3' },
    })
  })

  const previousDocument = globalThis.document
  globalThis.document = {
    createElement() {
      return { click() { filenames.push(this.download) } }
    },
  }
  t.after(() => {
    if (previousDocument === undefined) delete globalThis.document
    else globalThis.document = previousDocument
  })

  const architectures = ['amd64', 'arm64', 'loong64', 'riscv64']
  for (const arch of architectures) {
    const progress = []
    await downloadLinuxInstallPackage(arch, event => progress.push(event))
    assert.equal(progress.at(-1).received, 3)
  }
  await downloadInstallPackage('amd64', () => {})

  assert.deepEqual(requests, [
    ...architectures.map(arch => [`/api/agent/linux-package?arch=${arch}`, 'include']),
    ['/api/agent/install-package?arch=amd64', 'include'],
  ])
  assert.deepEqual(filenames, [
    ...architectures.map(arch => `ForensicAgent_linux_${arch}.tar.gz`),
    'ForensicAgent_windows_amd64.zip',
  ])
  await assert.rejects(downloadLinuxInstallPackage('invalid'), /Linux architecture/)
})

test('Linux package build errors are reported to the download UI', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => new Response(
    JSON.stringify({ detail: 'Go toolchain is unavailable on the backend' }),
    { status: 503, headers: { 'content-type': 'application/json' } },
  ))
  await assert.rejects(downloadLinuxInstallPackage('amd64'), /Go toolchain is unavailable/)
})
