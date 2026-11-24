import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const buildId = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 12)

// EDR 后台独立部署在自己的端口根路径（edr_server.py，默认 8100）
export default defineConfig({
  plugins: [vue()],
  base: '/',
  define: {
    'import.meta.env.VITE_XEDR_BUILD': JSON.stringify(buildId),
  },
  server: {
    port: 5174,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8100', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
