import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

// Published exports point at dist. The pack test removes it, and vitest does not build first.
export default defineConfig({
  test: { include: ['packages/*/test/**/*.test.ts'] },
  resolve: {
    alias: {
      '@signet/proof': fileURLToPath(new URL('./packages/proof/src/index.ts', import.meta.url)),
    },
  },
})
