import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Hosted Windows Git and filesystem operations routinely take longer than
    // Vitest's five-second unit-test default while remaining well bounded.
    testTimeout: process.platform === 'win32' ? 20_000 : 5_000,
  },
})
