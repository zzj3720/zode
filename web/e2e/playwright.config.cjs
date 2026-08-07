'use strict';

const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: [
    'support/smoke.spec.cjs',
    'support/harness_regressions.spec.cjs',
    'specs/**/*.spec.{cjs,ts}',
  ],
  timeout: 60_000,
  expect: { timeout: 8_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  preserveOutput: 'always',
  outputDir: '../../target/web-e2e-playwright',
  reporter: [['line']],
  use: {
    headless: true,
    trace: 'off',
    video: 'off',
    screenshot: 'off',
    actionTimeout: 8_000,
    navigationTimeout: 12_000,
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
    colorScheme: 'dark',
    locale: 'en-US',
    timezoneId: 'UTC',
    reducedMotion: 'reduce',
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
});
