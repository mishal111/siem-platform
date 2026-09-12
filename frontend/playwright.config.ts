import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  expect: { timeout: 8000 },
  reporter: 'list',
  use: {
    baseURL: process.env.UI_BASE_URL || 'http://127.0.0.1:5173',
    browserName: 'chromium',
    viewport: { width: 1440, height: 1100 },
    trace: 'off',
    screenshot: 'off',
    video: 'off',
    launchOptions: process.env.PW_CHROMIUM_EXECUTABLE
      ? { executablePath: process.env.PW_CHROMIUM_EXECUTABLE }
      : {},
  },
  webServer: process.env.UI_EXTERNAL_SERVER
    ? undefined
    : {
        command: 'npm run dev',
        url: 'http://127.0.0.1:5173',
        reuseExistingServer: !process.env.CI,
        timeout: 30000,
      },
});
