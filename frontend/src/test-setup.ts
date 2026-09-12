import '@testing-library/jest-dom/vitest';
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';
import { configureSession } from './api';
afterEach(() => {
  cleanup();
  configureSession(null);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
