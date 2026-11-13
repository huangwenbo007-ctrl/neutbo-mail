import { defineConfig } from 'vitest/config';

export default defineConfig({ test: { environment: 'node', include: ['test/registration-email.test.js'] } });
