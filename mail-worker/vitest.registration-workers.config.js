import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
  test: {
    include: ['test/registration-workers.test.js'],
    poolOptions: {
      workers: {
        main: './src/index.js',
        miniflare: {
          compatibilityDate: '2025-03-10',
          compatibilityFlags: ['nodejs_compat'],
          d1Databases: ['db'],
          kvNamespaces: ['kv'],
          bindings: {
            domain: ['example.com'],
            admin: 'admin@example.com',
            jwt_secret: 'local-integration-tests-only',
            orm_log: false,
          },
        },
      },
    },
  },
});
