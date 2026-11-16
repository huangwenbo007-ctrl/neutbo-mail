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
            account_deletion_test_only: 'enabled',
            attachment_origin_test_only: 'enabled',
            attachment_kv_store_id: 'kv:00000000000000000000000000000001',
            google_reauth_redirect_uri: 'https://local.test/login',
          },
        },
      },
    },
  },
});
