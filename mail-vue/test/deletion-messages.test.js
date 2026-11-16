import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createI18n } from 'vue-i18n';
import zh from '../src/i18n/zh.js';
import en from '../src/i18n/en.js';

for (const [locale, messages] of Object.entries({ zh, en })) {
  test(`account deletion text renders support email in ${locale}`, () => {
    const i18n = createI18n({ legacy: false, locale, messages: { [locale]: messages } });
    for (const key of ['deletionUnavailable', 'deletionGraceInfo']) {
      assert.match(i18n.global.t(key), /support@neutbo\.com/);
    }
  });
}
