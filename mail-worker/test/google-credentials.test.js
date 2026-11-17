import { afterEach, describe, expect, it, vi } from 'vitest';
import { googleCredentials } from '../src/service/google-credentials';
import oauthService from '../src/service/oauth-service';
import settingService from '../src/service/setting-service';

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('Google credentials', () => {
  const stored = { googleClientId: 'stored-id', googleClientSecret: 'stored-secret' };
  it('uses a complete Worker pair instead of stored credentials', () => {
    expect(googleCredentials({ google_oauth_client_id: 'worker-id', google_oauth_client_secret: 'worker-secret' }, stored))
      .toEqual({ id: 'worker-id', secret: 'worker-secret' });
  });
  it('never combines credentials from different sources', () => {
    expect(googleCredentials({ google_oauth_client_id: 'worker-id' }, stored)).toBeNull();
    expect(googleCredentials({ google_oauth_client_secret: 'worker-secret' }, stored)).toBeNull();
  });
  it('preserves existing database configuration when no Worker pair exists', () => {
    expect(googleCredentials({}, stored)).toEqual({ id: 'stored-id', secret: 'stored-secret' });
    expect(googleCredentials({}, {})).toBeNull();
  });
});

it('exchanges the Google code with the matching Worker credentials and PKCE verifier', async () => {
  vi.spyOn(settingService, 'query').mockResolvedValue({ googleSwitch: 0, googleClientId: 'old-id', googleClientSecret: 'old-secret' });
  vi.spyOn(oauthService, 'saveAndLogin').mockResolvedValue({ token: 'test' });
  const fetchMock = vi.fn()
    .mockResolvedValueOnce({ ok: true, json: async () => ({ access_token: 'temporary' }) })
    .mockResolvedValueOnce({ ok: true, json: async () => ({ sub: 'subject', email: 'person@example.com' }) });
  vi.stubGlobal('fetch', fetchMock);
  const c = { env: { google_oauth_client_id: 'worker-id', google_oauth_client_secret: 'worker-secret' } };
  await oauthService.googleLogin(c, { code: 'code', redirectUri: 'https://example.com/login', codeVerifier: 'a'.repeat(64) });
  const sent = new URLSearchParams(fetchMock.mock.calls[0][1].body);
  expect(sent.get('client_id')).toBe('worker-id');
  expect(sent.get('client_secret')).toBe('worker-secret');
  expect(sent.get('code_verifier')).toBe('a'.repeat(64));
});

it('rejects partial Worker credentials before contacting Google', async () => {
  vi.spyOn(settingService, 'query').mockResolvedValue({ googleSwitch: 0, googleClientId: 'old-id', googleClientSecret: 'old-secret' });
  const fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  await expect(oauthService.googleLogin({ env: { google_oauth_client_id: 'worker-id' } },
    { code: 'code', redirectUri: 'https://example.com/login', codeVerifier: 'a'.repeat(64) })).rejects.toThrow();
  expect(fetchMock).not.toHaveBeenCalled();
});
