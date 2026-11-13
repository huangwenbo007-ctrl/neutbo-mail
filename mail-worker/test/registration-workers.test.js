import { SELF, env, fetchMock } from 'cloudflare:test';
import { beforeEach, afterEach, expect, it } from 'vitest';
import settingService from '../src/service/setting-service';

beforeEach(async () => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
  const response = await SELF.fetch('https://local.test/api/init/local-integration-tests-only');
  expect(await response.text()).toBe('success');
  await env.db.prepare('UPDATE setting SET register=0, reg_key=1, register_verify=1, resend_tokens=?')
    .bind(JSON.stringify({'example.com':'test-resend-token'})).run();
  await refresh();
});
afterEach(() => { fetchMock.assertNoPendingInterceptors(); fetchMock.deactivate(); });

async function refresh() { await settingService.refresh({env, set() {}}); }
async function post(path, body) {
  const response = await SELF.fetch('https://local.test/api' + path, {
    method:'POST', headers:{'Content-Type':'application/json', 'CF-Connecting-IP':'192.0.2.20'}, body:JSON.stringify(body),
  });
  return response.json();
}
async function proof() {
  let sentCode;
  fetchMock.get('https://api.resend.com').intercept({path:'/emails', method:'POST'}).reply(200, (options) => {
    const mail = JSON.parse(options.body);
    expect(mail.from).toContain('no-reply@example.com');
    expect(mail.to).toEqual(['receiver@external.test']);
    sentCode = mail.text.match(/\b\d{6}\b/)[0];
    return JSON.stringify({id:'mock-email-id'});
  });
  const result = await post('/register/email-code', {externalEmail:'receiver@external.test'});
  expect(result.code).toBe(200);
  return {externalEmail:'receiver@external.test', emailChallenge:result.data.challenge, emailVerificationCode:sentCode};
}

it('initializes the verification schema and rejects registration without email proof', async () => {
  const response = await SELF.fetch('https://local.test/api/register', {
    method: 'POST', headers: {'Content-Type':'application/json', 'CF-Connecting-IP':'192.0.2.20'},
    body: JSON.stringify({ email:'new@example.com', password:'test-password' }),
  });
  const result = await response.json();
  expect(result.code).not.toBe(200);
  const row = await env.db.prepare("SELECT count(*) AS n FROM user WHERE email='new@example.com'").first();
  expect(row.n).toBe(0);
});

it('registers and logs in with an emailed code, then rejects replay', async () => {
  const verified = await proof();
  expect((await post('/register', {email:'verified@example.com', password:'test-password', ...verified})).code).toBe(200);
  const login = await post('/login', {email:'verified@example.com', password:'test-password'});
  expect(login.code).toBe(200);
  expect(typeof login.data.token).toBe('string');
  expect((await post('/register', {email:'replay@example.com', password:'test-password', ...verified})).code).not.toBe(200);
});

it('keeps invitation and Turnstile checks before email code consumption', async () => {
  const verified = await proof();
  await env.db.prepare('UPDATE setting SET reg_key=0, register_verify=0').run();
  await refresh();
  const params = {email:'protected@example.com', password:'test-password', ...verified};
  expect((await post('/register', params)).code).not.toBe(200);
  const role = await env.db.prepare('SELECT role_id FROM role LIMIT 1').first();
  await env.db.prepare("INSERT INTO reg_key (code,count,role_id,expire_time) VALUES ('test-invite',1,?,'2099-01-01 00:00:00')").bind(role.role_id).run();
  expect((await post('/register', {...params, code:'test-invite'})).code).toBe(400);
  fetchMock.get('https://challenges.cloudflare.com').intercept({path:'/turnstile/v0/siteverify',method:'POST'}).reply(200,JSON.stringify({success:true}));
  expect((await post('/register', {...params, code:'test-invite',token:'test-turnstile'})).code).toBe(200);
  expect((await env.db.prepare("SELECT count FROM reg_key WHERE code='test-invite'").first()).count).toBe(0);
});

it('rejects mail provider errors without returning a usable challenge', async () => {
  fetchMock.get('https://api.resend.com').intercept({path:'/emails',method:'POST'}).reply(403,JSON.stringify({name:'validation_error',message:'test failure'}));
  const result = await post('/register/email-code',{externalEmail:'receiver@external.test'});
  expect(result.code).not.toBe(200);
  expect(result.data).toBeUndefined();
});

it.each([
  [401, 'API key is invalid: re_private_test_value', 'Resend 密钥无效或未启用'],
  [403, 'The example.com domain is not verified. Please, add and verify your domain.', '发信域名尚未通过 Resend 验证'],
])('reports a safe diagnosis for provider status %s', async (status, message, expected) => {
  fetchMock.get('https://api.resend.com').intercept({path:'/emails',method:'POST'}).reply(status,JSON.stringify({name:'validation_error',message}));
  const result = await post('/register/email-code',{externalEmail:'receiver@external.test'});
  expect(result.code).not.toBe(200);
  expect(result.message).toContain(expected);
  expect(result.message).not.toContain('re_private_test_value');
  expect(result.data).toBeUndefined();
});

it('also requires email proof for first-time OAuth account binding', async () => {
  await env.db.prepare("INSERT INTO oauth (oauth_user_id,platform,user_id) VALUES ('test-oauth-user','github',0)").run();
  const params = {email:'oauth@example.com', oauthUserId:'test-oauth-user'};
  const bind = async (body) => {
    const response = await SELF.fetch('https://local.test/api/oauth/bindUser', {
      method:'PUT', headers:{'Content-Type':'application/json','CF-Connecting-IP':'192.0.2.20'}, body:JSON.stringify(body),
    });
    return response.json();
  };
  expect((await bind(params)).code).not.toBe(200);
  expect((await env.db.prepare("SELECT count(*) AS n FROM user WHERE email='oauth@example.com'").first()).n).toBe(0);
  expect((await bind({...params, ...await proof()})).code).toBe(200);
});
