import { SELF, env, fetchMock } from 'cloudflare:test';
import { beforeEach, afterEach, expect, it } from 'vitest';
import settingService from '../src/service/setting-service';
import { sign } from 'hono/jwt';
import worker from '../src/index';

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
async function proof(address = 'receiver@external.test') {
  let sentCode;
  fetchMock.get('https://api.resend.com').intercept({path:'/emails', method:'POST'}).reply(200, (options) => {
    const mail = JSON.parse(options.body);
    expect(mail.from).toContain('no-reply@example.com');
    expect(mail.to).toEqual([address]);
    sentCode = mail.text.match(/\b\d{6}\b/)[0];
    return JSON.stringify({id:'mock-email-id'});
  });
  const result = await post('/register/email-code', {externalEmail:address});
  expect(result.code).toBe(200);
  return {externalEmail:address, emailChallenge:result.data.challenge, emailVerificationCode:sentCode};
}

it('serves the public home at root and preserves mailbox and other methods', async () => {
  const requests = [];
  const assets = { fetch: async request => {
    requests.push({path: new URL(request.url).pathname, method: request.method});
    return new Response('asset');
  }};
  await worker.fetch(new Request('https://local.test/'), {assets}, {});
  await worker.fetch(new Request('https://local.test/', {method:'HEAD'}), {assets}, {});
  await worker.fetch(new Request('https://local.test/login'), {assets}, {});
  await worker.fetch(new Request('https://local.test/', {method:'POST'}), {assets}, {});
  expect(requests).toEqual([
    {path:'/about', method:'GET'},
    {path:'/about', method:'HEAD'},
    {path:'/login', method:'GET'},
    {path:'/', method:'POST'},
  ]);
});

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

async function googleLogin(subject = 'google-test-user', overrides = {}) {
  fetchMock.get('https://oauth2.googleapis.com').intercept({path:'/token', method:'POST'}).reply(200, options => {
    expect(new URLSearchParams(options.body).get('code_verifier')).toBe('a'.repeat(64));
    return JSON.stringify({access_token:'mock-google-access-token'});
  });
  fetchMock.get('https://openidconnect.googleapis.com').intercept({path:'/v1/userinfo', method:'GET'}).reply(200, JSON.stringify({sub:subject, email:'person@gmail.com', email_verified:true, name:'Test', ...overrides}));
  return post('/oauth/google/login', {code:'mock-auth-code',redirectUri:'https://local.test/login',codeVerifier:'a'.repeat(64)});
}

it('accepts a verified Google email without an extra code and supports subsequent login', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const oauth = await googleLogin();
  expect(oauth.code).toBe(200);
  expect(oauth.data.token).toBeNull();
  expect(typeof oauth.data.bindToken).toBe('string');
  expect(oauth.data.verifiedGoogleEmail).toBe('person@gmail.com');
  const params = {email:'oauth@example.com', oauthUserId:'google-test-user'};
  const bind = async (body) => {
    const response = await SELF.fetch('https://local.test/api/oauth/bindUser', {
      method:'PUT', headers:{'Content-Type':'application/json','CF-Connecting-IP':'192.0.2.20'}, body:JSON.stringify(body),
    });
    return response.json();
  };
  expect((await bind(params)).code).not.toBe(200);
  expect((await bind({...params, bindToken:'fake'})).code).not.toBe(200);
  const expired = await sign({purpose:'oauth-registration',oauthId:oauth.data.userInfo.oauthId,platform:'google',exp:Math.floor(Date.now()/1000)-1},env.jwt_secret+':oauth-registration:v1','HS256');
  expect((await bind({...params,bindToken:expired})).code).not.toBe(200);
  const legacy = await sign({purpose:'oauth-registration',oauthId:oauth.data.userInfo.oauthId,platform:'google',exp:Math.floor(Date.now()/1000)+300},env.jwt_secret+':oauth-registration:v1','HS256');
  expect((await bind({...params, bindToken:legacy, verifiedGoogleEmail:'forged@gmail.com'})).code).not.toBe(200);
  expect((await env.db.prepare("SELECT count(*) AS n FROM user WHERE email='oauth@example.com'").first()).n).toBe(0);
  const bound = await bind({...params,bindToken:oauth.data.bindToken,externalEmail:'forged@other.test'});
  expect(bound.code).toBe(200);
  expect(typeof bound.data.token).toBe('string');
  expect((await env.db.prepare("SELECT username FROM oauth WHERE oauth_user_id='google-test-user'").first()).username).toBe('person@gmail.com');
  expect((await bind({...params,bindToken:oauth.data.bindToken})).code).not.toBe(200);
  await env.db.prepare('UPDATE setting SET register=1').run();
  await refresh();
  const later = await googleLogin();
  expect(later.code).toBe(200);
  expect(typeof later.data.token).toBe('string');
});

it.each([
  { email_verified: false },
  { email_verified: 'true' },
  { email: '' },
  { email: 'person@example.com' },
])('rejects unverified or non-external Google email: %j', async overrides => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const result = await googleLogin('invalid-google', overrides);
  expect(result.code).not.toBe(200);
  expect(result.data?.bindToken).toBeUndefined();
  expect((await env.db.prepare("SELECT count(*) AS n FROM user WHERE email='invalid@example.com'").first()).n).toBe(0);
});

it('rejects Google code exchange without PKCE and does not confuse provider identities', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await env.db.prepare("INSERT INTO oauth (oauth_user_id,platform,user_id) VALUES ('same-id','github',42)").run();
  await refresh();
  expect((await post('/oauth/google/login',{code:'mock-auth-code',redirectUri:'https://local.test/login'})).code).not.toBe(200);
  const result = await googleLogin('same-id');
  expect(result.code).toBe(200);
  expect(result.data.token).toBeNull();
  expect(result.data.userInfo.platform).toBe('google');
});

it('does not bypass a closed registration setting for Google binding', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const oauth = await googleLogin('google-closed');
  const verified = await proof();
  await env.db.prepare('UPDATE setting SET register=1').run();
  await refresh();
  const response = await SELF.fetch('https://local.test/api/oauth/bindUser',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'closed@example.com',bindToken:oauth.data.bindToken,...verified})});
  expect((await response.json()).code).not.toBe(200);
  expect((await env.db.prepare("SELECT count(*) AS n FROM user WHERE email='closed@example.com'").first()).n).toBe(0);
  expect((await env.db.prepare("SELECT user_id FROM oauth WHERE oauth_user_id='google-closed'").first()).user_id).toBe(0);
});

it('allows only one account to bind the same Google identity concurrently', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const oauth = await googleLogin('google-race');
  const proofA = await proof('race-a@external.test');
  const proofB = await proof('race-b@external.test');
  const bind = async body => (await SELF.fetch('https://local.test/api/oauth/bindUser',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  const responses = await Promise.all([
    bind({email:'race-a@example.com',bindToken:oauth.data.bindToken,...proofA}),
    bind({email:'race-b@example.com',bindToken:oauth.data.bindToken,...proofB}),
  ]);
  expect(responses.filter(r => r.code === 200)).toHaveLength(1);
  const users = await env.db.prepare("SELECT count(*) AS n FROM user WHERE email IN ('race-a@example.com','race-b@example.com')").first();
  expect(users.n).toBe(1);
});

it('rolls back a failed mailbox insert so the Google identity can be retried', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const oauth = await googleLogin('google-interrupted');
  const verified = await proof('first@external.test');
  await env.db.prepare('UPDATE setting SET reg_key=0').run();
  const role = await env.db.prepare('SELECT role_id FROM role LIMIT 1').first();
  await env.db.prepare("INSERT INTO reg_key (code,count,role_id,expire_time) VALUES ('recovery-invite',1,?,'2099-01-01 00:00:00')").bind(role.role_id).run();
  await refresh();
  await env.db.prepare("CREATE TRIGGER simulate_account_failure BEFORE INSERT ON account BEGIN SELECT RAISE(ABORT, 'simulated failure'); END").run();
  const bind = async body => (await SELF.fetch('https://local.test/api/oauth/bindUser',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  expect((await bind({email:'recovery@example.com',bindToken:oauth.data.bindToken,code:'recovery-invite',...verified})).code).not.toBe(200);
  expect((await env.db.prepare("SELECT count(*) AS n FROM user WHERE email='recovery@example.com'").first()).n).toBe(0);
  expect((await env.db.prepare("SELECT user_id FROM oauth WHERE oauth_user_id='google-interrupted'").first()).user_id).toBe(0);
  expect((await env.db.prepare("SELECT count FROM reg_key WHERE code='recovery-invite'").first()).count).toBe(1);
  await env.db.prepare('DROP TRIGGER simulate_account_failure').run();
  const retryProof = await proof('retry@external.test');
  expect((await bind({email:'recovery@example.com',bindToken:oauth.data.bindToken,code:'recovery-invite',...retryProof})).code).toBe(200);
  expect((await env.db.prepare("SELECT count FROM reg_key WHERE code='recovery-invite'").first()).count).toBe(0);
});

it('uses a single remaining invitation only once across concurrent Google registrations', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const a = await googleLogin('invite-race-a');
  const b = await googleLogin('invite-race-b');
  const proofA = await proof('invite-a@external.test');
  const proofB = await proof('invite-b@external.test');
  await env.db.prepare('UPDATE setting SET reg_key=0').run();
  const role = await env.db.prepare('SELECT role_id FROM role LIMIT 1').first();
  await env.db.prepare("INSERT INTO reg_key (code,count,role_id,expire_time) VALUES ('last-invite',1,?,'2099-01-01 00:00:00')").bind(role.role_id).run();
  await refresh();
  const bind = async body => (await SELF.fetch('https://local.test/api/oauth/bindUser',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  const responses = await Promise.all([
    bind({email:'invite-a@example.com',bindToken:a.data.bindToken,code:'last-invite',...proofA}),
    bind({email:'invite-b@example.com',bindToken:b.data.bindToken,code:'last-invite',...proofB}),
  ]);
  expect(responses.filter(r => r.code === 200)).toHaveLength(1);
  expect((await env.db.prepare("SELECT count FROM reg_key WHERE code='last-invite'").first()).count).toBe(0);
  expect((await env.db.prepare("SELECT count(*) AS n FROM user WHERE email IN ('invite-a@example.com','invite-b@example.com')").first()).n).toBe(1);
});

it('falls back to the default role if an optional invitation is used concurrently', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const a = await googleLogin('optional-race-a');
  const b = await googleLogin('optional-race-b');
  const proofA = await proof('optional-a@external.test');
  const proofB = await proof('optional-b@external.test');
  await env.db.prepare('UPDATE setting SET reg_key=2').run();
  const role = await env.db.prepare('SELECT role_id FROM role LIMIT 1').first();
  await env.db.prepare("INSERT INTO reg_key (code,count,role_id,expire_time) VALUES ('optional-invite',1,?,'2099-01-01 00:00:00')").bind(role.role_id).run();
  await refresh();
  const bind = async body => (await SELF.fetch('https://local.test/api/oauth/bindUser',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  const responses = await Promise.all([
    bind({email:'optional-a@example.com',bindToken:a.data.bindToken,code:'optional-invite',...proofA}),
    bind({email:'optional-b@example.com',bindToken:b.data.bindToken,code:'optional-invite',...proofB}),
  ]);
  expect(responses.filter(r => r.code === 200)).toHaveLength(2);
  expect((await env.db.prepare("SELECT count FROM reg_key WHERE code='optional-invite'").first()).count).toBe(0);
  expect((await env.db.prepare("SELECT count(*) AS n FROM user WHERE email IN ('optional-a@example.com','optional-b@example.com')").first()).n).toBe(2);
});

it('enforces invitation and Turnstile for Google registration', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const oauth = await googleLogin('google-protected');
  const verified = await proof();
  await env.db.prepare('UPDATE setting SET reg_key=0, register_verify=0').run();
  await refresh();
  const params = {email:'google-protected@example.com',bindToken:oauth.data.bindToken,...verified};
  const bind = async body => (await SELF.fetch('https://local.test/api/oauth/bindUser', {method:'PUT',headers:{'Content-Type':'application/json','CF-Connecting-IP':'192.0.2.20'},body:JSON.stringify(body)})).json();
  expect((await bind(params)).code).not.toBe(200);
  const role = await env.db.prepare('SELECT role_id FROM role LIMIT 1').first();
  await env.db.prepare("INSERT INTO reg_key (code,count,role_id,expire_time) VALUES ('oauth-invite',1,?,'2099-01-01 00:00:00')").bind(role.role_id).run();
  expect((await bind({...params,code:'oauth-invite'})).code).toBe(400);
  fetchMock.get('https://challenges.cloudflare.com').intercept({path:'/turnstile/v0/siteverify',method:'POST'}).reply(200,JSON.stringify({success:true}));
  expect((await bind({...params,code:'oauth-invite',token:'test-turnstile'})).code).toBe(200);
  expect((await env.db.prepare("SELECT count FROM reg_key WHERE code='oauth-invite'").first()).count).toBe(0);
});
