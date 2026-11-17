import { SELF, env, fetchMock } from 'cloudflare:test';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import settingService from '../src/service/setting-service';
import { sign } from 'hono/jwt';
import { requestDeletion as requestDeletionRaw, restoreDeletion, claimDeletion, stagePurge, processQueuedObject, recordConfirmedObjectOrigin } from '../src/service/account-deletion-state';
import jwtUtils from '../src/utils/jwt-utils';
import userService from '../src/service/user-service';
import accountService from '../src/service/account-service';
import { email as receiveEmail } from '../src/email/email';
import attService from '../src/service/att-service';
import emailService from '../src/service/email-service';
import fileUtils from '../src/utils/file-utils';
import app from '../src/hono/webs';
import { checkPasswordReauth, requestPasswordDeletion, changePasswordWithReauth } from '../src/service/account-reauth-draft';
import { verifyGoogleReauthToken } from '../src/service/google-reauth-draft';
import { commitGoogleDeletion } from '../src/service/google-deletion-draft';
import { acquireObjectLock, releaseObjectLock } from '../src/service/account-deletion-state';
import { processTestKvAttachment } from '../src/service/attachment-cleanup-draft';
import cryptoUtils from '../src/utils/crypto-utils';
import { stageDueDeletionsForTest } from '../src/service/account-deletion-runner-draft';

const requestDeletion = (db, userId, now) => requestDeletionRaw(db, userId, now, 'admin@example.com');

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

it('verifies Google reauthentication signatures and rejects invalid identity claims', async () => {
  const algorithm = {name:'RSASSA-PKCS1-v1_5', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'};
  const pair = await crypto.subtle.generateKey(algorithm, true, ['sign','verify']);
  const other = await crypto.subtle.generateKey(algorithm, true, ['sign','verify']);
  const publicKey = {...await crypto.subtle.exportKey('jwk', pair.publicKey), kid:'test-key', alg:'RS256', use:'sig'};
  const privateKey = {...await crypto.subtle.exportKey('jwk', pair.privateKey), kid:'test-key', alg:'RS256'};
  const forgedKey = {...await crypto.subtle.exportKey('jwk', other.privateKey), kid:'test-key', alg:'RS256'};
  const now = Math.floor(Date.now()/1000);
  const nonce = 'test_nonce_012345678901234567890123456789';
  const claims = {iss:'https://accounts.google.com', sub:'google-owner', aud:'test-client',
    nonce, iat:now, auth_time:now, exp:now+300};
  async function check(payload, key = privateKey) {
    const token = await sign(payload, key, 'RS256');
    fetchMock.get('https://www.googleapis.com').intercept({path:'/oauth2/v3/certs', method:'GET'})
      .reply(200, JSON.stringify({keys:[publicKey]}));
    return verifyGoogleReauthToken(token, 'test-client', nonce, 'google-owner', now);
  }
  expect(await check(claims)).toBe(true);
  expect(await check(claims, forgedKey)).toBe(false);
  expect(await check({...claims, sub:'different-user'})).toBe(false);
  expect(await check({...claims, iss:'https://not-google.example'})).toBe(false);
  expect(await check({...claims, aud:'another-client'})).toBe(false);
  expect(await check({...claims, nonce:'different_nonce_012345678901234567890123'})).toBe(false);
  expect(await check({...claims, auth_time:now-301})).toBe(false);
  expect(await check({...claims, auth_time:undefined})).toBe(false);
  expect(await check({...claims, exp:now-1})).toBe(false);
  expect(await check({...claims, aud:['test-client','other'], azp:'other'})).toBe(false);
});

it('binds Google deletion to a fresh one-use challenge and the original session', async () => {
  const verified = await proof('google-delete-owner@external.test');
  expect((await post('/register', {email:'google-delete@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='google-delete@example.com'").first();
  await env.db.prepare("INSERT INTO oauth (user_id,platform,oauth_user_id) VALUES (?,'google','google-delete-subject')").bind(user.user_id).run();
  await env.db.prepare('INSERT OR IGNORE INTO role_perm (role_id,perm_id) VALUES (1,5)').run();
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const first = await post('/login', {email:'google-delete@example.com', password:'test-password'});
  const second = await post('/login', {email:'google-delete@example.com', password:'test-password'});
  expect(first.code).toBe(200);
  expect(second.code).toBe(200);
  const send = async (path, token, body = {}) => (await SELF.fetch('https://local.test/api' + path, {
    method:'POST', headers:{Authorization:token, 'Content-Type':'application/json', 'CF-Connecting-IP':'192.0.2.20'}, body:JSON.stringify(body),
  })).json();
  const started = await send('/my/delete/google/start', first.data.token);
  expect(started.code).toBe(200);
  const auth = new URL(started.data.url);
  expect(auth.origin).toBe('https://accounts.google.com');
  expect(auth.searchParams.get('redirect_uri')).toBe('https://local.test/login');
  expect(auth.searchParams.get('prompt')).toBe('login');
  expect(auth.searchParams.get('max_age')).toBe('0');
  const state = auth.searchParams.get('state'), nonce = auth.searchParams.get('nonce');
  const payload = {state, code:'test-authorization-code', confirmation:'DELETE'};
  expect((await send('/my/delete/google/complete', second.data.token, payload)).code).not.toBe(200);
  expect((await env.db.prepare('SELECT count(*) AS n FROM google_deletion_challenge WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
  expect((await send('/my/delete/google/complete', first.data.token, {...payload, confirmation:'no'})).code).not.toBe(200);
  const pair = await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'}, true, ['sign','verify']);
  const privateKey = {...await crypto.subtle.exportKey('jwk', pair.privateKey), kid:'google-test', alg:'RS256'};
  const publicKey = {...await crypto.subtle.exportKey('jwk', pair.publicKey), kid:'google-test', alg:'RS256', use:'sig'};
  const now = Math.floor(Date.now()/1000);
  const idToken = await sign({iss:'https://accounts.google.com', sub:'google-delete-subject', aud:'test-client',
    nonce, iat:now, auth_time:now, exp:now+300}, privateKey, 'RS256');
  fetchMock.get('https://oauth2.googleapis.com').intercept({path:'/token',method:'POST'}).reply(200, options => {
    const form = new URLSearchParams(options.body);
    expect(form.get('code')).toBe('test-authorization-code');
    expect(form.get('redirect_uri')).toBe('https://local.test/login');
    expect(form.get('code_verifier')).toMatch(/^[a-f0-9]{64}$/);
    return JSON.stringify({id_token:idToken});
  });
  fetchMock.get('https://www.googleapis.com').intercept({path:'/oauth2/v3/certs',method:'GET'}).reply(200, JSON.stringify({keys:[publicKey]}));
  const done = await send('/my/delete/google/complete', first.data.token, payload);
  expect(done.code).toBe(200);
  const request = await env.db.prepare('SELECT state,purge_after,requested_at FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first();
  expect(request.state).toBe('pending');
  expect(request.purge_after - request.requested_at).toBe(2592000);
  expect((await env.db.prepare('SELECT count(*) AS n FROM google_deletion_challenge WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
  expect((await send('/my/delete/google/complete', first.data.token, payload)).code).not.toBe(200);
});

it('consumes failed Google challenges and rejects expired ones without deleting the user', async () => {
  const verified = await proof('google-failure-owner@external.test');
  expect((await post('/register', {email:'google-failure@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='google-failure@example.com'").first();
  await env.db.prepare("INSERT INTO oauth (user_id,platform,oauth_user_id) VALUES (?,'google','google-failure-subject')").bind(user.user_id).run();
  await env.db.prepare('INSERT OR IGNORE INTO role_perm (role_id,perm_id) VALUES (1,5)').run();
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const login = await post('/login', {email:'google-failure@example.com', password:'test-password'});
  const send = async (path, body = {}) => (await SELF.fetch('https://local.test/api' + path, {
    method:'POST', headers:{Authorization:login.data.token, 'Content-Type':'application/json'}, body:JSON.stringify(body),
  })).json();
  const first = await send('/my/delete/google/start');
  const payload = {state:new URL(first.data.url).searchParams.get('state'), code:'bad-code', confirmation:'DELETE'};
  fetchMock.get('https://oauth2.googleapis.com').intercept({path:'/token',method:'POST'}).reply(400, JSON.stringify({error:'private-provider-detail'}));
  const failed = await send('/my/delete/google/complete', payload);
  expect(failed.code).not.toBe(200);
  expect(failed.message).not.toContain('private-provider-detail');
  expect((await send('/my/delete/google/complete', payload)).code).not.toBe(200);
  expect((await env.db.prepare('SELECT count(*) AS n FROM google_deletion_challenge WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
  const second = await send('/my/delete/google/start');
  const expired = {state:new URL(second.data.url).searchParams.get('state'), code:'unused-code', confirmation:'DELETE'};
  await env.db.prepare('UPDATE google_deletion_challenge SET expires_at=0 WHERE user_id=?').bind(user.user_id).run();
  expect((await send('/my/delete/google/complete', expired)).code).not.toBe(200);
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
});

it('does not delete after the session generation or linked Google identity changes', async () => {
  const verified = await proof('google-race-owner@external.test');
  expect((await post('/register', {email:'google-race@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='google-race@example.com'").first();
  await env.db.prepare("INSERT INTO oauth (user_id,platform,oauth_user_id) VALUES (?,'google','new-google-subject')").bind(user.user_id).run();
  await env.db.prepare('INSERT INTO account_session_generation (user_id,generation) VALUES (?,2)').bind(user.user_id).run();
  const now = Math.floor(Date.now()/1000);
  expect(await commitGoogleDeletion(env.db, user.user_id, 'admin@example.com', 'new-google-subject', 1, now)).toBe(false);
  expect(await commitGoogleDeletion(env.db, user.user_id, 'admin@example.com', 'old-google-subject', 2, now)).toBe(false);
  expect(await commitGoogleDeletion(env.db, user.user_id, 'Google-Race@Example.com', 'new-google-subject', 2, now)).toBe(false);
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
  expect(await commitGoogleDeletion(env.db, user.user_id, 'admin@example.com', 'new-google-subject', 2, now)).toBe(true);
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

it('does not change the password using only an existing session', async () => {
  const verified = await proof('password-owner@external.test');
  expect((await post('/register', {email:'password-owner@example.com', password:'test-password', ...verified})).code).toBe(200);
  const login = await post('/login', {email:'password-owner@example.com', password:'test-password'});
  expect(login.code).toBe(200);
  const response = await SELF.fetch('https://local.test/api/my/resetPassword', {
    method:'PUT', headers:{Authorization:login.data.token, 'Content-Type':'application/json', 'CF-Connecting-IP':'192.0.2.20'},
    body:JSON.stringify({password:'replacement-password'}),
  });
  expect((await response.json()).code).not.toBe(200);
  expect((await post('/login', {email:'password-owner@example.com', password:'test-password'})).code).toBe(200);
  expect((await post('/login', {email:'password-owner@example.com', password:'replacement-password'})).code).not.toBe(200);
});

it('requires the current password and invalidates old sessions after password change', async () => {
  const verified = await proof('password-change-owner@external.test');
  expect((await post('/register', {email:'password-change@example.com', password:'test-password', ...verified})).code).toBe(200);
  const login = await post('/login', {email:'password-change@example.com', password:'test-password'});
  expect(login.code).toBe(200);
  const change = async oldPassword => (await SELF.fetch('https://local.test/api/my/resetPassword', {
    method:'PUT', headers:{Authorization:login.data.token, 'Content-Type':'application/json', 'CF-Connecting-IP':'192.0.2.20'},
    body:JSON.stringify({oldPassword, password:'replacement-password'}),
  })).json();
  expect((await change('wrong-password')).code).not.toBe(200);
  expect((await change('test-password')).code).toBe(200);
  const oldSession = await SELF.fetch('https://local.test/api/my/loginUserInfo', {headers:{Authorization:login.data.token}});
  expect((await oldSession.json()).code).not.toBe(200);
  expect((await post('/login', {email:'password-change@example.com', password:'test-password'})).code).not.toBe(200);
  expect((await post('/login', {email:'password-change@example.com', password:'replacement-password'})).code).toBe(200);
});

it.each(['administrator', 'owner'])('rejects an old-password session overlapping a password change by %s', async mode => {
  const email=`login-reset-${mode}@example.com`;
  const verified = await proof(`login-reset-${mode}@external.test`);
  expect((await post('/register', {email, password:'old-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare('SELECT user_id FROM user WHERE email=?').bind(email).first();
  const original = cryptoUtils.verifyPassword.bind(cryptoUtils);
  const spy = vi.spyOn(cryptoUtils, 'verifyPassword').mockImplementationOnce(async (...args) => {
    const matches = await original(...args);
    if (mode === 'administrator') await userService.resetPassword({env}, {password:'new-password'}, user.user_id);
    else expect(await changePasswordWithReauth(env.db,user.user_id,'old-password','new-password',Math.floor(Date.now()/1000))).toBe(true);
    return matches;
  });
  try {
    const raced = await post('/login', {email, password:'old-password'});
    if (raced.code === 200) {
      const response = await SELF.fetch('https://local.test/api/my/loginUserInfo', {headers:{Authorization:raced.data.token}});
      expect((await response.json()).code).not.toBe(200);
    }
    expect((await post('/login', {email, password:'old-password'})).code).not.toBe(200);
    expect((await post('/login', {email, password:'new-password'})).code).toBe(200);
  } finally {
    spy.mockRestore();
  }
});

it('does not overwrite a password changed concurrently after verification', async () => {
  const verified = await proof('password-race-owner@external.test');
  expect((await post('/register', {email:'password-race@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='password-race@example.com'").first();
  const db = {prepare:env.db.prepare.bind(env.db), async batch(statements) {
    await env.db.prepare("UPDATE user SET password='concurrent-change' WHERE user_id=?").bind(user.user_id).run();
    return env.db.batch(statements);
  }};
  expect(await changePasswordWithReauth(db, user.user_id, 'test-password', 'replacement-password', Math.floor(Date.now()/1000))).toBe(false);
  expect((await env.db.prepare('SELECT password FROM user WHERE user_id=?').bind(user.user_id).first()).password).toBe('concurrent-change');
  expect((await env.db.prepare('SELECT count(*) AS n FROM account_session_generation WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
});

it('invalidates existing sessions when an administrator resets a password', async () => {
  const verified = await proof('admin-reset-owner@external.test');
  expect((await post('/register', {email:'admin-reset@example.com', password:'test-password', ...verified})).code).toBe(200);
  const login = await post('/login', {email:'admin-reset@example.com', password:'test-password'});
  expect(login.code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='admin-reset@example.com'").first();
  await userService.setPwd({env}, {userId:user.user_id, password:'replacement-password'});
  expect((await env.db.prepare('SELECT generation FROM account_session_generation WHERE user_id=?').bind(user.user_id).first()).generation).toBe(1);
  const oldSession = await SELF.fetch('https://local.test/api/my/loginUserInfo', {headers:{Authorization:login.data.token}});
  expect((await oldSession.json()).code).not.toBe(200);
  expect((await post('/login', {email:'admin-reset@example.com', password:'test-password'})).code).not.toBe(200);
  expect((await post('/login', {email:'admin-reset@example.com', password:'replacement-password'})).code).toBe(200);
});

it('limits concurrent password reauthentication attempts per account', async () => {
  const verified = await proof('reauth-owner@external.test');
  expect((await post('/register', {email:'reauth@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='reauth@example.com'").first();
  const now = Math.floor(Date.now() / 1000);
  const results = await Promise.all(Array.from({length:10}, () => checkPasswordReauth(env.db, user.user_id, 'incorrect', now)));
  expect(results.every(result => !result)).toBe(true);
  expect((await env.db.prepare('SELECT attempts FROM account_reauth_rate WHERE user_id=?').bind(user.user_id).first()).attempts).toBe(5);
  expect(await checkPasswordReauth(env.db, user.user_id, 'test-password', now + 899)).toBe(false);
  expect(await checkPasswordReauth(env.db, user.user_id, 'test-password', now + 900)).toBe(true);
  await env.db.prepare('UPDATE user SET is_del=1 WHERE user_id=?').bind(user.user_id).run();
  expect(await checkPasswordReauth(env.db, user.user_id, 'test-password', now + 901)).toBe(false);
});

it('requests password deletion only with the correct password and protects the administrator', async () => {
  const verified = await proof('password-delete-owner@external.test');
  expect((await post('/register', {email:'password-delete@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='password-delete@example.com'").first();
  const now = Math.floor(Date.now() / 1000);
  expect(await requestPasswordDeletion(env.db, user.user_id, 'wrong', now, 'admin@example.com')).toBe(false);
  expect(await requestPasswordDeletion(env.db, user.user_id, 'test-password', now, 'Password-Delete@Example.com')).toBe(false);
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(0);
  expect(await requestPasswordDeletion(env.db, user.user_id, 'test-password', now, 'admin@example.com')).toBe(true);
  expect(await env.db.prepare('SELECT requested_at,purge_after,state FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first())
    .toMatchObject({requested_at:now, purge_after:now + 2592000, state:'pending'});
  expect((await env.db.prepare('SELECT generation FROM account_session_generation WHERE user_id=?').bind(user.user_id).first()).generation).toBe(1);
});

it('accepts a confirmed password deletion request only from the authenticated owner', async () => {
  const verified = await proof('api-delete-owner@external.test');
  expect((await post('/register', {email:'api-delete@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='api-delete@example.com'").first();
  await env.db.prepare('INSERT OR IGNORE INTO role_perm (role_id, perm_id) VALUES (1, 5)').run();
  const login = await post('/login', {email:'api-delete@example.com', password:'test-password'});
  expect(login.code).toBe(200);
  const send = async (token, payload) => (await SELF.fetch('https://local.test/api/my/delete/request', {
    method:'POST', headers:{Authorization:token || '', 'Content-Type':'application/json', 'CF-Connecting-IP':'192.0.2.20'},
    body:JSON.stringify(payload),
  })).json();
  const disabledResponse = await app.fetch(new Request('https://local.test/my/delete/request', {
    method:'POST', headers:{Authorization:login.data.token, 'Content-Type':'application/json'},
    body:JSON.stringify({confirmation:'DELETE', password:'test-password'}),
  }), {...env, account_deletion_test_only:'disabled'});
  expect((await disabledResponse.json()).code).not.toBe(200);
  expect((await send('', {confirmation:'DELETE', password:'test-password'})).code).not.toBe(200);
  expect((await send(login.data.token, {password:'test-password'})).code).not.toBe(200);
  expect((await send(login.data.token, {confirmation:'DELETE', password:'incorrect'})).code).not.toBe(200);
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(0);
  const result = await send(login.data.token, {confirmation:'DELETE', password:'test-password'});
  expect(result.code).toBe(200);
  const request = await env.db.prepare('SELECT state,purge_after,requested_at FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first();
  expect(request.state).toBe('pending');
  expect(request.purge_after - request.requested_at).toBe(2592000);
  expect(result.data.recoverUntil).toBe(request.purge_after);
  expect((await send(login.data.token, {confirmation:'DELETE', password:'test-password'})).code).not.toBe(200);
});

it('rejects a deletion if the password changed after verification', async () => {
  const verified = await proof('racing-password-owner@external.test');
  expect((await post('/register', {email:'racing-password@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='racing-password@example.com'").first();
  const db = {prepare:env.db.prepare.bind(env.db), async batch(statements) {
    await env.db.prepare("UPDATE user SET password='changed-by-admin' WHERE user_id=?").bind(user.user_id).run();
    return env.db.batch(statements);
  }};
  expect(await requestPasswordDeletion(db, user.user_id, 'test-password', Math.floor(Date.now()/1000), 'admin@example.com')).toBe(false);
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
});

it('preserves pending-account mail against scheduled and privileged deletion paths', async () => {
  for (const name of ['pending-retention','active-retention']) {
    const verified=await proof(`${name}@external.test`);
    expect((await post('/register',{email:`${name}@example.com`,password:'test-password',...verified})).code).toBe(200);
  }
  const pending=await env.db.prepare("SELECT u.user_id,a.account_id FROM user u JOIN account a ON a.user_id=u.user_id WHERE u.email='pending-retention@example.com'").first();
  const active=await env.db.prepare("SELECT u.user_id,a.account_id FROM user u JOIN account a ON a.user_id=u.user_id WHERE u.email='active-retention@example.com'").first();
  const p=await env.db.prepare("INSERT INTO email(user_id,account_id,subject,create_time) VALUES (?,?,'pending-protected','2000-01-01 00:00:00') RETURNING email_id").bind(pending.user_id,pending.account_id).first();
  const a=await env.db.prepare("INSERT INTO email(user_id,account_id,subject,create_time) VALUES (?,?,'active-removable','2000-01-01 00:00:00') RETURNING email_id").bind(active.user_id,active.account_id).first();
  await env.db.prepare("INSERT INTO attachments(user_id,account_id,email_id,key) VALUES (?,?,?,'attachments/protected')").bind(pending.user_id,pending.account_id,p.email_id).run();
  expect(await requestDeletion(env.db,pending.user_id,Math.floor(Date.now()/1000))).toBe(true);
  await env.db.prepare('UPDATE setting SET auto_clean_days=1').run();
  await refresh();
  await emailService.autoClean({env});
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE email_id=?').bind(p.email_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE email_id=?').bind(a.email_id).first()).n).toBe(0);
  await expect(emailService.physicsDelete({env},{emailIds:String(p.email_id)})).rejects.toThrow('等待恢复或清理');
  await expect(emailService.batchDelete({env},{subject:'pending-protected',type:'include'})).rejects.toThrow('等待恢复或清理');
  await expect(accountService.physicsDelete({env},{accountId:pending.account_id})).rejects.toThrow('等待恢复或清理');
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE email_id=?').bind(p.email_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE email_id=?').bind(p.email_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account WHERE account_id=?').bind(pending.account_id).first()).n).toBe(1);
});

it('removes more than one D1 parameter batch of matching mail', async () => {
  await env.db.batch(Array.from({length: 110}, () => env.db.prepare("INSERT INTO email(user_id,account_id,subject) VALUES (1,1,'bulk-limit-test')")));
  await emailService.batchDelete({env},{subject:'bulk-limit-test',type:'include'});
  expect((await env.db.prepare("SELECT count(*) AS n FROM email WHERE subject='bulk-limit-test'").first()).n).toBe(0);
});

it('rejects a pre-deletion session after deletion and after recovery', async () => {
  const verified = await proof('session-owner@external.test');
  expect((await post('/register', {email:'session@example.com', password:'test-password', ...verified})).code).toBe(200);
  const oldLogin = await post('/login', {email:'session@example.com', password:'test-password'});
  const payload = await jwtUtils.verifyToken({env}, oldLogin.data.token);
  const legacyToken = await jwtUtils.generateToken({env}, {userId: payload.userId, token: payload.token});
  const requestWith = async token => (await SELF.fetch('https://local.test/api/my/loginUserInfo', {
    headers: { Authorization: token, 'CF-Connecting-IP': '192.0.2.20' },
  })).json();
  expect((await requestWith(oldLogin.data.token)).code).toBe(200);
  expect((await requestWith(legacyToken)).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='session@example.com'").first();
  const now = Math.floor(Date.now() / 1000);
  expect(await requestDeletion(env.db, user.user_id, now)).toBe(true);
  expect((await requestWith(oldLogin.data.token)).code).not.toBe(200);
  expect((await requestWith(legacyToken)).code).not.toBe(200);
  expect(await restoreDeletion(env.db, user.user_id, now + 1)).toBe(true);
  expect((await requestWith(oldLogin.data.token)).code).not.toBe(200);
  expect((await requestWith(legacyToken)).code).not.toBe(200);
  const newLogin = await post('/login', {email:'session@example.com', password:'test-password'});
  expect(newLogin.code).toBe(200);
  expect((await requestWith(newLogin.data.token)).code).toBe(200);
});

it('allows administrator recovery during the grace period but blocks it after expiry', async () => {
  const verified = await proof('restore-owner@external.test');
  expect((await post('/register', {email:'restore@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='restore@example.com'").first();
  const now = Math.floor(Date.now() / 1000);
  expect(await requestDeletion(env.db, user.user_id, now)).toBe(true);
  await userService.restore({env}, {userId:user.user_id});
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(0);
  expect(await requestDeletion(env.db, user.user_id, now - 31 * 86400)).toBe(true);
  await expect(userService.restore({env}, {userId:user.user_id})).rejects.toThrow('恢复期已结束');
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(1);
});

it('refuses a deletion request for the configured administrator', async () => {
  const verified = await proof('administrator-owner@external.test');
  expect((await post('/register', {email:'administrator@example.com', password:'test-password', ...verified})).code).toBe(200);
  const admin = await env.db.prepare("SELECT user_id FROM user WHERE email='administrator@example.com'").first();
  const now = Math.floor(Date.now() / 1000);
  await expect(requestDeletionRaw(env.db, admin.user_id, now)).rejects.toThrow('Administrator identity is required');
  expect(await requestDeletionRaw(env.db, admin.user_id, now, 'Administrator@Example.com')).toBe(false);
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(admin.user_id).first()).is_del).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account_deletion_request WHERE user_id=?').bind(admin.user_id).first()).n).toBe(0);
});

it('does not stage an accidentally reactivated account for purge in D1', async () => {
  const verified = await proof('purge-owner@external.test');
  expect((await post('/register', {email:'purge@example.com', password:'test-password', ...verified})).code).toBe(200);
  const otherProof = await proof('purge-other@external.test');
  expect((await post('/register', {email:'other@example.com', password:'test-password', ...otherProof})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='purge@example.com'").first();
  const other = await env.db.prepare("SELECT user_id FROM user WHERE email='other@example.com'").first();
  await env.db.prepare('UPDATE role SET user_id=? WHERE role_id=1').bind(user.user_id).run();
  await env.db.prepare("INSERT INTO reg_key (code, count, role_id, user_id) VALUES ('PRESERVE-SHARED', 2, 1, ?)").bind(user.user_id).run();
  await env.db.prepare(`CREATE TABLE IF NOT EXISTS account_deletion_object_queue (
    storage_type TEXT NOT NULL, object_key TEXT NOT NULL, user_id INTEGER NOT NULL,
    PRIMARY KEY(user_id, storage_type, object_key))`).run();
  const now = Math.floor(Date.now() / 1000);
  expect(await requestDeletion(env.db, user.user_id, now - 31 * 86400)).toBe(true);
  expect(await claimDeletion(env.db, user.user_id, now)).toBe(true);
  await env.db.prepare('UPDATE user SET is_del=0 WHERE user_id=?').bind(user.user_id).run();
  await stagePurge(env.db, user.user_id);
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT user_id FROM role WHERE role_id=1').first()).user_id).toBe(user.user_id);
  await env.db.prepare('UPDATE user SET is_del=1 WHERE user_id=?').bind(user.user_id).run();
  await stagePurge(env.db, user.user_id);
  await stagePurge(env.db, user.user_id);
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(other.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account WHERE user_id=?').bind(other.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT user_id FROM role WHERE role_id=1').first()).user_id).toBeNull();
  expect(await env.db.prepare("SELECT user_id, count, role_id FROM reg_key WHERE code='PRESERVE-SHARED'").first()).toMatchObject({user_id:0, count:2, role_id:1});
});

it('keeps a shared attachment through another account’s full deletion lifecycle', async () => {
  for (const name of ['lifecycle-owner','lifecycle-other']) {
    const verified=await proof(`${name}@external.test`);
    expect((await post('/register',{email:`${name}@example.com`,password:'test-password',...verified})).code).toBe(200);
  }
  const account = async name => env.db.prepare('SELECT u.user_id,a.account_id FROM user u JOIN account a ON a.user_id=u.user_id WHERE u.email=?').bind(`${name}@example.com`).first();
  const owner=await account('lifecycle-owner'), other=await account('lifecycle-other');
  const addMail = async person => env.db.prepare('INSERT INTO email(user_id,account_id,subject) VALUES(?,?,?) RETURNING email_id').bind(person.user_id,person.account_id,'lifecycle test').first();
  const ownerMail=await addMail(owner), otherMail=await addMail(other);
  const shared='attachments/lifecycle-shared', own='attachments/lifecycle-own';
  const record=(person,mail,key,text)=>({key,userId:person.user_id,accountId:person.account_id,emailId:mail.email_id,filename:'test.txt',mimeType:'text/plain',content:new TextEncoder().encode(text)});
  await attService.addAtt({env},[record(owner,ownerMail,shared,'shared'),record(owner,ownerMail,own,'private')]);
  await attService.addAtt({env},[record(other,otherMail,shared,'shared')]);
  const requested=1000000, due=requested+30*86400;
  expect(await requestDeletion(env.db,owner.user_id,requested)).toBe(true);
  expect(await claimDeletion(env.db,owner.user_id,due-1)).toBe(false);
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE user_id=?').bind(owner.user_id).first()).n).toBe(1);
  expect(await claimDeletion(env.db,owner.user_id,due)).toBe(true);
  await stagePurge(env.db,owner.user_id);
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(owner.user_id).first()).n).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE user_id=?').bind(other.user_id).first()).n).toBe(1);
  expect(await processTestKvAttachment({env},{userId:owner.user_id,storageType:'KV',key:shared},'lifecycle-shared',due)).toBe('shared');
  expect(await processTestKvAttachment({env},{userId:owner.user_id,storageType:'KV',key:own},'lifecycle-own',due)).toBe('deleted');
  expect(await env.kv.get(shared)).toBe('shared');
  expect(await env.kv.get(own)).toBeNull();
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key=? AND user_id=?').bind(shared,other.user_id).first()).n).toBe(1);
});

it('stages only due deletions in isolated batches and retries purging accounts', async () => {
  for (const name of ['due-batch','due-second','later-batch']) {
    const verified=await proof(`${name}@external.test`);
    expect((await post('/register',{email:`${name}@example.com`,password:'test-password',...verified})).code).toBe(200);
  }
  const getUser = async name => env.db.prepare('SELECT user_id FROM user WHERE email=?').bind(`${name}@example.com`).first();
  const due=await getUser('due-batch'), second=await getUser('due-second'), later=await getUser('later-batch');
  const now=4000000;
  expect(await requestDeletion(env.db,due.user_id,now-30*86400)).toBe(true);
  expect(await requestDeletion(env.db,second.user_id,now-30*86400)).toBe(true);
  expect(await requestDeletion(env.db,later.user_id,now-30*86400+1)).toBe(true);
  await expect(stageDueDeletionsForTest({...env,account_deletion_test_only:'disabled'},now)).rejects.toThrow('restricted');
  const lock=`internal/account/${due.user_id}`;
  expect(await acquireObjectLock(env.db,'KV',lock,'busy-owner',now)).toBe(true);
  expect(await stageDueDeletionsForTest(env,now,1)).toEqual({staged:0,skipped:0,failed:1,nextCursor:due.user_id});
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(due.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(later.user_id).first()).n).toBe(1);
  // A completed or stuck earlier request cannot starve later pages.
  expect(await stageDueDeletionsForTest(env,now,1,due.user_id)).toEqual({staged:1,skipped:0,failed:0,nextCursor:second.user_id});
  expect(await stageDueDeletionsForTest(env,now,1,second.user_id)).toEqual({staged:0,skipped:0,failed:0,nextCursor:null});
  expect(await releaseObjectLock(env.db,'KV',lock,'busy-owner')).toBe(true);
  // Restarting a pass safely retries the request which encountered contention.
  expect(await stageDueDeletionsForTest(env,now,1)).toEqual({staged:1,skipped:0,failed:0,nextCursor:due.user_id});
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(due.user_id).first()).n).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(later.user_id).first()).n).toBe(1);
});

it('does not stage a reactivated account when retrying a purging request', async () => {
  const verified=await proof('batch-reactivated@external.test');
  expect((await post('/register',{email:'batch-reactivated@example.com',password:'test-password',...verified})).code).toBe(200);
  const user=await env.db.prepare("SELECT user_id FROM user WHERE email='batch-reactivated@example.com'").first();
  const now=4000000;
  expect(await requestDeletion(env.db,user.user_id,now-30*86400)).toBe(true);
  expect(await claimDeletion(env.db,user.user_id,now)).toBe(true);
  await env.db.prepare('UPDATE user SET is_del=0 WHERE user_id=?').bind(user.user_id).run();
  expect(await stageDueDeletionsForTest(env,now)).toEqual({staged:0,skipped:1,failed:0,nextCursor:null});
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT state FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first()).state).toBe('purging');
  await expect(stageDueDeletionsForTest(env,now,0)).rejects.toThrow('Invalid deletion batch');
  await expect(stageDueDeletionsForTest(env,now,1,-1)).rejects.toThrow('Invalid deletion batch');
});

it('preserves shared attachments and retries failed cleanup in Workers bindings', async () => {
  await env.db.prepare(`CREATE TABLE IF NOT EXISTS account_deletion_object_queue (
    storage_type TEXT NOT NULL, object_key TEXT NOT NULL, user_id INTEGER NOT NULL,
    PRIMARY KEY(user_id, storage_type, object_key))`).run();
  const shared = 'attachments/test-shared-object';
  const own = 'attachments/test-private-object';
  await env.db.prepare('INSERT INTO attachments (user_id, email_id, account_id, key) VALUES (2, 2, 2, ?)').bind(shared).run();
  await env.db.prepare("INSERT INTO account_deletion_object_queue VALUES ('KV', ?, 1), ('KV', ?, 1)").bind(shared, own).run();
  await env.kv.put(shared, 'shared data');
  await env.kv.put(own, 'private data');
  const target = {storageType:'KV',storeId:'isolated-test-kv'};
  expect(await acquireObjectLock(env.db,'KV',own,'test-writer',99)).toBe(true);
  await recordConfirmedObjectOrigin(env.db, own, 'KV', target.storeId, 'test-writer');
  expect(await releaseObjectLock(env.db,'KV',own,'test-writer')).toBe(true);
  const remove = async (_type, key) => env.kv.delete(key);
  expect(await processQueuedObject(env.db, {userId:1, storageType:'KV', key:shared}, 'shared-cleaner', 100, remove, target)).toBe('shared');
  expect(await env.kv.get(shared)).toBe('shared data');
  await expect(processQueuedObject(env.db, {userId:1, storageType:'KV', key:own}, 'failing-cleaner', 101,
    async () => {throw new Error('storage unavailable');}, target)).rejects.toThrow('storage unavailable');
  expect((await env.db.prepare('SELECT count(*) AS n FROM account_deletion_object_queue WHERE user_id=1 AND object_key=?').bind(own).first()).n).toBe(1);
  expect(await env.kv.get(own)).toBe('private data');
  expect(await processQueuedObject(env.db, {userId:1, storageType:'KV', key:own}, 'retry-cleaner', 102, remove, target)).toBe('deleted');
  expect(await env.kv.get(own)).toBeNull();
});

it('queues removed attachments without deleting objects shared with another mailbox', async () => {
  const shared = 'attachments/legacy-shared';
  const own = 'attachments/legacy-private';
  await env.kv.put(shared, 'shared content');
  await env.kv.put(own, 'private content');
  await env.db.batch([
    env.db.prepare('INSERT INTO attachments (user_id,email_id,account_id,key) VALUES (1,10,1,?)').bind(shared),
    env.db.prepare('INSERT INTO attachments (user_id,email_id,account_id,key) VALUES (1,10,1,?)').bind(own),
    env.db.prepare('INSERT INTO attachments (user_id,email_id,account_id,key) VALUES (2,20,2,?)').bind(shared),
  ]);
  await attService.removeByEmailIds({env}, [10, 10]);
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE email_id=10').first()).n).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE email_id=20').first()).n).toBe(1);
  expect(await env.kv.get(shared)).toBe('shared content');
  expect(await env.kv.get(own)).toBe('private content');
  expect((await env.db.prepare("SELECT count(*) AS n FROM account_deletion_object_queue WHERE user_id=0 AND storage_type='UNRESOLVED' AND object_key IN (?,?)").bind(shared,own).first()).n).toBe(2);
  await expect(processQueuedObject(env.db, {userId:0,storageType:'UNRESOLVED',key:own}, 'cleaner', 123, async () => {})).rejects.toThrow('Invalid object reservation');
  await attService.removeByEmailIds({env}, [10]);
  expect((await env.db.prepare("SELECT count(*) AS n FROM account_deletion_object_queue WHERE user_id=0 AND storage_type='UNRESOLVED'").first()).n).toBe(2);
});

it('stops serving a retained attachment after its last reference is removed', async () => {
  const key='attachments/known-deleted-object.txt';
  await env.kv.put(key,'private test attachment');
  await env.db.prepare('INSERT INTO attachments (user_id,email_id,account_id,key) VALUES (1,10,1,?),(2,20,2,?)').bind(key,key).run();
  const get=path=>SELF.fetch('https://local.test/'+path);
  expect((await get(key)).status).toBe(200);
  expect((await get('oss/'+key)).status).toBe(200);
  expect((await get('api/oss/'+key)).status).toBe(200);
  await attService.removeByEmailIds({env},[10]);
  expect((await get(key)).status).toBe(200);
  await attService.removeByEmailIds({env},[20]);
  expect(await env.kv.get(key)).toBe('private test attachment');
  expect((await get(key)).status).toBe(404);
  expect((await get('oss/'+key)).status).toBe(404);
  expect((await get('api/oss/'+key)).status).toBe(404);
});

it('rejects new mail for an account awaiting deletion', async () => {
  const verified = await proof('mail-owner@external.test');
  expect((await post('/register', {email:'pending@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='pending@example.com'").first();
  await env.db.prepare('UPDATE setting SET receive=0').run();
  await refresh();
  expect(await requestDeletion(env.db, user.user_id, Math.floor(Date.now() / 1000))).toBe(true);
  let rejected = null;
  const bytes = new TextEncoder().encode('From: sender@external.test\r\nTo: pending@example.com\r\nSubject: Test\r\n\r\nHello');
  const message = {from:'sender@external.test', to:'pending@example.com', raw:new ReadableStream({start(controller) {controller.enqueue(bytes); controller.close();}}), setReject(reason) {rejected = reason;}};
  await receiveEmail(message, env, {});
  expect(rejected).toBe('Recipient account is unavailable');
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
});

it('prevents the legacy administrator delete from bypassing the recovery period', async () => {
  const verified = await proof('protected-owner@external.test');
  expect((await post('/register', {email:'protected@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='protected@example.com'").first();
  expect(await requestDeletion(env.db, user.user_id, Math.floor(Date.now() / 1000))).toBe(true);
  await expect(userService.physicsDelete({env}, {userIds:String(user.user_id)})).rejects.toThrow('账号正在等待恢复或清理');
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT state FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first()).state).toBe('pending');
});

it('blocks the legacy self-delete path before the recovery flow is ready', async () => {
  const verified = await proof('self-delete-owner@external.test');
  expect((await post('/register', {email:'self-delete@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='self-delete@example.com'").first();
  await expect(userService.delete({env}, user.user_id)).rejects.toThrow('账号删除功能暂不可用');
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
});

it('does not save incoming mail while the recipient account is being changed', async () => {
  const verified = await proof('locked-owner@external.test');
  expect((await post('/register', {email:'locked@example.com', password:'test-password', ...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='locked@example.com'").first();
  await env.db.prepare('UPDATE setting SET receive=0').run();
  await refresh();
  const key = `internal/account/${user.user_id}`;
  expect(await acquireObjectLock(env.db, 'KV', key, 'account-change', 123)).toBe(true);
  const makeMessage = () => {
    const bytes = new TextEncoder().encode('From: sender@external.test\r\nTo: locked@example.com\r\nSubject: Test\r\n\r\nHello');
    return {from:'sender@external.test', to:'locked@example.com', raw:new ReadableStream({start(controller) {controller.enqueue(bytes); controller.close();}}), setReject() {}};
  };
  await expect(receiveEmail(makeMessage(), env, {})).rejects.toThrow('Attachment temporarily busy');
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
  expect(await releaseObjectLock(env.db, 'KV', key, 'account-change')).toBe(true);
  await receiveEmail(makeMessage(), env, {});
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
});

it('accepts one incoming message after a short account lock clears', async () => {
  const verified=await proof('brief-lock@external.test');
  expect((await post('/register',{email:'brief-lock@example.com',password:'test-password',...verified})).code).toBe(200);
  const user=await env.db.prepare("SELECT user_id FROM user WHERE email='brief-lock@example.com'").first();
  await env.db.prepare('UPDATE setting SET receive=0').run();
  await refresh();
  const key=`internal/account/${user.user_id}`;
  expect(await acquireObjectLock(env.db,'KV',key,'brief-holder',100)).toBe(true);
  let rejected=null;
  const bytes=new TextEncoder().encode('From: sender@external.test\r\nTo: brief-lock@example.com\r\nSubject: brief lock\r\n\r\nHello');
  const delivery=receiveEmail({from:'sender@external.test',to:'brief-lock@example.com',raw:new ReadableStream({start(c){c.enqueue(bytes);c.close()}}),setReject(reason){rejected=reason}},env,{});
  await new Promise(resolve=>setTimeout(resolve,120));
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
  expect(await releaseObjectLock(env.db,'KV',key,'brief-holder')).toBe(true);
  await delivery;
  expect(rejected).toBeNull();
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
});

it('does not deliver on-site mail to a recipient awaiting deletion', async () => {
  const senderProof = await proof('onsite-sender@external.test');
  expect((await post('/register', {email:'sender@example.com', password:'test-password', ...senderProof})).code).toBe(200);
  const recipientProof = await proof('onsite-recipient@external.test');
  expect((await post('/register', {email:'recipient@example.com', password:'test-password', ...recipientProof})).code).toBe(200);
  const sender = await env.db.prepare("SELECT u.user_id,a.account_id FROM user u JOIN account a ON a.user_id=u.user_id WHERE u.email='sender@example.com'").first();
  const recipient = await env.db.prepare("SELECT user_id FROM user WHERE email='recipient@example.com'").first();
  const sent = await env.db.prepare("INSERT INTO email (user_id,account_id,send_email,subject,type,status,is_del) VALUES (?,?,'sender@example.com','on-site test',1,1,0) RETURNING email_id").bind(sender.user_id, sender.account_id).first();
  expect(await requestDeletion(env.db, recipient.user_id, Math.floor(Date.now() / 1000))).toBe(true);
  const delivered = await emailService.HandleOnSiteEmail({env}, ['recipient@example.com'], {emailId:sent.email_id, sendEmail:'sender@example.com'}, []);
  expect(delivered).toHaveLength(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE user_id=?').bind(recipient.user_id).first()).n).toBe(0);
  expect((await env.db.prepare('SELECT status FROM email WHERE email_id=?').bind(sent.email_id).first()).status).toBe(3);
});

it('still delivers on-site mail to an active recipient', async () => {
  const senderProof = await proof('active-sender@external.test');
  expect((await post('/register', {email:'active-sender@example.com', password:'test-password', ...senderProof})).code).toBe(200);
  const recipientProof = await proof('active-recipient@external.test');
  expect((await post('/register', {email:'active-recipient@example.com', password:'test-password', ...recipientProof})).code).toBe(200);
  const sender = await env.db.prepare("SELECT u.user_id,a.account_id FROM user u JOIN account a ON a.user_id=u.user_id WHERE u.email='active-sender@example.com'").first();
  const recipient = await env.db.prepare("SELECT user_id FROM user WHERE email='active-recipient@example.com'").first();
  const sent = await env.db.prepare("INSERT INTO email (user_id,account_id,send_email,subject,type,status,is_del) VALUES (?,?,'active-sender@example.com','active on-site',1,1,0) RETURNING email_id").bind(sender.user_id, sender.account_id).first();
  const delivered = await emailService.HandleOnSiteEmail({env}, ['active-recipient@example.com'], {emailId:sent.email_id,userId:sender.user_id,accountId:sender.account_id,sendEmail:'active-sender@example.com',subject:'active on-site',recipient:'[]',isDel:0}, []);
  expect(delivered).toHaveLength(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM email WHERE user_id=?').bind(recipient.user_id).first()).n).toBe(1);
});

it('does not write an outgoing attachment while its object is reserved', async () => {
  const key = 'attachments/' + await fileUtils.getBuffHash(new TextEncoder().encode('abc')) + '.txt';
  expect(await acquireObjectLock(env.db, 'KV', key, 'test-cleaner', 123)).toBe(true);
  const attachment = () => ({filename:'file.txt',type:'text/plain',content:'YWJj'});
  await expect(attService.saveSendAtt({env}, [attachment()], 1, 1, 1)).rejects.toThrow('Attachment temporarily busy');
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key = ?').bind(key).first()).n).toBe(0);
  expect(await env.kv.get(key)).toBeNull();
  expect(await releaseObjectLock(env.db, 'KV', key, 'test-cleaner')).toBe(true);
  await attService.saveSendAtt({env}, [attachment()], 1, 1, 1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key = ?').bind(key).first()).n).toBe(1);
  expect(await env.kv.get(key)).toBe('abc');
  expect(await env.db.prepare('SELECT storage_type,store_id,state FROM attachment_object_origin WHERE object_key=?').bind(key).first())
    .toMatchObject({storage_type:'KV',store_id:env.attachment_kv_store_id,state:'known'});
});

it('does not write an incoming attachment while its object is reserved', async () => {
  const key = 'attachments/incoming-test.txt';
  const record = () => ({key, userId:1, accountId:1, emailId:1, filename:'file.txt', mimeType:'text/plain', content:new TextEncoder().encode('abc')});
  expect(await acquireObjectLock(env.db, 'KV', key, 'test-cleaner', 123)).toBe(true);
  await expect(attService.addAtt({env}, [record()])).rejects.toThrow('Attachment temporarily busy');
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key = ?').bind(key).first()).n).toBe(0);
  expect(await env.kv.get(key)).toBeNull();
  expect(await releaseObjectLock(env.db, 'KV', key, 'test-cleaner')).toBe(true);
  await attService.addAtt({env}, [record()]);
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key = ?').bind(key).first()).n).toBe(1);
  expect(await env.kv.get(key)).toBe('abc');
  expect(await env.db.prepare('SELECT storage_type,store_id,state FROM attachment_object_origin WHERE object_key=?').bind(key).first())
    .toMatchObject({storage_type:'KV',store_id:env.attachment_kv_store_id,state:'known'});
});

it('keeps the storage origin ambiguous when a preexisting attachment has no trusted origin', async () => {
  const key='attachments/legacy-unverified.txt';
  await env.db.prepare('INSERT INTO attachments (user_id,email_id,account_id,key) VALUES (?,?,?,?)').bind(2,2,2,key).run();
  await attService.addAtt({env}, [{key,userId:1,accountId:1,emailId:1,filename:'file.txt',mimeType:'text/plain',content:new TextEncoder().encode('abc')}]);
  expect((await env.db.prepare('SELECT state FROM attachment_object_origin WHERE object_key=?').bind(key).first()).state).toBe('ambiguous');
  expect(await env.kv.get(key)).toBe('abc');
});

it('does not guess an origin for a previously queued legacy key', async () => {
  const key='attachments/legacy-queued.txt';
  await env.db.prepare("INSERT INTO account_deletion_object_queue(user_id,storage_type,object_key) VALUES (0,'UNRESOLVED',?)").bind(key).run();
  await attService.addAtt({env}, [{key,userId:1,accountId:1,emailId:1,filename:'file.txt',mimeType:'text/plain',content:new TextEncoder().encode('abc')}]);
  expect((await env.db.prepare('SELECT state FROM attachment_object_origin WHERE object_key=?').bind(key).first()).state).toBe('ambiguous');
});

it('fails before writing when the isolated test store identity is missing', async () => {
  const key='attachments/missing-test-store-id.txt';
  const testEnv={...env,attachment_kv_store_id:''};
  await expect(attService.addAtt({env:testEnv},[{key,userId:1,accountId:1,emailId:1,filename:'file.txt',mimeType:'text/plain',content:new TextEncoder().encode('abc')}])).rejects.toThrow('Test KV identity missing');
  expect(await env.kv.get(key)).toBeNull();
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key=?').bind(key).first()).n).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachment_object_origin WHERE object_key=?').bind(key).first()).n).toBe(0);
});

it('retains a written object for investigation if attachment metadata insertion fails', async () => {
  const key='attachments/' + await fileUtils.getBuffHash(new TextEncoder().encode('abc')) + '.txt';
  await env.db.prepare("CREATE TRIGGER fail_attachment_insert BEFORE INSERT ON attachments BEGIN SELECT RAISE(ABORT, 'simulated metadata failure'); END").run();
  try {
    await expect(attService.saveSendAtt({env},[{filename:'file.txt',type:'text/plain',content:'YWJj'}],1,1,1)).rejects.toThrow();
    expect(await env.kv.get(key)).toBe('abc');
    expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key=?').bind(key).first()).n).toBe(0);
    expect((await env.db.prepare("SELECT count(*) AS n FROM account_deletion_object_queue WHERE object_key=? AND storage_type='UNRESOLVED'").bind(key).first()).n).toBe(1);
    expect((await env.db.prepare('SELECT count(*) AS n FROM attachment_object_lock WHERE object_key=?').bind(key).first()).n).toBe(0);
  } finally {
    await env.db.prepare('DROP TRIGGER fail_attachment_insert').run();
  }
});

it('records origins for embedded attachments but never guesses for reference-only images', async () => {
  const key='attachments/new-inline.png', referenced='attachments/legacy-inline.png';
  await env.db.prepare('INSERT INTO attachments (user_id,email_id,account_id,key) VALUES (?,?,?,?)').bind(2,2,2,referenced).run();
  await attService.saveArticleAtt({env},[
    {key,buff:new TextEncoder().encode('image'),filename:'image.png',mimeType:'image/png'},
    {key:referenced,filename:'old.png',mimeType:'image/png'}
  ],1,1,1);
  expect((await env.db.prepare('SELECT state FROM attachment_object_origin WHERE object_key=?').bind(key).first()).state).toBe('known');
  expect(await env.db.prepare('SELECT state FROM attachment_object_origin WHERE object_key=?').bind(referenced).first()).toBeNull();
});

it('restores an inline image removed between reading and saving its new reference', async () => {
  const key='attachments/inline-race.png';
  const bytes=new TextEncoder().encode('inline image bytes');
  await attService.addAtt({env},[{key,userId:1,accountId:1,emailId:45,filename:'inline.png',mimeType:'image/png',content:bytes}]);
  await attService.removeByEmailIds({env},[45]);
  expect(await processTestKvAttachment({env},{userId:0,storageType:'KV',key},'inline-cleaner',100)).toBe('deleted');
  expect(await env.kv.get(key)).toBeNull();
  await attService.saveArticleAtt({env},[{key,content:bytes,filename:'inline.png',mimeType:'image/png'}],1,1,44);
  expect(await env.kv.get(key)).toBe('inline image bytes');
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key=? AND email_id=44').bind(key).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT state FROM attachment_object_origin WHERE object_key=?').bind(key).first()).state).toBe('known');
});

it('does not create a dangling inline image reference when the bytes are unavailable', async () => {
  const key='attachments/missing-inline.png';
  await expect(attService.saveArticleAtt({env},[{key,filename:'inline.png',mimeType:'image/png'}],1,1,44)).rejects.toThrow('Inline image is no longer available');
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key=?').bind(key).first()).n).toBe(0);
});

it('keeps a new shared KV attachment until its final reference is removed', async () => {
  const key='attachments/new-shared-flow.txt';
  const record=(userId,emailId)=>({key,userId,accountId:userId,emailId,filename:'file.txt',mimeType:'text/plain',content:new TextEncoder().encode('same')});
  await attService.addAtt({env},[record(1,101)]);
  await attService.addAtt({env},[record(2,202)]);
  expect((await env.db.prepare('SELECT state FROM attachment_object_origin WHERE object_key=?').bind(key).first()).state).toBe('known');
  await attService.removeByEmailIds({env},[101]);
  expect((await env.db.prepare('SELECT storage_type FROM account_deletion_object_queue WHERE user_id=0 AND object_key=?').bind(key).first()).storage_type).toBe('KV');
  const item={userId:0,storageType:'KV',key};
  expect(await processTestKvAttachment({env},item,'shared-first',100)).toBe('shared');
  expect(await env.kv.get(key)).toBe('same');
  await attService.removeByEmailIds({env},[202]);
  const wrongEnv={...env,attachment_kv_store_id:'kv:00000000000000000000000000000002'};
  expect(await processTestKvAttachment({env:wrongEnv},item,'wrong-store',101)).toBe('unresolved');
  expect(await env.kv.get(key)).toBe('same');
  expect(await processTestKvAttachment({env},item,'shared-last',102)).toBe('deleted');
  expect(await env.kv.get(key)).toBeNull();
  await expect(processTestKvAttachment({env:{...env,attachment_origin_test_only:'disabled'}},item,'disabled',103))
    .rejects.toThrow('Isolated KV cleanup is not configured');
});

it('rejects incoming mail and retains failure details if its attachment cannot be saved', async () => {
  const verified = await proof('attachment-owner@external.test');
  expect((await post('/register', {email:'receiver@example.com', password:'test-password', ...verified})).code).toBe(200);
  await env.db.prepare('UPDATE setting SET receive=0').run();
  await refresh();
  const key = 'attachments/' + await fileUtils.getBuffHash(new TextEncoder().encode('abc')) + '.txt';
  expect(await acquireObjectLock(env.db, 'KV', key, 'test-cleaner', 123)).toBe(true);
  const raw = ['From: sender@external.test','To: receiver@example.com','Subject: attachment test',
    'MIME-Version: 1.0','Content-Type: multipart/mixed; boundary="test-boundary"','',
    '--test-boundary','Content-Type: text/plain; charset=utf-8','','hello',
    '--test-boundary','Content-Type: text/plain; name="file.txt"',
    'Content-Disposition: attachment; filename="file.txt"','Content-Transfer-Encoding: base64','','YWJj',
    '--test-boundary--',''].join('\r\n');
  let rejected = null;
  const bytes = new TextEncoder().encode(raw);
  const message = {from:'sender@external.test', to:'receiver@example.com', raw:new ReadableStream({start(controller) {controller.enqueue(bytes); controller.close();}}), setReject(reason) {rejected = reason;}};
  await receiveEmail(message, env, {});
  expect(rejected).toBe('Unable to save attachment; please resend');
  const row = await env.db.prepare("SELECT email_id,status,is_del FROM email WHERE subject='attachment test'").first();
  expect(row.status).toBe(8);
  expect(row.is_del).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM inbound_attachment_failure WHERE email_id=? AND object_key=?').bind(row.email_id, key).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE key=?').bind(key).first()).n).toBe(0);
  await emailService.completeReceiveAll({env});
  expect((await env.db.prepare('SELECT status,is_del FROM email WHERE email_id=?').bind(row.email_id).first())).toMatchObject({status:8,is_del:1});
  expect(await releaseObjectLock(env.db, 'KV', key, 'test-cleaner')).toBe(true);
});

it('receives a complete message and attachment when storage succeeds', async () => {
  const verified = await proof('successful-attachment@external.test');
  expect((await post('/register', {email:'success@example.com', password:'test-password', ...verified})).code).toBe(200);
  await env.db.prepare('UPDATE setting SET receive=0').run();
  await refresh();
  const raw = ['From: sender@external.test','To: success@example.com','Subject: successful attachment',
    'MIME-Version: 1.0','Content-Type: multipart/mixed; boundary="test-boundary"','',
    '--test-boundary','Content-Type: text/plain; charset=utf-8','','hello',
    '--test-boundary','Content-Type: text/plain; name="file.txt"',
    'Content-Disposition: attachment; filename="file.txt"','Content-Transfer-Encoding: base64','','YWJj',
    '--test-boundary--',''].join('\r\n');
  let rejected = null;
  const bytes = new TextEncoder().encode(raw);
  await receiveEmail({from:'sender@external.test', to:'success@example.com', raw:new ReadableStream({start(controller) {controller.enqueue(bytes); controller.close();}}), setReject(reason) {rejected = reason;}}, env, {});
  expect(rejected).toBeNull();
  const row = await env.db.prepare("SELECT email_id,status,is_del FROM email WHERE subject='successful attachment'").first();
  expect(row).toMatchObject({status:0,is_del:0});
  const attachment = await env.db.prepare('SELECT key FROM attachments WHERE email_id=?').bind(row.email_id).first();
  expect(await env.kv.get(attachment.key)).toBe('abc');
});

it('receives one complete attachment after a short object lock clears', async () => {
  const verified=await proof('brief-attachment-lock@external.test');
  expect((await post('/register',{email:'brief-attachment@example.com',password:'test-password',...verified})).code).toBe(200);
  await env.db.prepare('UPDATE setting SET receive=0').run();
  await refresh();
  const key='attachments/'+await fileUtils.getBuffHash(new TextEncoder().encode('abc'))+'.txt';
  expect(await acquireObjectLock(env.db,'KV',key,'brief-cleaner',100)).toBe(true);
  const raw=['From: sender@external.test','To: brief-attachment@example.com','Subject: brief attachment lock',
    'MIME-Version: 1.0','Content-Type: multipart/mixed; boundary="test-boundary"','',
    '--test-boundary','Content-Type: text/plain; charset=utf-8','','hello',
    '--test-boundary','Content-Type: text/plain; name="file.txt"',
    'Content-Disposition: attachment; filename="file.txt"','Content-Transfer-Encoding: base64','','YWJj',
    '--test-boundary--',''].join('\r\n');
  const bytes=new TextEncoder().encode(raw);
  let rejected=null;
  const delivery=receiveEmail({from:'sender@external.test',to:'brief-attachment@example.com',raw:new ReadableStream({start(c){c.enqueue(bytes);c.close()}}),setReject(reason){rejected=reason}},env,{});
  await new Promise(resolve=>setTimeout(resolve,120));
  expect(await releaseObjectLock(env.db,'KV',key,'brief-cleaner')).toBe(true);
  await delivery;
  expect(rejected).toBeNull();
  const rows=await env.db.prepare("SELECT email_id,status,is_del FROM email WHERE subject='brief attachment lock'").all();
  expect(rows.results).toHaveLength(1);
  expect(rows.results[0]).toMatchObject({status:0,is_del:0});
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachments WHERE email_id=? AND key=?').bind(rows.results[0].email_id,key).first()).n).toBe(1);
  expect(await env.kv.get(key)).toBe('abc');
});

it('does not copy a stale on-site attachment reference after its source was deleted', async () => {
  const stale = [{attId:99999, key:'attachments/deleted-test.txt'}];
  await expect(emailService.HandleOnSiteEmail({env}, [], {emailId:1}, stale)).rejects.toThrow('附件已不可用');
  expect((await env.db.prepare("SELECT count(*) AS n FROM attachments WHERE key='attachments/deleted-test.txt'").first()).n).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM attachment_object_lock').first()).n).toBe(0);
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

async function googleLogin(subject = 'google-test-user', emailVerified = true) {
  fetchMock.get('https://oauth2.googleapis.com').intercept({path:'/token', method:'POST'}).reply(200, options => {
    expect(new URLSearchParams(options.body).get('code_verifier')).toBe('a'.repeat(64));
    return JSON.stringify({access_token:'mock-google-access-token'});
  });
  fetchMock.get('https://openidconnect.googleapis.com').intercept({path:'/v1/userinfo', method:'GET'}).reply(200, JSON.stringify({sub:subject, email:'person@gmail.com', email_verified:emailVerified, name:'Test'}));
  return post('/oauth/google/login', {code:'mock-auth-code',redirectUri:'https://local.test/login',codeVerifier:'a'.repeat(64)});
}

it('only remembers Google email from verified server-side Google userinfo', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const first = await googleLogin('verified-google-contact', true);
  const id = first.data.userInfo.oauthId;
  expect(await env.db.prepare('SELECT subject,email FROM google_verified_contact WHERE oauth_id=?').bind(id).first())
    .toMatchObject({subject:'verified-google-contact',email:'person@gmail.com'});
  await googleLogin('verified-google-contact', false);
  expect(await env.db.prepare('SELECT email FROM google_verified_contact WHERE oauth_id=?').bind(id).first()).toBeNull();
});

it('sends deletion code only to verified Google contact and binds it to one session', async () => {
  const verified = await proof('email-code-reg@external.test');
  expect((await post('/register',{email:'email-code@example.com',password:'test-password',...verified})).code).toBe(200);
  const user = await env.db.prepare("SELECT user_id FROM user WHERE email='email-code@example.com'").first();
  await env.db.prepare("INSERT INTO oauth (user_id,platform,oauth_user_id,username) VALUES (?,'google','subject-email-code','unverified@attacker.test')").bind(user.user_id).run();
  const oauth = await env.db.prepare("SELECT oauth_id FROM oauth WHERE oauth_user_id='subject-email-code'").first();
  await env.db.prepare('INSERT OR IGNORE INTO role_perm (role_id,perm_id) VALUES (1,5)').run();
  const first = await post('/login',{email:'email-code@example.com',password:'test-password'});
  const second = await post('/login',{email:'email-code@example.com',password:'test-password'});
  const call = async (path,token,body={}) => (await SELF.fetch('https://local.test/api'+path,{method:'POST',
    headers:{Authorization:token,'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  const send = token => call('/my/delete/google-email/send',token,{email:'attacker@external.test'});
  const complete = (token,code) => call('/my/delete/google-email/complete',token,{code,confirmation:'DELETE'});
  expect((await send(first.data.token)).code).not.toBe(200);
  await env.db.prepare('INSERT INTO google_verified_contact VALUES (?,?,?)').bind(oauth.oauth_id,'subject-email-code','verified@gmail.com').run();
  let code;
  fetchMock.get('https://api.resend.com').intercept({path:'/emails',method:'POST'}).reply(200,options=>{
    const mail = JSON.parse(options.body);
    expect(mail.to).toEqual(['verified@gmail.com']);
    code=mail.text.match(/\b\d{6}\b/)[0];
    return JSON.stringify({id:'sent'});
  });
  const sent=await send(first.data.token);
  expect(sent.code).toBe(200);
  expect(sent.data.maskedEmail).toBe('v***@gmail.com');
  expect((await send(first.data.token)).code).not.toBe(200);
  expect((await complete(second.data.token,code)).code).not.toBe(200);
  expect((await complete(first.data.token,code==='000000'?'000001':'000000')).code).not.toBe(200);
  expect((await complete(first.data.token,code)).code).toBe(200);
  const request=await env.db.prepare('SELECT state,purge_after,requested_at FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first();
  expect(request.state).toBe('pending');
  expect(request.purge_after-request.requested_at).toBe(2592000);
  expect((await complete(first.data.token,code)).code).not.toBe(200);
  expect((await post('/login',{email:'email-code@example.com',password:'test-password'})).code).not.toBe(200);
});

it('rejects expired codes and changes of Google contact or subject', async () => {
  const verified = await proof('email-race-reg@external.test');
  expect((await post('/register',{email:'email-race@example.com',password:'test-password',...verified})).code).toBe(200);
  const user=await env.db.prepare("SELECT user_id FROM user WHERE email='email-race@example.com'").first();
  await env.db.prepare("INSERT INTO oauth (user_id,platform,oauth_user_id) VALUES (?,'google','subject-email-race')").bind(user.user_id).run();
  const oauth=await env.db.prepare("SELECT oauth_id FROM oauth WHERE oauth_user_id='subject-email-race'").first();
  await env.db.prepare('INSERT INTO google_verified_contact VALUES (?,?,?)').bind(oauth.oauth_id,'subject-email-race','verified@gmail.com').run();
  await env.db.prepare('INSERT OR IGNORE INTO role_perm (role_id,perm_id) VALUES (1,5)').run();
  const login=await post('/login',{email:'email-race@example.com',password:'test-password'});
  const call=async(path,body={})=>(await SELF.fetch('https://local.test/api'+path,{method:'POST',headers:{Authorization:login.data.token,'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  let code;
  const mock=()=>fetchMock.get('https://api.resend.com').intercept({path:'/emails',method:'POST'}).reply(200,o=>{code=JSON.parse(o.body).text.match(/\b\d{6}\b/)[0];return JSON.stringify({id:'sent'});});
  mock(); expect((await call('/my/delete/google-email/send')).code).toBe(200);
  await env.db.prepare('UPDATE google_email_deletion_code SET expires_at=0,sent_at=0 WHERE user_id=?').bind(user.user_id).run();
  expect((await call('/my/delete/google-email/complete',{code,confirmation:'DELETE'})).code).not.toBe(200);
  mock(); expect((await call('/my/delete/google-email/send')).code).toBe(200);
  await env.db.prepare("UPDATE google_verified_contact SET email='new@gmail.com' WHERE oauth_id=?").bind(oauth.oauth_id).run();
  expect((await call('/my/delete/google-email/complete',{code,confirmation:'DELETE'})).code).not.toBe(200);
  await env.db.prepare('UPDATE google_email_deletion_code SET sent_at=0 WHERE user_id=?').bind(user.user_id).run();
  mock(); expect((await call('/my/delete/google-email/send')).code).toBe(200);
  const wrong=code==='000000'?'000001':'000000';
  for (let i=0;i<5;i++) expect((await call('/my/delete/google-email/complete',{code:wrong,confirmation:'DELETE'})).code).not.toBe(200);
  expect((await call('/my/delete/google-email/complete',{code,confirmation:'DELETE'})).code).not.toBe(200);
  await env.db.prepare('UPDATE google_email_deletion_code SET sent_at=0 WHERE user_id=?').bind(user.user_id).run();
  mock(); expect((await call('/my/delete/google-email/send')).code).toBe(200);
  await env.db.prepare("UPDATE oauth SET oauth_user_id='other-subject' WHERE oauth_id=?").bind(oauth.oauth_id).run();
  expect((await call('/my/delete/google-email/complete',{code,confirmation:'DELETE'})).code).not.toBe(200);
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account_deletion_request WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
});

it('refuses a Google contact hosted by the mailbox service and invalidates codes after send failure', async () => {
  const verified=await proof('email-provider-reg@external.test');
  expect((await post('/register',{email:'email-provider@example.com',password:'test-password',...verified})).code).toBe(200);
  const user=await env.db.prepare("SELECT user_id FROM user WHERE email='email-provider@example.com'").first();
  await env.db.prepare("INSERT INTO oauth (user_id,platform,oauth_user_id) VALUES (?,'google','provider-subject')").bind(user.user_id).run();
  const oauth=await env.db.prepare("SELECT oauth_id FROM oauth WHERE oauth_user_id='provider-subject'").first();
  await env.db.prepare('INSERT INTO google_verified_contact VALUES (?,?,?)').bind(oauth.oauth_id,'provider-subject','another@example.com').run();
  await env.db.prepare('INSERT OR IGNORE INTO role_perm (role_id,perm_id) VALUES (1,5)').run();
  const login=await post('/login',{email:'email-provider@example.com',password:'test-password'});
  const call=async(path,body={})=>(await SELF.fetch('https://local.test/api'+path,{method:'POST',headers:{Authorization:login.data.token,'Content-Type':'application/json'},body:JSON.stringify(body)})).json();
  expect((await call('/my/delete/google-email/send')).code).not.toBe(200);
  await env.db.prepare("UPDATE google_verified_contact SET email='verified@gmail.com' WHERE oauth_id=?").bind(oauth.oauth_id).run();
  let code;
  fetchMock.get('https://api.resend.com').intercept({path:'/emails',method:'POST'}).reply(403,o=>{
    code=JSON.parse(o.body).text.match(/\b\d{6}\b/)[0]; return JSON.stringify({name:'validation_error',message:'sensitive provider error'});
  });
  const failed=await call('/my/delete/google-email/send');
  expect(failed.code).not.toBe(200);
  expect(failed.message).not.toContain('sensitive');
  expect((await call('/my/delete/google-email/complete',{code,confirmation:'DELETE'})).code).not.toBe(200);
  expect((await env.db.prepare('SELECT is_del FROM user WHERE user_id=?').bind(user.user_id).first()).is_del).toBe(0);
});

it('requires Google binding proof and external email verification, and supports subsequent login', async () => {
  await env.db.prepare("UPDATE setting SET google_switch=0, google_client_id='test-client', google_client_secret='test-secret'").run();
  await refresh();
  const oauth = await googleLogin();
  expect(oauth.code).toBe(200);
  expect(oauth.data.token).toBeNull();
  expect(typeof oauth.data.bindToken).toBe('string');
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
  expect((await bind({...params, bindToken:oauth.data.bindToken})).code).not.toBe(200);
  expect((await env.db.prepare("SELECT count(*) AS n FROM user WHERE email='oauth@example.com'").first()).n).toBe(0);
  const verified = await proof();
  const bound = await bind({...params,bindToken:oauth.data.bindToken,...verified});
  expect(bound.code).toBe(200);
  expect(typeof bound.data.token).toBe('string');
  expect((await bind({...params,bindToken:oauth.data.bindToken,...verified})).code).not.toBe(200);
  await env.db.prepare('UPDATE setting SET register=1').run();
  await refresh();
  const later = await googleLogin();
  expect(later.code).toBe(200);
  expect(typeof later.data.token).toBe('string');
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
