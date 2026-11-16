import { SELF, env, fetchMock } from 'cloudflare:test';
import { beforeEach, afterEach, expect, it } from 'vitest';
import settingService from '../src/service/setting-service';
import { sign } from 'hono/jwt';
import { requestDeletion, restoreDeletion, claimDeletion, stagePurge } from '../src/service/account-deletion-state';
import jwtUtils from '../src/utils/jwt-utils';
import userService from '../src/service/user-service';
import { email as receiveEmail } from '../src/email/email';
import attService from '../src/service/att-service';
import emailService from '../src/service/email-service';
import fileUtils from '../src/utils/file-utils';
import { checkPasswordReauth } from '../src/service/account-reauth-draft';
import { acquireObjectLock, releaseObjectLock } from '../src/service/account-deletion-state';

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
  await stagePurge(env.db, user.user_id, 'KV');
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account WHERE user_id=?').bind(user.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT user_id FROM role WHERE role_id=1').first()).user_id).toBe(user.user_id);
  await env.db.prepare('UPDATE user SET is_del=1 WHERE user_id=?').bind(user.user_id).run();
  await stagePurge(env.db, user.user_id, 'KV');
  await stagePurge(env.db, user.user_id, 'KV');
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(user.user_id).first()).n).toBe(0);
  expect((await env.db.prepare('SELECT count(*) AS n FROM user WHERE user_id=?').bind(other.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT count(*) AS n FROM account WHERE user_id=?').bind(other.user_id).first()).n).toBe(1);
  expect((await env.db.prepare('SELECT user_id FROM role WHERE role_id=1').first()).user_id).toBeNull();
  expect(await env.db.prepare("SELECT user_id, count, role_id FROM reg_key WHERE code='PRESERVE-SHARED'").first()).toMatchObject({user_id:0, count:2, role_id:1});
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

async function googleLogin(subject = 'google-test-user') {
  fetchMock.get('https://oauth2.googleapis.com').intercept({path:'/token', method:'POST'}).reply(200, options => {
    expect(new URLSearchParams(options.body).get('code_verifier')).toBe('a'.repeat(64));
    return JSON.stringify({access_token:'mock-google-access-token'});
  });
  fetchMock.get('https://openidconnect.googleapis.com').intercept({path:'/v1/userinfo', method:'GET'}).reply(200, JSON.stringify({sub:subject, email:'person@gmail.com', email_verified:true, name:'Test'}));
  return post('/oauth/google/login', {code:'mock-auth-code',redirectUri:'https://local.test/login',codeVerifier:'a'.repeat(64)});
}

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
