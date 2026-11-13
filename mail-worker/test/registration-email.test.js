import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';

const sent = vi.hoisted(() => []);
vi.mock('resend', () => ({ Resend: class { emails = { send: async (msg) => { sent.push(msg); return { data: { id: 'test' }, error: null }; } }; } }));
vi.mock('../src/service/setting-service', () => ({ default: { query: async () => ({ register: 0, resendTokens: { 'example.com': 'test' } }) } }));
import verification from '../src/service/registration-email-service';
import settingService from '../src/service/setting-service';

let db, c, kv;
beforeEach(() => {
  vi.useFakeTimers();
  sent.length = 0;
  db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE registration_email_verification (email_hash TEXT PRIMARY KEY, challenge TEXT NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL, consumed INTEGER NOT NULL);
    CREATE TABLE registration_email_rate (ip_hash TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL);`);
  kv = new Map();
  c = { env: { domain: ['example.com'], jwt_secret: 'test secret', db: { prepare(sql) { return { bind(...args) { return { async first() { return db.prepare(sql).get(...args) || null; } }; } }; } }, kv: { async put(k,v) { kv.set(k,v); }, async get(k) { return kv.get(k); } } }, req: { header() { return '192.0.2.1'; } } };
});
afterEach(() => { db.close(); vi.useRealTimers(); vi.restoreAllMocks(); });

async function issue() {
  const { challenge } = await verification.send(c, { externalEmail: 'test@outside.com' });
  const code = sent.at(-1).text.match(/\b\d{6}\b/)[0];
  return { externalEmail: 'test@outside.com', emailChallenge: challenge, emailVerificationCode: code };
}

describe('registration email verification', () => {
  it.each(['163.com', 'gmail.com', 'qq.com'])('accepts an existing external %s mailbox', async (domain) => {
    const externalEmail = `receiver@${domain}`;
    const {challenge} = await verification.send(c, {externalEmail});
    const code = sent[0].text.match(/\b\d{6}\b/)[0];
    expect(sent[0].to).toEqual([externalEmail]);
    await expect(verification.consume(c, {externalEmail, emailChallenge:challenge, emailVerificationCode:code})).resolves.toBeUndefined();
  });
  it('supports initial setup using a dedicated Resend secret before an admin exists', async () => {
    vi.spyOn(settingService, 'query').mockResolvedValueOnce({register:0,resendTokens:{}});
    c.env.registration_resend_token = 'test-bootstrap-token';
    const params = await issue();
    expect(sent[0].from).toContain('no-reply@example.com');
    await expect(verification.consume(c, params)).resolves.toBeUndefined();
  });
  it('fails closed without either form of Resend configuration', async () => {
    vi.spyOn(settingService, 'query').mockResolvedValueOnce({register:0,resendTokens:{}});
    await expect(issue()).rejects.toThrow();
    expect(sent).toHaveLength(0);
  });
  it('accepts a valid code once, including under concurrent requests', async () => {
    const params = await issue();
    const results = await Promise.allSettled([verification.consume(c, params), verification.consume(c, params)]);
    expect(results.filter(x => x.status === 'fulfilled')).toHaveLength(1);
    await expect(verification.consume(c, params)).rejects.toThrow();
  });
  it('enforces the five-attempt limit', async () => {
    const params = await issue();
    const wrong = params.emailVerificationCode === '000000' ? '000001' : '000000';
    for (let i=0; i<5; i++) await expect(verification.consume(c, {...params, emailVerificationCode: wrong})).rejects.toThrow();
    await expect(verification.consume(c, params)).rejects.toThrow();
  });
  it('expires after five minutes and limits resend', async () => {
    const params = await issue();
    await expect(verification.send(c, {externalEmail: params.externalEmail})).rejects.toThrow();
    vi.advanceTimersByTime(300001);
    await expect(verification.consume(c, params)).rejects.toThrow();
  });
  it('invalidates the previous challenge when a new code is sent', async () => {
    const old = await issue();
    vi.advanceTimersByTime(60000);
    const current = await issue();
    await expect(verification.consume(c, old)).rejects.toThrow();
    await expect(verification.consume(c, current)).resolves.toBeUndefined();
  });
  it('limits an IP address to ten requests per hour', async () => {
    for (let i=0; i<10; i++) await verification.send(c, {externalEmail:`test${i}@outside.com`});
    await expect(verification.send(c, {externalEmail:'next@outside.com'})).rejects.toThrow();
  });
  it('rejects internal addresses and codes for a different address', async () => {
    await expect(verification.send(c, {externalEmail:'name@example.com'})).rejects.toThrow();
    const params = await issue();
    await expect(verification.consume(c, {...params, externalEmail:'other@outside.com'})).rejects.toThrow();
  });
});
