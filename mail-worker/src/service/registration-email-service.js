import { Resend } from 'resend';
import BizError from '../error/biz-error';
import settingService from './setting-service';
import verifyUtils from '../utils/verify-utils';

const prefix = 'registration-email:';
const ttl = 300;

async function mac(secret, value) {
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
	const bytes = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
	return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function externalEmail(value, domains) {
	if (typeof value !== 'string') throw new BizError('请输入有效的外部邮箱');
	const email = value.trim().toLowerCase();
	if (email.length > 254 || !verifyUtils.isEmail(email) || /[\r\n]/.test(email)) throw new BizError('请输入有效的外部邮箱');
	const domain = email.slice(email.lastIndexOf('@') + 1);
	if (domains.some(item => item.toLowerCase() === domain)) throw new BizError('请使用已有的外部邮箱');
	return email;
}

function randomCode() {
	const value = new Uint32Array(1);
	do { crypto.getRandomValues(value); } while (value[0] >= 4294000000);
	return String(value[0] % 1000000).padStart(6, '0');
}

export default {
	async cleanup(c) {
		const cutoff = Math.floor(Date.now() / 1000) - 86400;
		await c.env.db.batch([
			c.env.db.prepare('DELETE FROM registration_email_verification WHERE expires_at < ?').bind(cutoff),
			c.env.db.prepare('DELETE FROM registration_email_rate WHERE window_start < ?').bind(cutoff)
		]);
	},
	async send(c, params) {
		const setting = await settingService.query(c);
		if (setting.register === 1) throw new BizError('注册已关闭');
		const domains = Array.isArray(c.env.domain) ? c.env.domain : JSON.parse(c.env.domain);
		const email = externalEmail(params.externalEmail, domains);
		const senderDomain = domains.find(domain => setting.resendTokens[domain]);
		if (!senderDomain || !c.env.jwt_secret) throw new BizError('邮箱验证服务尚未配置');
		const now = Math.floor(Date.now() / 1000);
		const ip = c.req.header('CF-Connecting-IP');
		if (!ip) throw new BizError('无法验证请求来源');
		const ipHash = await mac(c.env.jwt_secret, 'ip:' + ip);
		const rate = await c.env.db.prepare(`INSERT INTO registration_email_rate (ip_hash, window_start, count) VALUES (?, ?, 1)
			ON CONFLICT(ip_hash) DO UPDATE SET window_start = CASE WHEN window_start <= ? THEN excluded.window_start ELSE window_start END,
			count = CASE WHEN window_start <= ? THEN 1 ELSE count + 1 END
			WHERE window_start <= ? OR count < 10 RETURNING count`).bind(ipHash, now, now - 3600, now - 3600, now - 3600).first();
		if (!rate) throw new BizError('请求过于频繁，请稍后再试');
		const emailHash = await mac(c.env.jwt_secret, 'email:' + email);
		const challenge = crypto.randomUUID();
		const row = await c.env.db.prepare(`INSERT INTO registration_email_verification (email_hash, challenge, sent_at, expires_at, attempts, consumed)
			VALUES (?, ?, ?, ?, 0, 0) ON CONFLICT(email_hash) DO UPDATE SET challenge=excluded.challenge,
			sent_at=excluded.sent_at, expires_at=excluded.expires_at, attempts=0, consumed=0
			WHERE sent_at <= ? RETURNING challenge`).bind(emailHash, challenge, now, now + ttl, now - 60).first();
		if (!row) throw new BizError('发送过于频繁，请等待60秒');
		const code = randomCode();
		await c.env.kv.put(prefix + challenge, await mac(c.env.jwt_secret, `code:${emailHash}:${challenge}:${code}`), {expirationTtl: ttl});
		const resend = new Resend(setting.resendTokens[senderDomain]);
		const result = await resend.emails.send({from: `Neutbo Mail <no-reply@${senderDomain}>`, to: [email], subject: 'Neutbo Mail 注册验证码', text: `您的验证码是 ${code}，5分钟内有效。请勿将验证码告知他人。`});
		if (result.error) throw new BizError('验证码发送失败，请稍后重试');
		return {challenge};
	},

	async consume(c, params) {
		const domains = Array.isArray(c.env.domain) ? c.env.domain : JSON.parse(c.env.domain);
		const email = externalEmail(params.externalEmail, domains);
		const { emailChallenge: challenge, emailVerificationCode: code } = params;
		if (typeof challenge !== 'string' || !/^[0-9a-f-]{36}$/i.test(challenge) || typeof code !== 'string' || !/^\d{6}$/.test(code)) throw new BizError('请输入有效的邮箱验证码');
		const emailHash = await mac(c.env.jwt_secret, 'email:' + email);
		const now = Math.floor(Date.now() / 1000);
		const attempt = await c.env.db.prepare(`UPDATE registration_email_verification SET attempts=attempts+1
			WHERE email_hash=? AND challenge=? AND expires_at>? AND attempts<5 AND consumed=0 RETURNING challenge`).bind(emailHash, challenge, now).first();
		if (!attempt) throw new BizError('验证码无效、过期或尝试次数过多');
		const expected = await c.env.kv.get(prefix + challenge);
		const actual = await mac(c.env.jwt_secret, `code:${emailHash}:${challenge}:${code}`);
		if (!expected || expected !== actual) throw new BizError('验证码无效、过期或尝试次数过多');
		const consumed = await c.env.db.prepare(`UPDATE registration_email_verification SET consumed=1
			WHERE email_hash=? AND challenge=? AND expires_at>? AND consumed=0 AND attempts<=5 RETURNING challenge`).bind(emailHash, challenge, Math.floor(Date.now()/1000)).first();
		if (!consumed) throw new BizError('验证码已使用或过期');
	}
};
