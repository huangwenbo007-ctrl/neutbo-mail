// Isolated preview only. Production cleanup and recovery are not complete.
import { Resend } from 'resend';
import BizError from '../error/biz-error';
import settingService from './setting-service';
import userContext from '../security/user-context';
import jwtUtils from '../utils/jwt-utils';
import constant from '../const/constant';
import { withAccountLock } from './account-deletion-state';

const fail = () => new BizError('验证码无效、已过期或暂时无法使用');
const enc = new TextEncoder();
const nowSeconds = () => Math.floor(Date.now() / 1000);
async function mac(secret, value) {
	const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
	return Array.from(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(value))), x => x.toString(16).padStart(2, '0')).join('');
}
function randomCode() {
	const v = new Uint32Array(1);
	do { crypto.getRandomValues(v); } while (v[0] >= 4294000000);
	return String(v[0] % 1000000).padStart(6, '0');
}
async function context(c) {
	const userId = userContext.getUserId(c);
	const claims = await jwtUtils.verifyToken(c, c.req.header(constant.TOKEN_HEADER));
	const secret = c.env.jwt_secret;
	const generation = claims?.generation ?? 0;
	if (!Number.isSafeInteger(userId) || userId <= 0 || claims?.userId !== userId ||
		!Number.isSafeInteger(generation) || generation < 0 || typeof claims?.token !== 'string' || !claims.token ||
		typeof secret !== 'string' || !secret || typeof c.env.admin !== 'string' || !c.env.admin.trim()) throw fail();
	return {userId, generation, secret, admin:c.env.admin.trim(), sessionHash:await mac(secret, 'delete-email-session:' + claims.token)};
}
function mask(email) {
	const at = email.lastIndexOf('@');
	return email.slice(0, 1) + '***' + email.slice(at);
}

export async function sendGoogleEmailDeletionCode(c) {
	const v = await context(c);
	const contact = await c.env.db.prepare(`SELECT o.oauth_id, o.oauth_user_id AS subject, g.email FROM user u
		JOIN oauth o ON o.user_id=u.user_id AND o.platform='google'
		JOIN google_verified_contact g ON g.oauth_id=o.oauth_id AND g.subject=o.oauth_user_id
		WHERE u.user_id=? AND u.status=0 AND u.is_del=0 AND u.email COLLATE NOCASE != ? LIMIT 1`)
		.bind(v.userId, v.admin).first();
	if (!contact) throw new BizError('没有已确认的 Google 邮箱，请先用已绑定的 Google 账号登录一次');
	const domains = Array.isArray(c.env.domain) ? c.env.domain : JSON.parse(c.env.domain);
	// An address hosted by this service would let an already stolen session
	// read its own challenge, so it cannot serve as independent confirmation.
	const contactDomain = contact.email.slice(contact.email.lastIndexOf('@') + 1).toLowerCase();
	if (!contactDomain || domains.some(d => d.toLowerCase() === contactDomain)) throw new BizError('请使用可独立收信的 Google 邮箱');
	const setting = await settingService.query(c);
	const senderDomain = c.env.registration_resend_token ? domains[0] : domains.find(d => setting.resendTokens[d]);
	const resendToken = c.env.registration_resend_token || setting.resendTokens[senderDomain];
	if (!senderDomain || !resendToken) throw new BizError('邮箱验证服务尚未配置');
	const now = nowSeconds();
	const rate = await c.env.db.prepare(`INSERT INTO google_email_deletion_rate(user_id,window_start,count) VALUES (?, ?, 1)
		ON CONFLICT(user_id) DO UPDATE SET window_start=CASE WHEN window_start<=? THEN excluded.window_start ELSE window_start END,
		count=CASE WHEN window_start<=? THEN 1 ELSE count+1 END WHERE window_start<=? OR count<5 RETURNING count`)
		.bind(v.userId,now,now-3600,now-3600,now-3600).first();
	if (!rate) throw new BizError('发送次数过多，请稍后再试');
	const challenge = crypto.randomUUID(), code = randomCode();
	const digest = await mac(v.secret, JSON.stringify(['google-delete-email-v1',v.userId,contact.oauth_id,contact.subject,contact.email,v.sessionHash,challenge,code]));
	const saved = await c.env.db.prepare(`INSERT INTO google_email_deletion_code
		(user_id,oauth_id,subject,email,session_hash,challenge,code_hash,sent_at,expires_at,attempts,consumed)
		VALUES (?,?,?,?,?,?,?,?,?,0,0) ON CONFLICT(user_id) DO UPDATE SET oauth_id=excluded.oauth_id,
		subject=excluded.subject,email=excluded.email,session_hash=excluded.session_hash,challenge=excluded.challenge,
		code_hash=excluded.code_hash,sent_at=excluded.sent_at,expires_at=excluded.expires_at,attempts=0,consumed=0
		WHERE sent_at<=? RETURNING challenge`)
		.bind(v.userId,contact.oauth_id,contact.subject,contact.email,v.sessionHash,challenge,digest,now,now+300,now-60).first();
	if (!saved) throw new BizError('发送过于频繁，请等待60秒');
	try {
		const result = await new Resend(resendToken).emails.send({from:`Neutbo Mail <no-reply@${senderDomain}>`,to:[contact.email],
			subject:'Neutbo Mail 删除账户验证码',text:`您的删除账户验证码是 ${code}，5分钟内有效。确认后账户将进入30天恢复期。若非本人操作，请忽略并检查账号安全。`});
		if (result.error) throw new Error('delivery rejected');
	} catch {
		await c.env.db.prepare('UPDATE google_email_deletion_code SET consumed=1 WHERE user_id=? AND challenge=?').bind(v.userId,challenge).run();
		throw new BizError('验证码发送失败，请稍后重试');
	}
	return { maskedEmail:mask(contact.email) };
}

export async function completeGoogleEmailDeletion(c, body) {
	const v = await context(c);
	if (body?.confirmation !== 'DELETE' || typeof body.code !== 'string' || !/^\d{6}$/.test(body.code)) throw fail();
	const now = nowSeconds();
	const row = await c.env.db.prepare(`UPDATE google_email_deletion_code SET attempts=attempts+1
		WHERE user_id=? AND session_hash=? AND consumed=0 AND expires_at>? AND attempts<5
		RETURNING oauth_id,subject,email,challenge,code_hash,session_hash`)
		.bind(v.userId,v.sessionHash,now).first();
	if (!row) throw fail();
	const digest = await mac(v.secret, JSON.stringify(['google-delete-email-v1',v.userId,row.oauth_id,row.subject,row.email,v.sessionHash,row.challenge,body.code]));
	if (!crypto.subtle.timingSafeEqual(enc.encode(digest),enc.encode(row.code_hash))) throw fail();
	const committed = await withAccountLock(c.env.db,v.userId,async () => {
		const t = nowSeconds();
		return c.env.db.batch([
			c.env.db.prepare(`UPDATE google_email_deletion_code SET consumed=1 WHERE user_id=? AND challenge=? AND code_hash=?
				AND session_hash=? AND consumed=0 AND expires_at>? AND attempts<=5
				AND EXISTS (SELECT 1 FROM user u JOIN oauth o ON o.user_id=u.user_id
					JOIN google_verified_contact g ON g.oauth_id=o.oauth_id AND g.subject=o.oauth_user_id
					WHERE u.user_id=? AND u.status=0 AND u.is_del=0 AND u.email COLLATE NOCASE != ?
					AND o.platform='google' AND o.oauth_id=? AND o.oauth_user_id=? AND g.email=?)
				AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=?),0)=?`)
				.bind(v.userId,row.challenge,digest,v.sessionHash,t,v.userId,v.admin,row.oauth_id,row.subject,row.email,v.userId,v.generation),
			c.env.db.prepare('UPDATE user SET is_del=1 WHERE user_id=? AND is_del=0 AND status=0 AND changes()=1').bind(v.userId),
			c.env.db.prepare(`INSERT INTO account_deletion_request(user_id,requested_at,purge_after,state)
				SELECT ?,?,?,'pending' WHERE changes()=1`).bind(v.userId,t,t+2592000),
			c.env.db.prepare(`INSERT INTO account_session_generation(user_id,generation) SELECT ?,1 WHERE changes()=1
				ON CONFLICT(user_id) DO UPDATE SET generation=generation+1`).bind(v.userId),
		]);
	});
	if (!committed.every(item => item.meta.changes === 1)) throw fail();
	return {recoverUntil:nowSeconds()+2592000};
}
