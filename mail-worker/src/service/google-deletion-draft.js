// Isolated-test prototype. Do not enable in production until cleanup,
// recovery, migration and a real Google reauthentication have been reviewed.
import BizError from '../error/biz-error';
import settingService from './setting-service';
import userContext from '../security/user-context';
import { reserveReauthAttempt } from './account-reauth-draft';
import { verifyGoogleReauthToken } from './google-reauth-draft';
import { withAccountLock } from './account-deletion-state';
import jwtUtils from '../utils/jwt-utils';
import constant from '../const/constant';

const fail = () => new BizError('Google 身份验证失败，请重新操作');
const enc = new TextEncoder();
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const randomHex = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const base64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function context(c) {
	const userId = userContext.getUserId(c);
	const claims = await jwtUtils.verifyToken(c, c.req.header(constant.TOKEN_HEADER));
	const token = claims?.token;
	const generation = claims?.generation ?? 0;
	const secret = c.env.jwt_secret;
	const admin = c.env.admin;
	const redirect = c.env.google_reauth_redirect_uri;
	if (!Number.isSafeInteger(userId) || userId <= 0 || claims?.userId !== userId ||
		!Number.isSafeInteger(generation) || generation < 0 || typeof token !== 'string' || !token ||
		typeof secret !== 'string' || !secret || typeof admin !== 'string' || !admin.trim() || typeof redirect !== 'string') throw fail();
	let url;
	try { url = new URL(redirect); } catch { throw fail(); }
	if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/login' || url.search || url.hash ||
		url.origin !== new URL(c.req.url).origin) throw fail();
	const setting = await settingService.query(c);
	if (setting.googleSwitch !== 0 || !setting.googleClientId || !setting.googleClientSecret) throw fail();
	const key = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
	const sessionHash = hex(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode('google-deletion-session:' + token))));
	return {userId, admin:admin.trim(), redirect, setting, sessionHash, generation};
}

export async function startGoogleDeletion(c) {
	const v = await context(c);
	const now = Math.floor(Date.now()/1000);
	if (!await reserveReauthAttempt(c.env.db, v.userId, now)) throw fail();
	const owner = await c.env.db.prepare(`SELECT u.email, o.oauth_user_id AS subject FROM user u JOIN oauth o ON o.user_id=u.user_id
		WHERE u.user_id=? AND u.is_del=0 AND u.status=0 AND o.platform='google' AND o.oauth_user_id IS NOT NULL LIMIT 1`).bind(v.userId).first();
	if (!owner?.subject || owner.email.toLowerCase() === v.admin.toLowerCase()) throw fail();
	const state = randomHex(), nonce = randomHex(), verifier = randomHex();
	const challenge = base64url(await crypto.subtle.digest('SHA-256', enc.encode(verifier)));
	await c.env.db.prepare(`INSERT INTO google_deletion_challenge (user_id,state,session_hash,nonce,verifier,subject,expires_at)
		VALUES (?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET state=excluded.state,session_hash=excluded.session_hash,
		nonce=excluded.nonce,verifier=excluded.verifier,subject=excluded.subject,expires_at=excluded.expires_at`)
		.bind(v.userId,state,v.sessionHash,nonce,verifier,owner.subject,now+300).run();
	const q = new URLSearchParams({client_id:v.setting.googleClientId, redirect_uri:v.redirect, response_type:'code',
		scope:'openid', state, nonce, code_challenge:challenge, code_challenge_method:'S256', prompt:'login', max_age:'0',
		claims:JSON.stringify({id_token:{auth_time:{essential:true}}})});
	return {url:'https://accounts.google.com/o/oauth2/v2/auth?' + q.toString()};
}

export async function completeGoogleDeletion(c, body) {
	const v = await context(c);
	if (!body || body.confirmation !== 'DELETE' || typeof body.state !== 'string' || !/^[a-f0-9]{64}$/.test(body.state) ||
		typeof body.code !== 'string' || !body.code || body.code.length > 2048) throw fail();
	const now = Math.floor(Date.now()/1000);
	// Consume before network calls, even on failure. This prevents replay and
	// leaves mismatched sessions unable to consume another session's challenge.
	const challenge = await c.env.db.prepare(`DELETE FROM google_deletion_challenge
		WHERE user_id=? AND state=? AND session_hash=? AND expires_at>? RETURNING nonce,verifier,subject,expires_at`)
		.bind(v.userId,body.state,v.sessionHash,now).first();
	if (!challenge) throw fail();
	let token;
	try {
		const form = new URLSearchParams({client_id:v.setting.googleClientId, client_secret:v.setting.googleClientSecret,
			code:body.code, redirect_uri:v.redirect, grant_type:'authorization_code', code_verifier:challenge.verifier});
		const response = await fetch('https://oauth2.googleapis.com/token', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:form.toString()});
		if (!response.ok) throw new Error('exchange failed');
		token = (await response.json()).id_token;
	} catch { throw fail(); }
	const verifiedAt = Math.floor(Date.now()/1000);
	if (challenge.expires_at <= verifiedAt || !await verifyGoogleReauthToken(token, v.setting.googleClientId, challenge.nonce, challenge.subject, verifiedAt)) throw fail();
	const requestedAt = Math.floor(Date.now()/1000);
	if (challenge.expires_at <= requestedAt) throw fail();
	const committed = await commitGoogleDeletion(c.env.db, v.userId, v.admin, challenge.subject, v.generation, requestedAt);
	if (!committed) throw fail();
	return {recoverUntil:requestedAt+2592000};
}

// Trusted, verified server-side inputs only. The atomic predicates reject a
// revoked generation or a Google identity rebound while the exchange ran.
export async function commitGoogleDeletion(db, userId, admin, subject, generation, requestedAt) {
	if (!Number.isSafeInteger(userId) || userId <= 0 || typeof admin !== 'string' || !admin.trim() ||
		typeof subject !== 'string' || !subject || !Number.isSafeInteger(generation) || generation < 0 ||
		!Number.isSafeInteger(requestedAt) || requestedAt < 0) throw fail();
	const committed = await withAccountLock(db, userId, async () => db.batch([
		db.prepare(`UPDATE user SET is_del=1 WHERE user_id=? AND is_del=0 AND status=0 AND email COLLATE NOCASE != ?
			AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=?),0)=?
			AND EXISTS (SELECT 1 FROM oauth WHERE user_id=? AND platform='google' AND oauth_user_id=?)`)
			.bind(userId,admin.trim(),userId,generation,userId,subject),
		db.prepare(`INSERT INTO account_deletion_request(user_id,requested_at,purge_after,state)
			SELECT ?,?,?,'pending' WHERE changes()=1`).bind(userId,requestedAt,requestedAt+2592000),
		db.prepare(`INSERT INTO account_session_generation(user_id,generation) SELECT ?,1 WHERE changes()=1
			ON CONFLICT(user_id) DO UPDATE SET generation=generation+1`).bind(userId),
	]));
	return committed.every(item=>item.meta.changes===1);
}
