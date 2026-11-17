// Isolated preview only. Production requires further review of anti-abuse,
// support identity verification, old writers, retention and account cleanup.
import { Resend } from 'resend';
import BizError from '../error/biz-error';
import settingService from './setting-service';
import { withAccountLock, ReservationBusyError } from './account-deletion-state';

const encoder = new TextEncoder();
const fail = () => new BizError('验证码无效、已过期或暂时无法使用');
const nowSeconds = () => Math.floor(Date.now() / 1000);
function checkEnvironment(env) {
	if (env.account_deletion_test_only !== 'enabled' || typeof env.jwt_secret !== 'string' || !env.jwt_secret ||
		typeof env.admin !== 'string' || !env.admin.trim()) throw new Error('Recovery proof is restricted to isolated tests');
}
function mailbox(value) {
	if (typeof value !== 'string') return '';
	const email = value.trim().toLowerCase();
	return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : '';
}
async function mac(secret, value) {
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
	return Array.from(new Uint8Array(await crypto.subtle.sign('HMAC',key,encoder.encode(value))), x=>x.toString(16).padStart(2,'0')).join('');
}
function randomCode() {
	const value = new Uint32Array(1);
	do { crypto.getRandomValues(value); } while (value[0] >= 4294000000);
	return String(value[0] % 1000000).padStart(6,'0');
}
async function rate(env, key, now, limit) {
	return env.db.prepare(`INSERT INTO account_recovery_email_rate(rate_key,window_start,count) VALUES(?,?,1)
		ON CONFLICT(rate_key) DO UPDATE SET window_start=CASE WHEN window_start<=? THEN excluded.window_start ELSE window_start END,
		count=CASE WHEN window_start<=? THEN 1 ELSE count+1 END WHERE window_start<=? OR count<? RETURNING count`)
		.bind(key,now,now-3600,now-3600,now-3600,limit).first();
}
// Aliases are fixed server-side strings, never client input. Zero denotes a
// separately verified external contact; positive IDs identify Google links.
function contactMatches(proof) {
	return `((${proof}.oauth_id=0 AND EXISTS (SELECT 1 FROM account_recovery_contact rc WHERE rc.user_id=u.user_id
		AND CAST(rc.version AS TEXT)=${proof}.subject AND rc.email=${proof}.email)) OR
		(${proof}.oauth_id>0 AND EXISTS (SELECT 1 FROM oauth o JOIN google_verified_contact g ON g.oauth_id=o.oauth_id AND g.subject=o.oauth_user_id
		WHERE o.user_id=u.user_id AND o.platform='google' AND o.oauth_id=${proof}.oauth_id AND o.oauth_user_id=${proof}.subject AND g.email=${proof}.email)))`;
}
function internalDomains(env) {
	const domains=Array.isArray(env.domain)?env.domain:JSON.parse(env.domain);
	if(!domains.length||domains.some(d=>typeof d!=='string'||!d.trim())) throw new Error('Mail domains are required');
	return domains.map(d=>d.trim().toLowerCase());
}
async function eligible(env, email, now) {
	const internal=internalDomains(env), placeholders=internal.map(()=>'?').join(',');
	return env.db.prepare(`SELECT u.user_id,c.oauth_id,c.subject,c.email,
		COALESCE(s.generation,0) AS generation,r.purge_after FROM user u
		JOIN account_deletion_request r ON r.user_id=u.user_id AND r.state='pending' AND r.purge_after>?
		JOIN (SELECT user_id,0 AS oauth_id,CAST(version AS TEXT) AS subject,email,0 AS priority FROM account_recovery_contact
		UNION ALL SELECT o.user_id,o.oauth_id,o.oauth_user_id,g.email,1 FROM oauth o JOIN google_verified_contact g ON g.oauth_id=o.oauth_id AND g.subject=o.oauth_user_id WHERE o.platform='google') c ON c.user_id=u.user_id
		LEFT JOIN account_session_generation s ON s.user_id=u.user_id
		WHERE u.email COLLATE NOCASE=? AND u.email COLLATE NOCASE!=? AND u.is_del=1 AND u.status=0
		AND instr(c.email,'@')>1 AND lower(substr(c.email,instr(c.email,'@')+1)) NOT IN (${placeholders}) ORDER BY c.priority LIMIT 1`)
		.bind(now,email,env.admin.trim(),...internal).first();
}

async function requireSupportAdmin(env, actorId, actorGeneration) {
	const configured=String(env.recovery_support_admin_user_id||'');
	if (!/^[1-9]\d{0,14}$/.test(configured) || !Number.isSafeInteger(actorId) || actorId!==Number(configured) ||
		!Number.isSafeInteger(actorGeneration) || actorGeneration<0) throw new BizError('无权处理恢复申请',403);
	const row=await env.db.prepare(`SELECT 1 AS allowed FROM user u WHERE u.user_id=? AND u.email COLLATE NOCASE=? AND u.is_del=0 AND u.status=0
		AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=u.user_id),0)=?`)
		.bind(actorId,env.admin.trim(),actorGeneration).first();
	if (!row) throw new BizError('无权处理恢复申请',403);
}

export async function createSupportTicketForTest(env, userId, actorId, actorGeneration) {
	checkEnvironment(env);
	if (!Number.isSafeInteger(userId) || userId<=0) throw fail();
	await requireSupportAdmin(env,actorId,actorGeneration);
	const reference=crypto.randomUUID().replace(/-/g,'');
	const hash=await mac(env.jwt_secret,'recovery-support-reference:'+reference);
	const targetHash=await mac(env.jwt_secret,'recovery-audit-target:'+userId);
	const result=await env.db.batch([
		env.db.prepare(`INSERT INTO account_recovery_support_ticket(user_id,generation,reference_hash,created_at,expires_at,closed)
		SELECT u.user_id,COALESCE(s.generation,0),?,unixepoch(),MIN(unixepoch()+86400,r.purge_after),0 FROM user u
		JOIN account_deletion_request r ON r.user_id=u.user_id LEFT JOIN account_session_generation s ON s.user_id=u.user_id
		WHERE u.user_id=? AND u.is_del=1 AND u.status=0
		AND u.email COLLATE NOCASE!=? AND r.state='pending' AND r.purge_after>unixepoch()
		AND EXISTS (SELECT 1 FROM user admin WHERE admin.user_id=? AND admin.email COLLATE NOCASE=? AND admin.is_del=0 AND admin.status=0
		AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=admin.user_id),0)=?)
		ON CONFLICT(user_id) DO UPDATE SET generation=excluded.generation,reference_hash=excluded.reference_hash,created_at=excluded.created_at,
		expires_at=excluded.expires_at,closed=0 WHERE account_recovery_support_ticket.closed=1 OR account_recovery_support_ticket.expires_at<=unixepoch()
		OR account_recovery_support_ticket.generation!=excluded.generation`).bind(hash,userId,env.admin.trim(),actorId,env.admin.trim(),actorGeneration),
		env.db.prepare(`INSERT INTO account_recovery_support_audit(actor_user_id,user_id,target_hash,action,created_at)
			SELECT ?,?,?,'ticket_create',unixepoch() WHERE changes()=1`).bind(actorId,userId,targetHash),
	]);
	if (!result.every(item=>item.meta.changes===1)) throw fail();
	return {supportReference:reference};
}

export async function supportRecoveryStatusForTest(env,userId,actorId,actorGeneration) {
	checkEnvironment(env);
	await requireSupportAdmin(env,actorId,actorGeneration);
	if (!Number.isSafeInteger(userId) || userId<=0) throw fail();
	const domains=internalDomains(env), placeholders=domains.map(()=>'?').join(',');
	const row=await env.db.prepare(`SELECT t.expires_at AS ticket_expires, r.purge_after,
		CASE WHEN p.verified_until>unixepoch() AND p.consumed=0 AND p.reference_hash=t.reference_hash
		AND p.generation=t.generation AND t.generation=COALESCE(s.generation,0)
		AND instr(p.email,'@')>1 AND lower(substr(p.email,instr(p.email,'@')+1)) NOT IN (${placeholders})
		AND ${contactMatches('p')}
		THEN 1 ELSE 0 END AS verified
		FROM account_recovery_support_ticket t JOIN account_deletion_request r ON r.user_id=t.user_id
		JOIN user u ON u.user_id=t.user_id AND u.is_del=1 AND u.status=0
		LEFT JOIN account_session_generation s ON s.user_id=u.user_id
		LEFT JOIN account_recovery_email_code p ON p.user_id=t.user_id
		WHERE t.user_id=? AND t.closed=0 AND t.expires_at>unixepoch() AND r.state='pending' AND r.purge_after>unixepoch()
		AND EXISTS (SELECT 1 FROM user admin WHERE admin.user_id=? AND admin.email COLLATE NOCASE=? AND admin.is_del=0 AND admin.status=0
		AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=admin.user_id),0)=?)`)
		.bind(...domains,userId,actorId,env.admin.trim(),actorGeneration).first();
	const targetHash=await mac(env.jwt_secret,'recovery-audit-target:'+userId);
	const history=await env.db.prepare(`SELECT actor_user_id,action,created_at FROM account_recovery_support_audit WHERE target_hash=?
		AND EXISTS (SELECT 1 FROM user admin WHERE admin.user_id=? AND admin.email COLLATE NOCASE=? AND admin.is_del=0 AND admin.status=0
		AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=admin.user_id),0)=?)
		ORDER BY audit_id DESC LIMIT 10`).bind(targetHash,actorId,env.admin.trim(),actorGeneration).all();
	return row ? {available:true,ticketExpires:row.ticket_expires,recoverUntil:row.purge_after,verified:row.verified===1,history:history.results} : {available:false,history:history.results};
}

export async function sendRecoveryCodeForTest(c, input) {
	const {env}=c; checkEnvironment(env);
	// A slot is maintained for known and unknown mailboxes alike. A repeated
	// request during the cooldown returns the same challenge and sends no mail.
	const candidate=crypto.randomUUID(), generic = {accepted:true,challenge:candidate};
	const email=mailbox(input?.email), ip=c.req?.header('CF-Connecting-IP');
	if (!email || typeof ip !== 'string' || !ip || ip.length>128) return generic;
	const now=nowSeconds();
	const ipKey=await mac(env.jwt_secret,'recovery-ip:'+ip);
	const emailKey=await mac(env.jwt_secret,'recovery-mailbox:'+email);
	if (!await rate(env,ipKey,now,20)) {
		const slot=await env.db.prepare('SELECT challenge FROM account_recovery_email_slot WHERE email_hash=? AND issued_at>unixepoch()-60').bind(emailKey).first();
		if (slot) generic.challenge=slot.challenge;
		return generic;
	}
	const slot=await env.db.prepare(`INSERT INTO account_recovery_email_slot(email_hash,challenge,issued_at) VALUES(?,?,unixepoch())
		ON CONFLICT(email_hash) DO UPDATE SET challenge=CASE WHEN issued_at<=unixepoch()-60 THEN excluded.challenge ELSE challenge END,
		issued_at=CASE WHEN issued_at<=unixepoch()-60 THEN excluded.issued_at ELSE issued_at END RETURNING challenge`).bind(emailKey,candidate).first();
	const challenge=slot.challenge;
	generic.challenge=challenge;
	if (challenge!==candidate || !await rate(env,emailKey,now,5)) return generic;
	const contact=await eligible(env,email,now);
	if (!contact || !mailbox(contact.email)) return generic;
	const domains=Array.isArray(env.domain) ? env.domain : JSON.parse(env.domain);
	const internal=internalDomains(env), placeholders=internal.map(()=>'?').join(',');
	const contactDomain=contact.email.slice(contact.email.lastIndexOf('@')+1).toLowerCase();
	if (domains.some(d=>d.toLowerCase()===contactDomain)) return generic;
	const setting=await settingService.query(c);
	const senderDomain=env.registration_resend_token ? domains[0] : domains.find(d=>setting.resendTokens[d]);
	const token=env.registration_resend_token || setting.resendTokens[senderDomain];
	if (!senderDomain || !token) return generic;
	const code=randomCode();
	const digest=await mac(env.jwt_secret,JSON.stringify(['recovery-email-v1',contact.user_id,contact.oauth_id,contact.subject,contact.email,contact.generation,challenge,code]));
	let saved;
	try { saved=await withAccountLock(env.db,contact.user_id,()=>env.db.prepare(`INSERT INTO account_recovery_email_code
		(user_id,oauth_id,subject,email,generation,challenge,code_hash,sent_at,expires_at,attempts,verified_until,consumed)
		SELECT ?,?,?,?,?,?,?,unixepoch(),unixepoch()+300,0,0,0 WHERE EXISTS (
		SELECT 1 FROM user u JOIN account_deletion_request r ON r.user_id=u.user_id
		WHERE u.user_id=? AND u.email COLLATE NOCASE=? AND u.email COLLATE NOCASE!=? AND u.is_del=1 AND u.status=0
		AND r.state='pending' AND r.purge_after>unixepoch() AND ((?=0 AND EXISTS (SELECT 1 FROM account_recovery_contact rc WHERE rc.user_id=u.user_id AND CAST(rc.version AS TEXT)=? AND rc.email=?))
		OR (?>0 AND EXISTS (SELECT 1 FROM oauth o JOIN google_verified_contact g ON g.oauth_id=o.oauth_id AND g.subject=o.oauth_user_id WHERE o.user_id=u.user_id AND o.platform='google' AND o.oauth_id=? AND o.oauth_user_id=? AND g.email=?)))
		AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=u.user_id),0)=?)
		AND EXISTS (SELECT 1 FROM account_recovery_email_slot WHERE email_hash=? AND challenge=?)
		ON CONFLICT(user_id) DO UPDATE SET oauth_id=excluded.oauth_id,
		subject=excluded.subject,email=excluded.email,generation=excluded.generation,challenge=excluded.challenge,
		code_hash=excluded.code_hash,sent_at=excluded.sent_at,expires_at=excluded.expires_at,attempts=0,verified_until=0,reference_hash='',consumed=0
		WHERE (verified_until<=unixepoch() OR consumed=1 OR instr(account_recovery_email_code.email,'@')<=1
		OR lower(substr(account_recovery_email_code.email,instr(account_recovery_email_code.email,'@')+1)) IN (${placeholders})
		OR NOT EXISTS (SELECT 1 FROM user u JOIN account_deletion_request r ON r.user_id=u.user_id
		JOIN account_recovery_support_ticket t ON t.user_id=u.user_id
		WHERE u.user_id=account_recovery_email_code.user_id AND u.is_del=1 AND u.status=0 AND r.state='pending' AND r.purge_after>unixepoch()
		AND t.closed=0 AND t.expires_at>unixepoch() AND t.generation=account_recovery_email_code.generation
		AND t.reference_hash=account_recovery_email_code.reference_hash AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=u.user_id),0)=account_recovery_email_code.generation
		AND ${contactMatches('account_recovery_email_code')})) AND EXISTS (SELECT 1 FROM account_recovery_email_slot WHERE email_hash=? AND challenge=?)
		RETURNING challenge`).bind(contact.user_id,contact.oauth_id,contact.subject,contact.email,contact.generation,
		challenge,digest,contact.user_id,email,env.admin.trim(),contact.oauth_id,contact.subject,contact.email,contact.oauth_id,contact.oauth_id,contact.subject,contact.email,contact.generation,
		emailKey,challenge,...internal,emailKey,challenge).first()); }
	catch (error) { if (error instanceof ReservationBusyError) return generic; throw error; }
	if (!saved) return generic;
	try {
		const result=await new Resend(token).emails.send({from:`Neutbo Mail <no-reply@${senderDomain}>`,to:[contact.email],
			subject:'Neutbo Mail 恢复账户验证码',text:`您的恢复账户验证码是 ${code}，5分钟内有效。请勿将验证码告知他人。`});
		if (result.error) throw new Error('delivery rejected');
	} catch {
		await env.db.prepare('UPDATE account_recovery_email_code SET consumed=1 WHERE user_id=? AND challenge=?').bind(contact.user_id,challenge).run();
	}
	return generic;
}

export async function verifyRecoveryCodeForTest(c, input) {
	const {env}=c; checkEnvironment(env);
	const email=mailbox(input?.email), code=input?.code, reference=input?.supportReference, challenge=input?.challenge, now=nowSeconds();
	if (!email || typeof code !== 'string' || !/^\d{6}$/.test(code) ||
		typeof reference !== 'string' || !/^[0-9a-f]{32}$/.test(reference) ||
		typeof challenge !== 'string' || !/^[0-9a-f-]{36}$/.test(challenge)) throw fail();
	const contact=await eligible(env,email,now);
	if (!contact) throw fail();
	const referenceHash=await mac(env.jwt_secret,'recovery-support-reference:'+reference);
	const ticket=await env.db.prepare(`SELECT 1 AS present FROM account_recovery_support_ticket
		WHERE user_id=? AND generation=? AND reference_hash=? AND closed=0 AND expires_at>unixepoch()`).bind(contact.user_id,contact.generation,referenceHash).first();
	if (!ticket) throw fail();
	const row=await env.db.prepare(`UPDATE account_recovery_email_code SET attempts=attempts+1
		WHERE user_id=? AND generation=? AND challenge=? AND consumed=0 AND verified_until=0 AND expires_at>unixepoch() AND attempts<5
		AND EXISTS (SELECT 1 FROM account_recovery_support_ticket t JOIN user u ON u.user_id=t.user_id
		JOIN account_deletion_request r ON r.user_id=u.user_id
		WHERE t.user_id=account_recovery_email_code.user_id AND t.generation=account_recovery_email_code.generation
		AND t.reference_hash=? AND t.closed=0 AND t.expires_at>unixepoch() AND u.email COLLATE NOCASE=?
		AND u.email COLLATE NOCASE!=? AND u.is_del=1 AND u.status=0 AND r.state='pending' AND r.purge_after>unixepoch()
		AND ${contactMatches('account_recovery_email_code')} AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=u.user_id),0)=account_recovery_email_code.generation)
		RETURNING oauth_id,subject,email,generation,challenge,code_hash`).bind(contact.user_id,contact.generation,challenge,referenceHash,email,env.admin.trim()).first();
	if (!row) throw fail();
	if (row.oauth_id!==contact.oauth_id || row.subject!==contact.subject || row.email!==contact.email || row.generation!==contact.generation) throw fail();
	const digest=await mac(env.jwt_secret,JSON.stringify(['recovery-email-v1',contact.user_id,row.oauth_id,row.subject,row.email,row.generation,row.challenge,code]));
	if (!crypto.subtle.timingSafeEqual(encoder.encode(digest),encoder.encode(row.code_hash))) throw fail();
	const verified=await env.db.prepare(`UPDATE account_recovery_email_code SET
		verified_until=MIN(unixepoch()+86400,(SELECT expires_at FROM account_recovery_support_ticket WHERE user_id=?)), reference_hash=?
		WHERE user_id=? AND challenge=? AND code_hash=? AND consumed=0 AND verified_until=0 AND expires_at>unixepoch() AND attempts<=5
		AND EXISTS (SELECT 1 FROM account_recovery_support_ticket WHERE user_id=? AND generation=? AND reference_hash=? AND closed=0 AND expires_at>unixepoch())
		AND EXISTS (SELECT 1 FROM user u JOIN account_deletion_request r ON r.user_id=u.user_id
		WHERE u.user_id=? AND u.is_del=1 AND u.status=0 AND u.email COLLATE NOCASE!=? AND r.state='pending' AND r.purge_after>unixepoch()
		AND ${contactMatches('account_recovery_email_code')} AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=u.user_id),0)=?)
		RETURNING user_id`).bind(contact.user_id,referenceHash,contact.user_id,row.challenge,digest,contact.user_id,row.generation,referenceHash,
		contact.user_id,env.admin.trim(),row.generation).first();
	if (!verified) throw fail();
	return {verified:true};
}

export async function approveRecoveryForTest(env, userId, reference, actorId, actorGeneration) {
	checkEnvironment(env);
	if (!Number.isSafeInteger(userId) || userId<=0 || typeof reference !== 'string' || !/^[0-9a-f]{32}$/.test(reference)) throw fail();
	await requireSupportAdmin(env,actorId,actorGeneration);
	const referenceHash=await mac(env.jwt_secret,'recovery-support-reference:'+reference);
	const targetHash=await mac(env.jwt_secret,'recovery-audit-target:'+userId);
	const domains=internalDomains(env), placeholders=domains.map(()=>'?').join(',');
	return withAccountLock(env.db,userId,async()=>{
		const result=await env.db.batch([
			env.db.prepare(`UPDATE account_recovery_email_code SET consumed=1 WHERE user_id=? AND consumed=0 AND verified_until>unixepoch() AND reference_hash=?
				AND instr(email,'@')>1 AND lower(substr(email,instr(email,'@')+1)) NOT IN (${placeholders})
				AND EXISTS (SELECT 1 FROM user admin WHERE admin.user_id=? AND admin.email COLLATE NOCASE=? AND admin.is_del=0 AND admin.status=0
				AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=admin.user_id),0)=?)
				AND EXISTS (SELECT 1 FROM account_recovery_support_ticket WHERE user_id=? AND generation=account_recovery_email_code.generation AND reference_hash=? AND closed=0 AND expires_at>unixepoch())
				AND EXISTS (SELECT 1 FROM user u JOIN account_deletion_request r ON r.user_id=u.user_id
				WHERE u.user_id=? AND u.is_del=1 AND u.status=0 AND u.email COLLATE NOCASE!=? AND r.state='pending' AND r.purge_after>unixepoch()
				AND ${contactMatches('account_recovery_email_code')} AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=u.user_id),0)=account_recovery_email_code.generation)`)
				.bind(userId,referenceHash,...domains,actorId,env.admin.trim(),actorGeneration,userId,referenceHash,userId,env.admin.trim()),
			env.db.prepare('UPDATE user SET is_del=0 WHERE user_id=? AND is_del=1 AND changes()=1').bind(userId),
			env.db.prepare("DELETE FROM account_deletion_request WHERE user_id=? AND state='pending' AND changes()=1").bind(userId),
			env.db.prepare('DELETE FROM account_recovery_email_code WHERE user_id=? AND changes()=1').bind(userId),
			env.db.prepare('DELETE FROM account_recovery_support_ticket WHERE user_id=? AND changes()=1').bind(userId),
			env.db.prepare(`INSERT INTO account_recovery_support_audit(actor_user_id,user_id,target_hash,action,created_at)
				SELECT ?,?,?,'approve',unixepoch() WHERE changes()=1`).bind(actorId,userId,targetHash),
		]);
		if (!result.every(item=>item.meta.changes===1)) throw fail();
		return {restored:true};
	});
}

// Manual isolated-test primitive; production retention still needs a scheduler
// and an operational audit policy before this can be used.
export async function cleanupRecoveryProofsForTest(env, now) {
	checkEnvironment(env);
	if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid cleanup time');
	await env.db.batch([
		env.db.prepare('DELETE FROM account_recovery_email_code WHERE consumed=1 OR (expires_at<=? AND verified_until<=?)').bind(now,now),
		env.db.prepare('DELETE FROM account_recovery_email_rate WHERE window_start<?').bind(now-86400),
		env.db.prepare('DELETE FROM account_recovery_email_slot WHERE issued_at<?').bind(now-86400),
		env.db.prepare('DELETE FROM account_recovery_support_ticket WHERE closed=1 OR expires_at<=?').bind(now),
	]);
}
