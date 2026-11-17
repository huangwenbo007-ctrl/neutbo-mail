// Isolated preview only. Requires a current password and a code delivered to
// the new external address; a session alone cannot change recovery contact.
import { Resend } from 'resend';
import BizError from '../error/biz-error';
import settingService from './setting-service';
import userContext from '../security/user-context';
import jwtUtils from '../utils/jwt-utils';
import constant from '../const/constant';
import verifyUtils from '../utils/verify-utils';
import { passwordSnapshotForRecovery } from './account-reauth-draft';
import { withAccountLock } from './account-deletion-state';

const enc=new TextEncoder();
const fail=()=>new BizError('无法设置恢复邮箱，请检查密码或验证码');
async function mac(secret,value){const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);return Array.from(new Uint8Array(await crypto.subtle.sign('HMAC',key,enc.encode(value))),x=>x.toString(16).padStart(2,'0')).join('');}
function randomCode(){const n=new Uint32Array(1);do{crypto.getRandomValues(n)}while(n[0]>=4294000000);return String(n[0]%1000000).padStart(6,'0');}
async function context(c){
	if(c.env.account_deletion_test_only!=='enabled'||typeof c.env.jwt_secret!=='string'||!c.env.jwt_secret)throw new Error('Recovery contact is restricted to isolated tests');
	const userId=userContext.getUserId(c),claims=await jwtUtils.verifyToken(c,c.req.header(constant.TOKEN_HEADER));
	const generation=claims?.generation??0;
	if(!Number.isSafeInteger(userId)||userId<=0||claims?.userId!==userId||!Number.isSafeInteger(generation)||generation<0||typeof claims.token!=='string'||!claims.token)throw fail();
	return {userId,generation,sessionHash:await mac(c.env.jwt_secret,'recovery-contact-session:'+claims.token)};
}
function externalEmail(value,domains){
	if(typeof value!=='string')throw fail();
	const email=value.trim().toLowerCase();
	if(email.length>254||!verifyUtils.isEmail(email)||/[\r\n]/.test(email)||domains.some(d=>d.toLowerCase()===email.slice(email.lastIndexOf('@')+1)))throw fail();
	return email;
}
async function rate(env,key,limit){
	return env.db.prepare(`INSERT INTO account_recovery_email_rate(rate_key,window_start,count) VALUES(?,unixepoch(),1)
		ON CONFLICT(rate_key) DO UPDATE SET window_start=CASE WHEN window_start<=unixepoch()-3600 THEN excluded.window_start ELSE window_start END,
		count=CASE WHEN window_start<=unixepoch()-3600 THEN 1 ELSE count+1 END WHERE window_start<=unixepoch()-3600 OR count<? RETURNING count`).bind(key,limit).first();
}
function mask(email){const at=email.lastIndexOf('@');return email.slice(0,1)+'***'+email.slice(at);}

export async function recoveryContactStatusForTest(c){
	const v=await context(c);
	const row=await c.env.db.prepare('SELECT email FROM account_recovery_contact WHERE user_id=?').bind(v.userId).first();
	return row?{configured:true,maskedEmail:mask(row.email)}:{configured:false};
}

export async function sendRecoveryContactCodeForTest(c,input){
	const v=await context(c),env=c.env,domains=Array.isArray(env.domain)?env.domain:JSON.parse(env.domain);
	const email=externalEmail(input?.email,domains),now=Math.floor(Date.now()/1000);
	const snapshot=await passwordSnapshotForRecovery(env.db,v.userId,input?.password,now);
	if(!snapshot)throw fail();
	const userRate=await mac(env.jwt_secret,'contact-send-user:'+v.userId), emailRate=await mac(env.jwt_secret,'contact-send-address:'+email);
	if(!await rate(env,userRate,5)||!await rate(env,emailRate,5))throw new BizError('请求过于频繁，请稍后再试');
	const setting=await settingService.query(c),domain=env.registration_resend_token?domains[0]:domains.find(d=>setting.resendTokens[d]);
	const token=env.registration_resend_token||setting.resendTokens[domain];
	if(!domain||!token)throw new BizError('邮箱验证服务尚未配置');
	const challenge=crypto.randomUUID(),code=randomCode();
	const digest=await mac(env.jwt_secret,JSON.stringify(['recovery-contact-v1',v.userId,email,v.generation,v.sessionHash,challenge,code]));
	const saved=await withAccountLock(env.db,v.userId,()=>env.db.prepare(`INSERT INTO account_recovery_contact_code
		(user_id,email,challenge,code_hash,session_hash,generation,sent_at,expires_at,attempts,consumed)
		SELECT ?,?,?,?,?,?,unixepoch(),unixepoch()+300,0,0 WHERE EXISTS (SELECT 1 FROM user u WHERE u.user_id=? AND u.is_del=0 AND u.status=0
		AND u.password=? AND u.salt=? AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=u.user_id),0)=?)
		ON CONFLICT(user_id) DO UPDATE SET email=excluded.email,challenge=excluded.challenge,code_hash=excluded.code_hash,
		session_hash=excluded.session_hash,generation=excluded.generation,sent_at=excluded.sent_at,expires_at=excluded.expires_at,attempts=0,consumed=0
		WHERE sent_at<=unixepoch()-60 RETURNING challenge`).bind(v.userId,email,challenge,digest,v.sessionHash,v.generation,v.userId,snapshot.password,snapshot.salt,v.generation).first());
	if(!saved)throw fail();
	try{const result=await new Resend(token).emails.send({from:`Neutbo Mail <no-reply@${domain}>`,to:[email],subject:'Neutbo Mail 恢复邮箱验证码',text:`您的验证码是 ${code}，5分钟内有效。请勿将验证码告知他人。`});if(result.error)throw new Error('delivery rejected');}
	catch{await env.db.prepare('UPDATE account_recovery_contact_code SET consumed=1 WHERE user_id=? AND challenge=?').bind(v.userId,challenge).run();throw new BizError('验证码发送失败，请稍后重试');}
	return {challenge,maskedEmail:mask(email)};
}

export async function verifyRecoveryContactCodeForTest(c,input){
	const v=await context(c),env=c.env,challenge=input?.challenge,code=input?.code;
	if(typeof challenge!=='string'||! /^[0-9a-f-]{36}$/.test(challenge)||typeof code!=='string'||!/^\d{6}$/.test(code))throw fail();
	const row=await env.db.prepare(`UPDATE account_recovery_contact_code SET attempts=attempts+1 WHERE user_id=? AND challenge=? AND session_hash=? AND generation=?
		AND consumed=0 AND expires_at>unixepoch() AND attempts<5 RETURNING email,code_hash`).bind(v.userId,challenge,v.sessionHash,v.generation).first();
	if(!row)throw fail();
	const digest=await mac(env.jwt_secret,JSON.stringify(['recovery-contact-v1',v.userId,row.email,v.generation,v.sessionHash,challenge,code]));
	if(!crypto.subtle.timingSafeEqual(enc.encode(digest),enc.encode(row.code_hash)))throw fail();
	return withAccountLock(env.db,v.userId,async()=>{
		const results=await env.db.batch([
			env.db.prepare(`UPDATE account_recovery_contact_code SET consumed=1 WHERE user_id=? AND challenge=? AND code_hash=? AND session_hash=? AND generation=?
				AND consumed=0 AND expires_at>unixepoch() AND attempts<=5 AND EXISTS (SELECT 1 FROM user u WHERE u.user_id=? AND u.is_del=0 AND u.status=0
				AND COALESCE((SELECT generation FROM account_session_generation WHERE user_id=u.user_id),0)=?)`).bind(v.userId,challenge,digest,v.sessionHash,v.generation,v.userId,v.generation),
			env.db.prepare(`INSERT INTO account_recovery_contact(user_id,email,version,verified_at) SELECT ?,?,1,unixepoch() WHERE changes()=1
				ON CONFLICT(user_id) DO UPDATE SET email=excluded.email,version=account_recovery_contact.version+1,verified_at=excluded.verified_at`).bind(v.userId,row.email),
		]);
		if(!results.every(x=>x.meta.changes===1))throw fail();
		return {configured:true,maskedEmail:mask(row.email)};
	});
}
