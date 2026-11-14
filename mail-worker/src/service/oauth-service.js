import BizError from "../error/biz-error";
import orm from "../entity/orm";
import {oauth} from "../entity/oauth";
import { and, eq, inArray } from 'drizzle-orm';
import userService from "./user-service";
import loginService from "./login-service";
import settingService from "./setting-service";
import {t} from '../i18n/i18n';
import {sign, verify} from 'hono/jwt';

const oauthService = {

	async bindUser(c, params) {

		const { email, code, token, externalEmail, emailChallenge, emailVerificationCode, bindToken } = params;
		let proof;
		try {
			if (typeof bindToken !== 'string' || !c.env.jwt_secret) throw new Error('missing binding proof');
			proof = await verify(bindToken, c.env.jwt_secret + ':oauth-registration:v1', 'HS256');
			if (proof.purpose !== 'oauth-registration' || !Number.isSafeInteger(proof.oauthId) || !proof.exp || !['google', 'github', 'linuxdo'].includes(proof.platform)) throw new Error('invalid binding proof');
		} catch {
			throw new BizError('第三方登录已失效，请重新登录');
		}
		this.assertEnabled(await settingService.query(c), proof.platform + 'Switch');
		// Reserve this identity atomically so concurrent requests cannot attach it to two accounts.
		const reserved = await c.env.db.prepare('UPDATE oauth SET user_id = -1 WHERE oauth_id = ? AND platform = ? AND user_id = 0 RETURNING oauth_id')
			.bind(proof.oauthId, proof.platform).first();
		if (!reserved) throw new BizError('第三方账号已绑定或正在处理中');
		let registered = false;
		let existingBefore = null;
		try {
			existingBefore = typeof email === 'string' ? await userService.selectByEmailIncludeDel(c, email) : null;
			const randomPassword = crypto.randomUUID().replace(/-/g, '').slice(0, 24);
			await loginService.register(c, { email, password: randomPassword, code, token, externalEmail, emailChallenge, emailVerificationCode });
			registered = true;
			const userRow = await userService.selectByEmail(c, email);
			if (!userRow) throw new BizError('邮箱创建后无法完成绑定，请联系管理员');
			const linked = await c.env.db.prepare('UPDATE oauth SET user_id = ? WHERE oauth_id = ? AND user_id = -1 RETURNING oauth_id')
				.bind(userRow.userId, proof.oauthId).first();
			if (!linked) throw new BizError('邮箱创建后无法完成绑定，请联系管理员');
			const jwtToken = await loginService.login(c, { email, password: null }, true);
			return { token: jwtToken };
		} catch (error) {
			// Never release a reservation after account creation: retrying could create another account.
			const existingAfter = typeof email === 'string' ? await userService.selectByEmailIncludeDel(c, email) : null;
			if (!registered && (existingBefore || !existingAfter)) await c.env.db.prepare('UPDATE oauth SET user_id = 0 WHERE oauth_id = ? AND user_id = -1').bind(proof.oauthId).run();
			throw error;
		}
	},

	async linuxDoLogin(c, params) {

		const { code, redirectUri } = params;

		const setting = await settingService.query(c);
		this.assertEnabled(setting, 'linuxdoSwitch');

		const reqParams = new URLSearchParams()
		reqParams.append('client_id', setting.linuxdoClientId)
		reqParams.append('client_secret', setting.linuxdoClientSecret)
		reqParams.append('code', code)
		reqParams.append('redirect_uri', redirectUri)
		reqParams.append('grant_type', 'authorization_code')

		const tokenRes = await fetch("https://connect.linux.do/oauth2/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: reqParams.toString()
		})

		if (!tokenRes.ok) {
			throw new BizError(tokenRes.statusText)
		}

		const token = await tokenRes.json()

		const userRes = await fetch('https://connect.linux.do/api/user', {
			headers: {
				Authorization: 'Bearer ' + token.access_token
			}
		});

		if (!userRes.ok) {
			throw new BizError(userRes.statusText)
		}

		const userInfo = await userRes.json();

		userInfo.oauthUserId = String(userInfo.id);
		userInfo.active = userInfo.active ? 0 : 1;
		userInfo.silenced = userInfo.silenced ? 0 : 1;
		userInfo.trustLevel = userInfo.trust_level;
		userInfo.avatar = userInfo.avatar_url;
		userInfo.platform = 'linuxdo';

		return await this.saveAndLogin(c, userInfo)
	},

	async githubLogin(c, params) {

		const { code, redirectUri } = params;

		const setting = await settingService.query(c);
		this.assertEnabled(setting, 'githubSwitch');

		const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Accept": "application/json"
			},
			body: JSON.stringify({
				client_id: setting.githubClientId,
				client_secret: setting.githubClientSecret,
				code: code,
				redirect_uri: redirectUri
			})
		});

		if (!tokenRes.ok) {
			throw new BizError(tokenRes.statusText);
		}

		const token = await tokenRes.json();

		if (token.error) {
			throw new BizError(token.error_description || token.error);
		}

		const userRes = await fetch('https://api.github.com/user', {
			headers: {
				Authorization: 'Bearer ' + token.access_token,
				'User-Agent': 'cloud-mail'
			}
		});

		if (!userRes.ok) {
			throw new BizError(userRes.statusText);
		}

		const userInfo = await userRes.json();

		userInfo.oauthUserId = String(userInfo.id);
		userInfo.username = userInfo.login;
		userInfo.avatar = userInfo.avatar_url;
		userInfo.platform = 'github';

		return await this.saveAndLogin(c, userInfo);
	},

	async googleLogin(c, params) {

		const { code, redirectUri, codeVerifier } = params;
		if (typeof codeVerifier !== 'string' || !/^[0-9a-f]{64}$/.test(codeVerifier)) throw new BizError('登录请求已失效，请重新登录');

		const setting = await settingService.query(c);
		this.assertEnabled(setting, 'googleSwitch');

		const reqParams = new URLSearchParams()
		reqParams.append('client_id', setting.googleClientId)
		reqParams.append('client_secret', setting.googleClientSecret)
		reqParams.append('code', code)
		reqParams.append('redirect_uri', redirectUri)
		reqParams.append('grant_type', 'authorization_code')
		reqParams.append('code_verifier', codeVerifier)

		const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: reqParams.toString()
		});

		if (!tokenRes.ok) {
			throw new BizError(tokenRes.statusText);
		}

		const token = await tokenRes.json();

		const userRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
			headers: {
				Authorization: 'Bearer ' + token.access_token
			}
		});

		if (!userRes.ok) {
			throw new BizError(userRes.statusText);
		}

		const userInfo = await userRes.json();

		if (typeof userInfo.sub !== 'string' || !userInfo.sub) throw new BizError('无法确认 Google 账号身份');
		userInfo.oauthUserId = String(userInfo.sub);
		userInfo.username = userInfo.email;
		userInfo.name = userInfo.name;
		userInfo.avatar = userInfo.picture;
		userInfo.platform = 'google';

		return await this.saveAndLogin(c, userInfo);
	},

	async saveAndLogin(c, userInfo) {

		const oauthRow = await this.saveUser(c, userInfo);
		if (oauthRow.userId === -1) throw new BizError('第三方账号正在处理中，请稍后重试');
		const userRow = await userService.selectByIdIncludeDel(c, oauthRow.userId);

		if (!userRow) {
			if (oauthRow.userId !== 0 || !c.env.jwt_secret) throw new BizError('第三方账号状态异常');
			const bindToken = await sign({ purpose: 'oauth-registration', oauthId: oauthRow.oauthId, platform: oauthRow.platform, exp: Math.floor(Date.now() / 1000) + 600 }, c.env.jwt_secret + ':oauth-registration:v1', 'HS256');
			return { userInfo: oauthRow, token: null, bindToken };
		}

		const JwtToken = await loginService.login(c, { email: userRow.email, password: null }, true);
		return { userInfo: oauthRow, token: JwtToken };
	},

	async saveUser(c, userInfo) {
		const { oauthUserId, platform } = userInfo;
		const profile = { username: userInfo.username || '', name: userInfo.name || '', avatar: userInfo.avatar || '',
			active: userInfo.active ?? null, trustLevel: userInfo.trustLevel ?? null, silenced: userInfo.silenced ?? null };
		// One SQL statement prevents simultaneous first logins from creating duplicate identities.
		await c.env.db.prepare(`INSERT INTO oauth (oauth_user_id, platform, username, name, avatar, active, trust_level, silenced)
			SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM oauth WHERE oauth_user_id = ? AND platform = ?)`)
			.bind(oauthUserId, platform, profile.username, profile.name, profile.avatar, profile.active, profile.trustLevel, profile.silenced, oauthUserId, platform).run();
		const rows = await orm(c).select().from(oauth).where(and(eq(oauth.oauthUserId, oauthUserId), eq(oauth.platform, platform))).all();
		if (rows.length !== 1) throw new BizError('第三方账号状态异常，请联系管理员');
		return await orm(c).update(oauth).set(profile).where(eq(oauth.oauthId, rows[0].oauthId)).returning().get();

	},

	assertEnabled(setting, switchKey) {
		if (setting[switchKey] !== 0) {
			throw new BizError(t('oauthDisabled'));
		}
	},

	async deleteByUserId(c, userId) {
		await this.deleteByUserIds(c, [userId]);
	},

	async deleteByUserIds(c, userIds) {
		await orm(c).delete(oauth).where(inArray(oauth.userId, userIds)).run();
	},

	//定时任务凌晨清除未绑定邮箱的oauth用户
	async clearNoBindOathUser(c) {
		await orm(c).delete(oauth).where(eq(oauth.userId, 0)).run();
	},

}

export default  oauthService
