import app from '../hono/hono';
import userService from '../service/user-service';
import result from '../model/result';
import userContext from '../security/user-context';
import BizError from '../error/biz-error';
import { requestPasswordDeletion, changePasswordWithReauth } from '../service/account-reauth-draft';

app.get('/my/loginUserInfo', async (c) => {
	const user = await userService.loginUserInfo(c, userContext.getUserId(c));
	return c.json(result.ok(user));
});

app.put('/my/resetPassword', async (c) => {
	const body = await c.req.json();
	const ok = await changePasswordWithReauth(c.env.db, userContext.getUserId(c),
		body?.oldPassword, body?.password, Math.floor(Date.now() / 1000));
	if (!ok) throw new BizError('无法修改密码，请检查当前密码或稍后重试');
	return c.json(result.ok());
});

app.delete('/my/delete', async (c) => {
	await userService.delete(c, userContext.getUserId(c));
	return c.json(result.ok());
});

// Isolated integration testing only; never enable in production until the
// scheduler, recovery, storage coordination and OAuth flows are complete.
app.post('/my/delete/request', async (c) => {
	if (c.env.account_deletion_test_only !== 'enabled') throw new BizError('账号删除功能暂不可用');
	const body = await c.req.json();
	if (!body || body.confirmation !== 'DELETE' || typeof body.password !== 'string') {
		throw new BizError('请确认删除申请并输入密码');
	}
	const now = Math.floor(Date.now() / 1000);
	const ok = await requestPasswordDeletion(c.env.db, userContext.getUserId(c), body.password, now, c.env.admin);
	if (!ok) throw new BizError('无法提交申请，请检查密码或稍后再试');
	return c.json(result.ok({ recoverUntil: now + 2592000 }));
});


