import app from '../hono/hono';
import userService from '../service/user-service';
import result from '../model/result';
import userContext from '../security/user-context';
import BizError from '../error/biz-error';

app.get('/my/loginUserInfo', async (c) => {
	const user = await userService.loginUserInfo(c, userContext.getUserId(c));
	return c.json(result.ok(user));
});

app.put('/my/resetPassword', async (c) => {
	// A session alone is not proof of identity for a sensitive credential change.
	// Re-enable only with a verified flow for both password and OAuth accounts.
	throw new BizError('修改密码功能暂不可用，请联系 support@neutbo.com');
});

app.delete('/my/delete', async (c) => {
	await userService.delete(c, userContext.getUserId(c));
	return c.json(result.ok());
});


