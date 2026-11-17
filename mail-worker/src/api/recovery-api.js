import app from '../hono/hono';
import result from '../model/result';
import userContext from '../security/user-context';
import { sendRecoveryCodeForTest, verifyRecoveryCodeForTest, createSupportTicketForTest, supportRecoveryStatusForTest, approveRecoveryForTest } from '../service/account-recovery-email-draft';
import { recoveryContactStatusForTest,sendRecoveryContactCodeForTest,verifyRecoveryContactCodeForTest } from '../service/recovery-contact-draft';

// All functions enforce the isolated-preview flag; support actions additionally
// verify the authenticated actor against the configured administrator in D1.
app.post('/recovery/email/send', async c => c.json(result.ok(await sendRecoveryCodeForTest(c,await c.req.json()))));
app.post('/recovery/email/verify', async c => c.json(result.ok(await verifyRecoveryCodeForTest(c,await c.req.json()))));
app.get('/my/recovery-contact', async c => c.json(result.ok(await recoveryContactStatusForTest(c))));
app.post('/my/recovery-contact/send', async c => c.json(result.ok(await sendRecoveryContactCodeForTest(c,await c.req.json()))));
app.post('/my/recovery-contact/verify', async c => c.json(result.ok(await verifyRecoveryContactCodeForTest(c,await c.req.json()))));
app.post('/user/recovery/ticket', async c => {
	const body=await c.req.json();
	return c.json(result.ok(await createSupportTicketForTest(c.env,body?.userId,userContext.getUserId(c),c.get('authGeneration'))));
});
app.get('/user/recovery/status', async c => c.json(result.ok(await supportRecoveryStatusForTest(c.env,Number(c.req.query('userId')),userContext.getUserId(c),c.get('authGeneration')))));
app.post('/user/recovery/approve', async c => {
	const body=await c.req.json();
	return c.json(result.ok(await approveRecoveryForTest(c.env,body?.userId,body?.supportReference,userContext.getUserId(c),c.get('authGeneration'))));
});
