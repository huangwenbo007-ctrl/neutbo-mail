import r2Service from '../service/r2-service';
import app from '../hono/hono';
import { hasAttachmentReference } from '../service/attachment-access';

app.get('/oss/*', async (c) => {
	const key = c.req.path.split('/oss/')[1];
	if (key.startsWith('attachments/') && !await hasAttachmentReference(c.env, key)) {
		return c.notFound();
	}
	const resp = await r2Service.toObjResp(c, key);
	if (!resp) {
		return c.notFound();
	}
	return resp;
});


