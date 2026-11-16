// Isolated tests only. Never call from a scheduler or production endpoint.
import { processQueuedObject } from './account-deletion-state';

export async function processTestKvAttachment(c, item, owner, now) {
	const storeId = c.env.attachment_kv_store_id;
	const kv = c.env.kv;
	if (c.env.attachment_origin_test_only !== 'enabled' ||
		typeof storeId !== 'string' || !/^kv:[a-f0-9]{32}$/.test(storeId) || !kv || item.storageType !== 'KV') {
		throw new Error('Isolated KV cleanup is not configured');
	}
	// The binding and declared namespace ID are captured together. Deployment
	// must independently verify the declaration against the actual binding.
	const target = {storageType:'KV',storeId};
	return processQueuedObject(c.env.db,item,owner,now,async (type,key,originId) => {
		if (type !== 'KV' || originId !== storeId) throw new Error('Attachment store mismatch');
		await kv.delete(key);
	},target);
}
