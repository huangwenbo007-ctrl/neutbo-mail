// Objects can remain in storage after their last reference is removed.
export async function hasAttachmentReference(env, key) {
	const row = await env.db.prepare('SELECT 1 AS present FROM attachments WHERE key = ? LIMIT 1').bind(key).first();
	return Boolean(row);
}
