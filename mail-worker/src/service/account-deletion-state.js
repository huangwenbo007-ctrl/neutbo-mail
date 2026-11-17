// Draft lifecycle primitives; not connected to any endpoint or scheduler.
// Callers must authenticate and authorize the user before calling.
const GRACE_SECONDS = 30 * 24 * 60 * 60;

export async function requestDeletion(db, userId, now, protectedAdminEmail) {
	if (typeof protectedAdminEmail !== 'string' || !protectedAdminEmail.trim()) {
		throw new Error('Administrator identity is required');
	}
	return withAccountLock(db, userId, async () => {
		const result = await db.batch([
			db.prepare('UPDATE user SET is_del = 1 WHERE user_id = ? AND is_del = 0 AND email COLLATE NOCASE != ?')
				.bind(userId, protectedAdminEmail.trim()),
			db.prepare(`INSERT INTO account_deletion_request (user_id, requested_at, purge_after, state)
				SELECT ?, ?, ?, 'pending' WHERE changes() = 1`).bind(userId, now, now + GRACE_SECONDS),
			db.prepare(`INSERT INTO account_session_generation (user_id, generation)
				SELECT ?, 1 WHERE changes() = 1
				ON CONFLICT(user_id) DO UPDATE SET generation = generation + 1`).bind(userId),
		]);
		return result.every(item => item.meta.changes === 1);
	});
}

// Read status and generation together at token issuance and on protected calls.
// A null result means the account must not receive or use a session.
export async function readActiveSessionGeneration(db, userId) {
	const row = await db.prepare(`SELECT COALESCE(g.generation, 0) AS generation FROM user u
		LEFT JOIN account_session_generation g ON g.user_id = u.user_id
		WHERE u.user_id = ? AND u.is_del = 0 AND u.status = 0`).bind(userId).first();
	return row ? row.generation : null;
}

export async function restoreDeletion(db, userId, now) {
	return withAccountLock(db, userId, async () => {
		const result = await db.batch([
			db.prepare(`UPDATE user SET is_del = 0 WHERE user_id = ? AND is_del = 1 AND EXISTS
				(SELECT 1 FROM account_deletion_request WHERE user_id = ? AND state = 'pending' AND purge_after > ?)`)
				.bind(userId, userId, now),
			db.prepare('DELETE FROM account_deletion_request WHERE user_id = ? AND state = \'pending\' AND changes() = 1')
				.bind(userId),
		]);
		return result.every(item => item.meta.changes === 1);
	});
}

export async function claimDeletion(db, userId, now) {
	return withAccountLock(db, userId, async () => {
		const row = await db.prepare(`UPDATE account_deletion_request SET state = 'purging'
			WHERE user_id = ? AND state = 'pending' AND purge_after <= ? RETURNING user_id`).bind(userId, now).first();
		return Boolean(row);
	});
}

// Draft only: queue file keys before removing their metadata. A separate,
// coordinated object cleaner is required; this function never deletes files.
export async function stagePurge(db, userId) {
	return withAccountLock(db, userId, async () => {
		// Fail closed if legacy code has reactivated the user. A missing user is
		// allowed so retries remain harmless after metadata was already staged.
		const stillPurging = "EXISTS (SELECT 1 FROM account_deletion_request WHERE user_id = ? AND state = 'purging') AND NOT EXISTS (SELECT 1 FROM user WHERE user_id = ? AND is_del IS NOT 1)";
		await db.batch([
			db.prepare(`INSERT OR IGNORE INTO account_deletion_object_queue (user_id, storage_type, object_key)
				SELECT DISTINCT ?, CASE WHEN origin.state='known' THEN origin.storage_type ELSE 'UNRESOLVED' END, a.key
				FROM attachments a LEFT JOIN attachment_object_origin origin ON origin.object_key=a.key
				WHERE a.user_id = ? AND ${stillPurging}`)
				.bind(userId, userId, userId, userId),
			db.prepare(`INSERT OR IGNORE INTO account_deletion_object_queue (user_id, storage_type, object_key)
				SELECT DISTINCT ?, 'UNRESOLVED', f.object_key FROM inbound_attachment_failure f
				JOIN email e ON e.email_id = f.email_id WHERE e.user_id = ? AND ${stillPurging}`)
				.bind(userId, userId, userId, userId),
			db.prepare(`DELETE FROM inbound_attachment_failure WHERE email_id IN
				(SELECT email_id FROM email WHERE user_id = ?) AND ${stillPurging}`).bind(userId, userId, userId),
			// These objects may be used by other users. Preserve them while
			// removing their reference to the deleted creator.
			db.prepare(`UPDATE role SET user_id = NULL WHERE user_id = ? AND ${stillPurging}`).bind(userId, userId, userId),
			db.prepare(`UPDATE reg_key SET user_id = 0 WHERE user_id = ? AND ${stillPurging}`).bind(userId, userId, userId),
			db.prepare(`DELETE FROM google_verified_contact WHERE oauth_id IN (SELECT oauth_id FROM oauth WHERE user_id=?) AND ${stillPurging}`).bind(userId,userId,userId),
			...['star', 'attachments', 'email', 'account', 'oauth', 'google_deletion_challenge', 'google_email_deletion_code', 'google_email_deletion_rate', 'account_reauth_rate', 'user'].map(table =>
				db.prepare(`DELETE FROM ${table} WHERE user_id = ? AND ${stillPurging}`).bind(userId, userId, userId)),
		]);
	});
}

// Draft primitive. All object writers and the eventual cleaner must use this
// same reservation protocol before any physical object can safely be removed.
export async function acquireObjectLock(db, storageType, key, owner, now) {
	if (!['KV', 'R2', 'S3'].includes(storageType) || !key || !owner) throw new Error('Invalid object reservation');
	const result = await db.prepare(`INSERT OR IGNORE INTO attachment_object_lock
		(storage_type, object_key, owner_token, created_at) VALUES (?, ?, ?, ?)`).bind(storageType, key, owner, now).run();
	return result.meta.changes === 1;
}

export async function releaseObjectLock(db, storageType, key, owner) {
	const result = await db.prepare(`DELETE FROM attachment_object_lock
		WHERE storage_type = ? AND object_key = ? AND owner_token = ?`).bind(storageType, key, owner).run();
	return result.meta.changes === 1;
}

// Prototype: reserve all unique keys in a deterministic order before a writer
// starts. Contention fails closed and acquired locks are released on failure.
export async function withObjectLocks(db, storageType, keys, owner, now, operation, options = {}) {
	const uniqueKeys = [...new Set(keys)].sort();
	const acquired = [];
	let retries = options.retries ?? 0;
	const delayMs = options.delayMs ?? 0;
	if (!Number.isSafeInteger(retries) || retries < 0 || retries > 4 ||
		!Number.isSafeInteger(delayMs) || delayMs < 0 || delayMs > 100) throw new Error('Invalid reservation retry policy');
	try {
		for (const key of uniqueKeys) {
			while (!await acquireObjectLock(db, storageType, key, owner, now)) {
				if (retries-- <= 0) throw new Error('Attachment temporarily busy');
				await new Promise(resolve => setTimeout(resolve, delayMs));
			}
			acquired.push(key);
		}
		return await operation();
	} finally {
		let releaseError;
		for (const key of acquired.reverse()) {
			try {
				if (!await releaseObjectLock(db, storageType, key, owner)) throw new Error('Attachment reservation lost');
			} catch (error) {
				releaseError ||= error;
			}
		}
		if (releaseError) throw releaseError;
	}
}

// Use a reserved namespace that cannot collide with attachment object keys.
// This lock is only effective when every account-data writer also uses it.
export async function withAccountLock(db, userId, operation, options) {
	return withAccountLocks(db, [userId], operation, options);
}

export async function withAccountLocks(db, userIds, operation, options) {
	const ids = userIds.map(Number);
	if (!ids.length || ids.some(id => !Number.isSafeInteger(id) || id <= 0)) throw new Error('Invalid account identifier');
	return withObjectLocks(db, 'KV', ids.map(id => `internal/account/${id}`), crypto.randomUUID(), Math.floor(Date.now() / 1000), operation, options);
}

// Prototype only. Call while holding the object reservation, after a trusted
// writer confirms the actual storage identity. Never infer an origin from the
// current setting or from a client-supplied value. Test-only KV wiring exists;
// other writers and storage identities still require integration and review.
export async function recordConfirmedObjectOrigin(db, key, storageType, storeId, owner) {
	if (typeof key !== 'string' || !key.startsWith('attachments/') ||
		!['KV', 'R2', 'S3'].includes(storageType) || typeof storeId !== 'string' || !storeId.trim() ||
		typeof owner !== 'string' || !owner) {
		throw new Error('Invalid confirmed object origin');
	}
	const row = await db.prepare(`INSERT INTO attachment_object_origin(object_key,storage_type,store_id,state)
		SELECT ?,?,?,CASE WHEN NOT EXISTS (SELECT 1 FROM attachment_object_origin WHERE object_key=?) AND
			(EXISTS (SELECT 1 FROM attachments WHERE key=?) OR EXISTS (SELECT 1 FROM account_deletion_object_queue
				WHERE object_key=? AND storage_type='UNRESOLVED')) THEN 'ambiguous' ELSE 'known' END
		WHERE EXISTS (SELECT 1 FROM attachment_object_lock WHERE object_key=? AND owner_token=? AND storage_type=?)
		ON CONFLICT(object_key) DO UPDATE SET state=CASE
			WHEN attachment_object_origin.state='known' AND attachment_object_origin.storage_type=excluded.storage_type
			AND attachment_object_origin.store_id=excluded.store_id THEN 'known' ELSE 'ambiguous' END RETURNING state`)
		.bind(key,storageType,storeId,key,key,key,key,owner,storageType).first();
	if (!row) throw new Error('Object reservation required');
	return row.state;
}

// Prototype only: do not connect this to a scheduler until *every* attachment
// writer uses the same lock and records the actual storage identity.
export async function processQueuedObject(db, item, owner, now, deleteObject, verifiedTarget) {
	const { userId, storageType, key } = item;
	if (typeof key !== 'string' || !key.startsWith('attachments/') || typeof deleteObject !== 'function') {
		throw new Error('Invalid attachment cleanup request');
	}
	if (!await acquireObjectLock(db, storageType, key, owner, now)) return 'busy';
	try {
		const queued = await db.prepare(`SELECT 1 AS present FROM account_deletion_object_queue
			WHERE user_id = ? AND storage_type = ? AND object_key = ?`).bind(userId, storageType, key).first();
		if (!queued) return 'not-queued';
		const refs = await db.prepare('SELECT count(*) AS n FROM attachments WHERE key = ?').bind(key).first();
		// Keep shared entries queued, so a later removal of the final reference
		// can be retried even if it came from a different deletion path.
		if (refs.n > 0) return 'shared';
		const origin = await db.prepare('SELECT storage_type,store_id,state FROM attachment_object_origin WHERE object_key=?').bind(key).first();
		if (!origin || origin.state !== 'known' || origin.storage_type !== storageType ||
			!verifiedTarget || verifiedTarget.storageType !== storageType || verifiedTarget.storeId !== origin.store_id) return 'unresolved';
		await deleteObject(storageType, key, origin.store_id);
		await db.prepare('DELETE FROM account_deletion_object_queue WHERE user_id = ? AND storage_type = ? AND object_key = ?')
			.bind(userId, storageType, key).run();
		return 'deleted';
	} finally {
		await releaseObjectLock(db, storageType, key, owner);
	}
}
