// Prototype only: not an authorization token and not wired to any endpoint.
// Google identities need a separate, fresh OAuth reauthentication flow.
import cryptoUtils from '../utils/crypto-utils';
import { withAccountLock } from './account-deletion-state';

async function verifyPassword(password, salt, storedHash) {
	const candidateHash = await cryptoUtils.genHashPassword(password, salt);
	const encoder = new TextEncoder();
	// Hash both strings to fixed-size buffers before the Workers constant-time
	// comparison. This preserves compatibility with existing password hashes.
	const [candidate, expected] = await Promise.all([
		crypto.subtle.digest('SHA-256', encoder.encode(candidateHash)),
		crypto.subtle.digest('SHA-256', encoder.encode(storedHash)),
	]);
	return crypto.subtle.timingSafeEqual(candidate, expected);
}

export async function reserveReauthAttempt(db, userId, now) {
	if (!Number.isSafeInteger(userId) || userId <= 0 || !Number.isSafeInteger(now) || now < 0) return false;
	// One D1 statement reserves each attempt, including successful attempts.
	// Do not reset on success: concurrent attempts cannot extend the allowance.
	const attempt = await db.prepare(`INSERT INTO account_reauth_rate (user_id, window_start, attempts)
		VALUES (?, ?, 1) ON CONFLICT(user_id) DO UPDATE SET
		window_start = CASE WHEN window_start <= ? THEN excluded.window_start ELSE window_start END,
		attempts = CASE WHEN window_start <= ? THEN 1 ELSE attempts + 1 END
		WHERE window_start <= ? OR attempts < 5 RETURNING attempts`)
		.bind(userId, now, now - 900, now - 900, now - 900).first();
	return Boolean(attempt);
}

async function passwordSnapshot(db, userId, password, now) {
	if (typeof password !== 'string' || password.length < 1 || password.length > 128) return null;
	if (!await reserveReauthAttempt(db, userId, now)) return null;
	const user = await db.prepare('SELECT salt, password FROM user WHERE user_id = ? AND is_del = 0 AND status = 0')
		.bind(userId).first();
	if (!user || typeof user.salt !== 'string' || typeof user.password !== 'string') return null;
	return await verifyPassword(password, user.salt, user.password) ? user : null;
}

// Internal service helper only; credential snapshots must never reach a client.
export async function passwordSnapshotForRecovery(db,userId,password,now) {
	return passwordSnapshot(db,userId,password,now);
}

export async function checkPasswordReauth(db, userId, password, now) {
	return Boolean(await passwordSnapshot(db, userId, password, now));
}

// Call only after session authentication. Existing sessions are invalidated
// in the same database transaction as the credential change.
export async function changePasswordWithReauth(db, userId, oldPassword, newPassword, now) {
	if (typeof newPassword !== 'string' || newPassword.length < 6 || newPassword.length > 30) return false;
	const snapshot = await passwordSnapshot(db, userId, oldPassword, now);
	if (!snapshot) return false;
	const next = await cryptoUtils.hashPassword(newPassword);
	return withAccountLock(db, userId, async () => {
		const result = await db.batch([
			db.prepare(`UPDATE user SET password = ?, salt = ? WHERE user_id = ?
				AND is_del = 0 AND status = 0 AND password = ? AND salt = ?`)
				.bind(next.hash, next.salt, userId, snapshot.password, snapshot.salt),
			db.prepare(`INSERT INTO account_session_generation (user_id, generation)
				SELECT ?, 1 WHERE changes() = 1 ON CONFLICT(user_id) DO UPDATE SET generation = generation + 1`).bind(userId),
		]);
		return result.every(item => item.meta.changes === 1);
	});
}

// Disconnected prototype. Authentication, identity and time must be supplied by
// trusted server code. Never expose the credential snapshot as a client proof.
export async function requestPasswordDeletion(db, userId, password, now, adminEmail, domains) {
	if (typeof adminEmail !== 'string' || !adminEmail.trim()) throw new Error('Administrator identity is required');
	if (!Array.isArray(domains) || !domains.length || domains.some(d=>typeof d!=='string'||!d.trim())) throw new Error('Mail domains are required');
	const internalDomains=domains.map(d=>d.trim().toLowerCase());
	const placeholders=internalDomains.map(()=>'?').join(',');
	const snapshot = await passwordSnapshot(db, userId, password, now);
	if (!snapshot) return false;
	return withAccountLock(db, userId, async () => {
		// Credential predicates close the race with a concurrent password reset.
		const result = await db.batch([
			db.prepare(`UPDATE user SET is_del = 1 WHERE user_id = ? AND is_del = 0 AND status = 0
				AND email COLLATE NOCASE != ? AND salt = ? AND password = ? AND (
				EXISTS (SELECT 1 FROM account_recovery_contact rc WHERE rc.user_id=user.user_id AND instr(rc.email,'@')>1
				AND lower(substr(rc.email,instr(rc.email,'@')+1)) NOT IN (${placeholders})) OR
				EXISTS (SELECT 1 FROM oauth o JOIN google_verified_contact g ON g.oauth_id=o.oauth_id AND g.subject=o.oauth_user_id
				WHERE o.user_id=user.user_id AND o.platform='google' AND instr(g.email,'@')>1
				AND lower(substr(g.email,instr(g.email,'@')+1)) NOT IN (${placeholders})))`)
				.bind(userId, adminEmail.trim(), snapshot.salt, snapshot.password,...internalDomains,...internalDomains),
			db.prepare(`INSERT INTO account_deletion_request (user_id, requested_at, purge_after, state)
				SELECT ?, ?, ?, 'pending' WHERE changes() = 1`).bind(userId, now, now + 2592000),
			db.prepare(`INSERT INTO account_session_generation (user_id, generation)
				SELECT ?, 1 WHERE changes() = 1 ON CONFLICT(user_id) DO UPDATE SET generation = generation + 1`).bind(userId),
		]);
		return result.every(item => item.meta.changes === 1);
	});
}
