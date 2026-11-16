// Prototype only: not an authorization token and not wired to any endpoint.
// Google identities need a separate, fresh OAuth reauthentication flow.
import cryptoUtils from '../utils/crypto-utils';

export async function checkPasswordReauth(db, userId, password, now) {
	if (!Number.isSafeInteger(userId) || userId <= 0 || !Number.isSafeInteger(now) || now < 0 ||
		typeof password !== 'string' || password.length < 1 || password.length > 128) return false;
	// One D1 statement reserves each attempt, including successful attempts.
	// Do not reset on success: concurrent attempts cannot extend the allowance.
	const attempt = await db.prepare(`INSERT INTO account_reauth_rate (user_id, window_start, attempts)
		VALUES (?, ?, 1) ON CONFLICT(user_id) DO UPDATE SET
		window_start = CASE WHEN window_start <= ? THEN excluded.window_start ELSE window_start END,
		attempts = CASE WHEN window_start <= ? THEN 1 ELSE attempts + 1 END
		WHERE window_start <= ? OR attempts < 5 RETURNING attempts`)
		.bind(userId, now, now - 900, now - 900, now - 900).first();
	if (!attempt) return false;
	const user = await db.prepare('SELECT salt, password FROM user WHERE user_id = ? AND is_del = 0 AND status = 0')
		.bind(userId).first();
	if (!user || typeof user.salt !== 'string' || typeof user.password !== 'string') return false;
	return cryptoUtils.verifyPassword(password, user.salt, user.password);
}
