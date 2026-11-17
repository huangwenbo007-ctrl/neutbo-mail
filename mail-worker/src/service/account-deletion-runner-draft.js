import { claimDeletion, stagePurge } from './account-deletion-state';

// Isolated test helper only. Not wired to a cron or API, and it never removes
// objects. In particular, unresolved or shared attachment keys remain queued.
export async function stageDueDeletionsForTest(env, now, limit = 10, afterUserId = 0) {
	if (env.account_deletion_test_only !== 'enabled') throw new Error('Deletion runner is restricted to isolated tests');
	if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 10 ||
		!Number.isSafeInteger(afterUserId) || afterUserId < 0) {
		throw new Error('Invalid deletion batch');
	}
	const rows = await env.db.prepare(`SELECT user_id, state FROM account_deletion_request
		WHERE user_id > ? AND ((state='pending' AND purge_after<=?) OR state='purging')
		ORDER BY user_id LIMIT ?`).bind(afterUserId, now, limit).all();
	// A caller walks every page before restarting at zero. Already-staged or
	// blocked requests cannot permanently starve later accounts in this pass.
	const result = { staged: 0, skipped: 0, failed: 0, nextCursor: rows.results.length === limit ? rows.results.at(-1).user_id : null };
	for (const row of rows.results) {
		try {
			if (row.state === 'pending' && !await claimDeletion(env.db, row.user_id, now)) {
				result.skipped++;
				continue;
			}
			await stagePurge(env.db, row.user_id);
			const user = await env.db.prepare('SELECT 1 AS present FROM user WHERE user_id=?').bind(row.user_id).first();
			if (user) result.skipped++; // Reactivated accounts fail closed.
			else result.staged++;
		} catch {
			// Preserve the request for a later attempt; do not hide partial failure.
			result.failed++;
		}
	}
	return result;
}
