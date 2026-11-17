// Test-only coordinator. Its opt-in cron hook is disabled by default.
// Storage deletion is safe only when every writer obeys the same lock protocol
// and the binding's real identity has been independently verified.
import { claimDeletion, stagePurge } from './account-deletion-state';
import { processTestKvAttachment } from './attachment-cleanup-draft';

function requireIsolated(env) {
	if (env.account_deletion_test_only !== 'enabled' || env.attachment_origin_test_only !== 'enabled') {
		throw new Error('Cleanup coordinator is restricted to isolated tests');
	}
}

function retryDelay(attempts) {
	return Math.min(86400, 60 * 2 ** Math.min(attempts, 10));
}

// Bounded batches allow another invocation to continue after interruption. The
// database clock, not a supplied scheduled event time, enforces the grace period.
export async function runIsolatedCleanupBatch(env, limit = 10) {
	requireIsolated(env);
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > 25) throw new Error('Invalid cleanup batch');
	const db = env.db;
	const clock = await db.prepare('SELECT unixepoch() AS now').bind().first();
	const now = clock.now;
	const accounts = await db.prepare(`SELECT r.user_id,r.state,COALESCE(j.attempts,0) AS attempts FROM account_deletion_request r
		LEFT JOIN account_deletion_cleanup_job j ON j.user_id=r.user_id
		WHERE r.purge_after<=unixepoch() AND r.state IN ('pending','purging')
		AND (j.user_id IS NULL OR (j.state='retry' AND j.next_attempt_at<=unixepoch()))
		ORDER BY COALESCE(j.next_attempt_at,0),r.user_id LIMIT ?`).bind(limit).all();
	const result = {staged:0, accountRetry:0, blocked:0, deleted:0, shared:0, unresolved:0, objectRetry:0};
	for (const account of accounts.results) {
		try {
			if (account.state === 'pending' && !await claimDeletion(db, account.user_id, now)) continue;
			await stagePurge(db, account.user_id);
			const remaining = await db.prepare('SELECT 1 AS present FROM user WHERE user_id=?').bind(account.user_id).first();
			const state = remaining ? 'blocked' : 'staged';
			await db.prepare(`INSERT INTO account_deletion_cleanup_job VALUES (?,?,1,?,0,?)
				ON CONFLICT(user_id) DO UPDATE SET state=excluded.state,attempts=attempts+1,
				last_attempt_at=excluded.last_attempt_at,next_attempt_at=0,reason=excluded.reason`)
				.bind(account.user_id,state,now,remaining ? 'account_active' : 'metadata_staged').run();
			result[remaining ? 'blocked' : 'staged']++;
		} catch {
			// Never store exception strings, email addresses or secrets in status.
			await db.prepare(`INSERT INTO account_deletion_cleanup_job VALUES (?,'retry',1,?,?, 'stage_failed')
				ON CONFLICT(user_id) DO UPDATE SET attempts=attempts+1,last_attempt_at=excluded.last_attempt_at,
				next_attempt_at=excluded.next_attempt_at,reason='stage_failed'
				WHERE state='retry'`).bind(account.user_id,now,now+retryDelay(account.attempts+1)).run();
			result.accountRetry++;
		}
	}

	const objects = await db.prepare(`SELECT q.user_id,q.storage_type,q.object_key,COALESCE(s.attempts,0) AS attempts
		FROM account_deletion_object_queue q LEFT JOIN account_deletion_cleanup_object_status s
		ON s.user_id=q.user_id AND s.storage_type=q.storage_type AND s.object_key=q.object_key
		WHERE s.user_id IS NULL OR s.next_attempt_at<=unixepoch()
		ORDER BY COALESCE(s.next_attempt_at,0),q.user_id,q.storage_type,q.object_key LIMIT ?`).bind(limit).all();
	for (const object of objects.results) {
		const item = {userId:object.user_id,storageType:object.storage_type,key:object.object_key};
		let outcome;
		try {
			outcome = object.storage_type === 'KV' ? await processTestKvAttachment({env},item,crypto.randomUUID(),now) : 'unresolved';
		} catch {
			outcome = 'storage_error';
		}
		if (outcome === 'deleted' || outcome === 'not-queued') {
			await db.prepare('DELETE FROM account_deletion_cleanup_object_status WHERE user_id=? AND storage_type=? AND object_key=?')
				.bind(item.userId,item.storageType,item.key).run();
			if (outcome === 'deleted') result.deleted++;
			continue;
		}
		const state = outcome === 'shared' || outcome === 'unresolved' ? outcome : 'retry';
		const reason = ['shared','unresolved','busy','storage_error'].includes(outcome) ? outcome : 'retry';
		const delay = state === 'shared' ? 3600 : state === 'unresolved' ? 86400 : retryDelay(object.attempts+1);
		// A concurrent cleaner may have removed this queue row while we waited.
		await db.prepare(`INSERT INTO account_deletion_cleanup_object_status
			(user_id,storage_type,object_key,state,attempts,last_attempt_at,next_attempt_at,reason)
			SELECT ?,?,?,?,1,?,?,? WHERE EXISTS (SELECT 1 FROM account_deletion_object_queue
			WHERE user_id=? AND storage_type=? AND object_key=?)
			ON CONFLICT(user_id,storage_type,object_key) DO UPDATE SET state=excluded.state,
			attempts=attempts+1,last_attempt_at=excluded.last_attempt_at,next_attempt_at=excluded.next_attempt_at,reason=excluded.reason`)
			.bind(item.userId,item.storageType,item.key,state,now,now+delay,reason,item.userId,item.storageType,item.key).run();
		result[state === 'retry' ? 'objectRetry' : state]++;
	}
	return result;
}

// Aggregate diagnostics for a trusted operator, without object keys or emails.
// This helper is not exposed as a public endpoint.
export async function isolatedCleanupSummary(env) {
	requireIsolated(env);
	const jobs = await env.db.prepare('SELECT state,count(*) AS count FROM account_deletion_cleanup_job GROUP BY state').bind().all();
	const objects = await env.db.prepare(`SELECT COALESCE(s.state,'waiting') AS state,count(*) AS count
		FROM account_deletion_object_queue q LEFT JOIN account_deletion_cleanup_object_status s
		ON s.user_id=q.user_id AND s.storage_type=q.storage_type AND s.object_key=q.object_key
		GROUP BY COALESCE(s.state,'waiting')`).bind().all();
	return {jobs:jobs.results,objects:objects.results};
}

// Only an explicitly configured isolated Worker can invoke this from its cron.
// Never set this flag in production; the production safety review is incomplete.
export async function runIsolatedScheduledCleanup(env) {
	if (env.account_deletion_scheduled_test_only !== 'enabled') return null;
	return runIsolatedCleanupBatch(env);
}
