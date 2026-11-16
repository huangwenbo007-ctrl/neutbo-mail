# Account deletion: incomplete development draft

Do not deploy this branch. The deletion endpoint and scheduler are deliberately not connected.

## Agreed product behavior

- Disable a user's account when deletion is requested; keep it recoverable for 30 days.
- During the grace period, the owner requests recovery through support@neutbo.com; an administrator must verify identity before restoring it.
- After the grace period, begin deleting account data and attachments. Backups, provider logs, and shared objects need separately documented retention and deletion behavior.

## Implemented in this draft

- D1 state transitions mark a user deleted, record the deadline, increment the session generation, allow an atomic pre-deadline restoration, and claim an expired request for purge.
- Login and protected API requests read the account status and generation from D1. Old tokens become invalid even after a restoration; tokens issued before this migration are treated as generation zero.
- Administrator restoration is guarded against expiry and concurrent purge; new incoming mail is rejected for deleted accounts.
- The prototype coordinates deletion transitions with inbound and on-site recipient writes using a per-account reservation, and rechecks the recipient before saving. Isolated Workers tests cover normal delivery, deleted recipients and lock contention. This does not cover every writer or older deployed workers, and lock contention currently raises an error whose SMTP retry behavior has not been verified.
- The legacy administrator user-deletion path acquires the same account reservation and refuses accounts with deletion requests, preserving their recovery period. Other legacy deletion paths remain to be audited.
- The legacy self-delete path is temporarily disabled in this draft, because its existing settings can trigger immediate permanent deletion. Replace it with a reauthenticated grace-period request only when the complete flow is ready.
- A disconnected password-check prototype reserves at most five attempts per account per 15 minutes in D1, including successful attempts. It is not an authorization proof and is not connected to deletion or password changes. Test-only clock injection must never be exposed to clients.
- A draft purge staging operation queues attachment keys and deletes only the selected user's metadata in one transaction. It never deletes the underlying objects.
- Staging refuses to remove metadata when the user has been reactivated, even if a stale request says it is being purged. Isolated SQLite and Workers/D1 tests cover this, a harmless retry after staging, and preservation of another user's account.
- Staging clears the deleted creator's references in shared roles and invitation codes while retaining those records. Isolated tests cover preservation and other users' references; operational and privacy review is still required.
- Draft per-object reservations and queue processing have isolated SQLite tests for shared references, failed deletion, retry and lock contention. Incoming, outgoing, inline and on-site-copy draft paths use the reservation. Targeted Workers tests cover incoming/outgoing contention and stale on-site references; the scheduler remains disconnected and this does not yet protect actual attachments.

## Release blockers

- Design and implement recent reauthentication and confirmation for both password and Google accounts, and protect the administrator account. Wire the authenticated request and support-guided restore flow.
- Registration verifies an external email but does not persist a verified recovery address linked to the account; it cannot currently be used for recovery or deletion confirmation. Define a safe enrollment and change process before relying on it.
- The password-check prototype needs an independently reviewable design for brute-force and account-lockout abuse, proof binding, expiry, single use, password-change races, token revocation, and cryptographic comparison before use. Google reauthentication needs separate validation.
- The draft temporarily blocks self-service password changes because the previous endpoint accepted an active session without further identity proof. Implement and test a replacement for both password and Google users, session revocation, rate limits, and recovery before release. Administrator password reset is a separate path and needs its own audit.
- Complete scheduler integration, durable retry, operational monitoring and idempotent cleanup for requests stuck in `purging`.
- Existing attachment keys are content hashes, shared by different users and reused by multiple writer paths. A reference-count check alone races with new writes. Coordinate **all** attachment writers and cleanup before deleting an object; test concurrent writes, shared keys and retries.
- The draft rejects incoming mail if attachment storage fails, marks the message hidden/failed, and records attempted object keys. Targeted Workers tests cover rejection and the normal receive path. This is a permanent SMTP rejection, not an automatic retry guarantee. If D1 itself is unavailable, failure details may not be recorded; build monitoring and a recovery procedure before release.
- Existing attachment-deletion paths do not participate in the reservation protocol and must be coordinated with writers and cleanup. Per-account deletion also needs protection against a concurrent new attachment.
- The draft reservation intentionally has no automatic expiry: clearing a lock while a previous writer or cleaner is still running can corrupt data. Define monitored, verified recovery for stranded locks, or replace it with a fully fenced coordination design before deployment.
- A reservation release can fail after a write has committed. Define idempotent operation identifiers and retry behavior so an error does not lead to duplicate delivered emails.
- Existing attachments do not store their original storage provider. A settings change can make the current provider different from where an old object lives. Determine and record the correct provider and preserve credentials until cleanup completes; do not blindly use the current setting.
- Prevent every concurrent/in-flight writer from re-creating data after purge begins. Inbound and on-site delivery are only partly coordinated; audit all other account and attachment writes, older deployed versions, lock ordering, release failures, and SMTP behavior under contention before release.
- Define how to stop, retry and observe KV/R2/S3 deletion, including partial failures and provider changes. Ensure a shared file is never removed while referenced by any other user.
- Audit all other copies, including object storage, cached or forwarded messages, database backups and provider logs. Do not promise complete erasure or a fixed retention period until verified.
- Review remaining user identifiers in session-generation/deletion tables and all other records. Verify shared role and invitation-code behavior and anonymization against existing deployment data; don't promise complete removal without a safe retention design.
- Review compatibility with legacy admin deletion/restore operations, account aliases, disabled registration, existing sessions, and missing/deleted database rows.
- Provide an explicit production migration and rollback plan. Without `account_session_generation`, the draft auth changes fail closed; adding code before the table would disrupt login.
- Run Workers integration tests and realistic storage failure/concurrency tests; perform end-to-end tests only on isolated, disposable resources. Do not touch production before all checks and migration/rollback are ready.
