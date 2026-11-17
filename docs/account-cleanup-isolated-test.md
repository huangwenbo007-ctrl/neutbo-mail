# Isolated account cleanup prototype

This is a development prototype, not authorization to migrate, schedule, or
deploy it against production. No existing preview data should be used as test
fixtures: metadata removal and object deletion are irreversible.

The coordinator uses the D1 clock to choose requests at least 30 days old. It
records account staging and per-object failures, defers shared and unidentified
objects, and retries failed work with bounded backoff. For its KV-only test
path, an object is removed only under its reservation after checking current
references and the recorded storage identity. Status counters omit object keys
and email addresses. A completed metadata stage does not imply every attachment
or backup has been erased.

For a disposable Worker with separately created D1 and KV only, initialize its
normal test schema and apply account-deletion-cleanup-test.sql. Verify the
actual D1 and KV bindings and ensure all fixture accounts and objects are
disposable. Set the two existing isolated-test flags and the exact KV namespace
ID, then explicitly set account_deletion_scheduled_test_only to enabled.
The existing hourly cron may then run a bounded batch and emit a structured
isolated_account_cleanup log with backlog counts. Without that last flag the
hook does nothing. No alerting service or production operator dashboard exists.
Backlogged shared or unresolved objects are intentionally retained; the
summary is for diagnosis, not evidence that deletion is complete.

Before production: audit every account and attachment writer including old or
in-flight Worker versions; design safe recovery of abandoned reservations;
verify historical storage identities and access controls, including direct
storage URLs; support the actual KV/R2/S3 stores; review KV's eventual
consistency; implement operational alerting and recovery; verify database and
object backups and restoration; validate the full deletion and recovery flows;
and independently review the migration, safety and rollback plan. A declared
KV ID alone cannot prove that the attached binding points to that namespace.
