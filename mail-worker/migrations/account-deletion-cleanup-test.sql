-- Isolated test environments only. This is not a production migration.
CREATE TABLE IF NOT EXISTS account_deletion_cleanup_job (
  user_id INTEGER PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('retry', 'staged', 'blocked')),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_attempt_at INTEGER NOT NULL,
  next_attempt_at INTEGER NOT NULL,
  reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS account_deletion_cleanup_object_status (
  user_id INTEGER NOT NULL,
  storage_type TEXT NOT NULL,
  object_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('retry', 'shared', 'unresolved')),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_attempt_at INTEGER NOT NULL,
  next_attempt_at INTEGER NOT NULL,
  reason TEXT NOT NULL,
  PRIMARY KEY (user_id, storage_type, object_key)
);
