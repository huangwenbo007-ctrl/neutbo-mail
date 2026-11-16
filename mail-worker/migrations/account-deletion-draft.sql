-- Draft only: do not run against an existing environment until the service,
-- recovery flow, purge worker and rollback procedure have all been reviewed.
CREATE TABLE IF NOT EXISTS account_deletion_request (
  user_id INTEGER PRIMARY KEY,
  requested_at INTEGER NOT NULL,
  purge_after INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending', 'purging')),
  CHECK (purge_after >= requested_at + 2592000)
);

CREATE INDEX IF NOT EXISTS idx_account_deletion_due
  ON account_deletion_request(state, purge_after);

-- Retain the generation after recovery so pre-deletion tokens stay invalid.
CREATE TABLE IF NOT EXISTS account_session_generation (
  user_id INTEGER PRIMARY KEY,
  generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0)
);

-- Per-account reauthentication attempts; never store passwords here.
CREATE TABLE IF NOT EXISTS account_reauth_rate (
  user_id INTEGER PRIMARY KEY,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL CHECK (attempts BETWEEN 1 AND 5)
);

-- One pending Google reauthentication per account. Never stores Google tokens.
CREATE TABLE IF NOT EXISTS google_deletion_challenge (
  user_id INTEGER PRIMARY KEY,
  state TEXT NOT NULL UNIQUE,
  session_hash TEXT NOT NULL,
  nonce TEXT NOT NULL,
  verifier TEXT NOT NULL,
  subject TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Contact comes exclusively from Google's verified userinfo response, never
-- from the browser or the legacy, unverified oauth.username field.
CREATE TABLE IF NOT EXISTS google_verified_contact (
  oauth_id INTEGER PRIMARY KEY, subject TEXT NOT NULL, email TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS google_email_deletion_code (
  user_id INTEGER PRIMARY KEY, oauth_id INTEGER NOT NULL, subject TEXT NOT NULL,
  email TEXT NOT NULL, session_hash TEXT NOT NULL, challenge TEXT NOT NULL,
  code_hash TEXT NOT NULL, sent_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS google_email_deletion_rate (
  user_id INTEGER PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL
);

-- This queue is only a schema sketch. Shared content-addressed objects require
-- coordination with every upload/attachment writer before deletion is safe.
CREATE TABLE IF NOT EXISTS account_deletion_object_queue (
  storage_type TEXT NOT NULL,
  object_key TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY(user_id, storage_type, object_key)
);

-- Draft reservation: do not automatically expire a lock while a slow object
-- write or delete may still be in flight. A failed owner needs manual recovery.
CREATE TABLE IF NOT EXISTS attachment_object_lock (
  storage_type TEXT NOT NULL,
  object_key TEXT NOT NULL,
  owner_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(object_key)
);

-- An origin is usable only when recorded from a trusted, locked writer after
-- a successful write. A conflicting origin is permanently ambiguous until a
-- separately reviewed reconciliation; legacy objects have no trusted origin.
CREATE TABLE IF NOT EXISTS attachment_object_origin (
  object_key TEXT PRIMARY KEY,
  storage_type TEXT NOT NULL CHECK (storage_type IN ('KV', 'R2', 'S3')),
  store_id TEXT NOT NULL CHECK (length(store_id) > 0),
  state TEXT NOT NULL CHECK (state IN ('known', 'ambiguous'))
);

-- Failed inbound attachment keys remain traceable for later investigation.
CREATE TABLE IF NOT EXISTS inbound_attachment_failure (
  email_id INTEGER NOT NULL,
  object_key TEXT NOT NULL,
  recorded_at INTEGER NOT NULL,
  PRIMARY KEY(email_id, object_key)
);
