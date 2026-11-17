-- Isolated preview only. Execute exactly once, and only after PRAGMA table_info
-- confirms the table exists and reference_hash is absent. Never use blindly.
ALTER TABLE account_recovery_email_code ADD COLUMN reference_hash TEXT NOT NULL DEFAULT '';
