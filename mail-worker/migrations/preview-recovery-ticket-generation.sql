-- Isolated preview only. Execute exactly once, and only after PRAGMA table_info
-- confirms the table exists and generation is absent. Zero invalidates old
-- tickets for accounts whose deletion incremented their generation.
ALTER TABLE account_recovery_support_ticket ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
