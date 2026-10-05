-- Tooling convention only: migrations are forward-only and rollback is by
-- pg_dump snapshot restore.
ALTER TABLE domains DROP COLUMN IF EXISTS spam_threshold_override;

COMMENT ON COLUMN domains.spam_threshold IS NULL;
