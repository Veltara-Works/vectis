-- Tooling convention only: migrations are forward-only (rollback = pg_dump restore).
ALTER TABLE rbl_checks DROP COLUMN IF EXISTS status;
