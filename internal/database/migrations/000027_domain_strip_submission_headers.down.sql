-- Tooling convention only: migrations are forward-only and rollback is by
-- pg_dump snapshot restore.
ALTER TABLE domains DROP COLUMN IF EXISTS strip_submission_headers;
