-- Tooling convention only: migrations are forward-only and rollback is by
-- pg_dump snapshot restore. Restores the pre-000024 shape; cleared values
-- come back as the old 15.0 default.
UPDATE domains SET spam_threshold = 15.0 WHERE spam_threshold IS NULL;

ALTER TABLE domains
    ALTER COLUMN spam_threshold SET DEFAULT 15.0,
    ALTER COLUMN spam_threshold SET NOT NULL;

COMMENT ON COLUMN domains.spam_threshold IS NULL;
