-- 000025_rbl_check_status.up.sql
--
-- RBL check outcome as a three-way status (#283). A lookup can be listed,
-- clean, or unknown: the list refused the query (Spamhaus answers
-- 127.255.255.x to shared/public resolvers), the lookup timed out, or the
-- list failed its own test address. Unknown must never read as clean, so a
-- boolean `listed` is not enough.
--
-- Additive only. `listed` stays and keeps being written (true only for
-- 'listed'), so the previous release's API reads these rows correctly during
-- an update window. Rows written before this migration have status NULL;
-- readers derive it from `listed`.

ALTER TABLE rbl_checks
    ADD COLUMN IF NOT EXISTS status VARCHAR(16) NULL
        CHECK (status IS NULL OR status IN ('listed', 'clean', 'unknown'));

COMMENT ON COLUMN rbl_checks.status IS
    'listed | clean | unknown (query refused, lookup error, or list failed its test address). NULL on pre-000025 rows: derive from listed.';
COMMENT ON COLUMN rbl_checks.response IS
    'DNS answer when listed, or the reason when status is unknown.';
