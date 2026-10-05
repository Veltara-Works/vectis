-- 000024_domain_spam_threshold_override.up.sql
--
-- Per-domain spam (add_header, files to Junk) threshold override, Pro.
-- NULL = use the system-wide rspamd.spam_threshold from config.yaml, matching
-- reject_threshold and greylist_enabled (000016). The API field stays
-- `spam_threshold`; it reads and writes this column from v0.1.50.
--
-- Expand/contract: this migration ONLY adds a column. The legacy
-- domains.spam_threshold (NOT NULL DEFAULT 15.0) is left exactly as it is,
-- because the previous release's API is still serving while an update
-- applies, and it scans that column into a non-nullable number. Clearing or
-- loosening it here would break domain reads during the upgrade window.
--
-- The legacy column was stored but never rendered into the Rspamd config, so
-- no install has ever filtered on it. Its values are deliberately NOT copied:
-- every domain starts with no override and keeps the threshold it actually
-- uses today. A later release drops the legacy column (the contract step).

ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS spam_threshold_override DECIMAL(4,1) NULL;

COMMENT ON COLUMN domains.spam_threshold_override IS
    'Per-domain Rspamd add_header (spam) threshold override. NULL = use system-wide config.yaml value.';

COMMENT ON COLUMN domains.spam_threshold IS
    'DEPRECATED since 000024: never applied to Rspamd; superseded by spam_threshold_override. Kept for pre-v0.1.50 readers; dropped in a later release.';
