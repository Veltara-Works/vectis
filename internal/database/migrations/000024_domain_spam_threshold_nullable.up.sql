-- 000024_domain_spam_threshold_nullable.up.sql
--
-- domains.spam_threshold becomes a working, optional per-domain override of
-- the Rspamd add_header ("spam", files to Junk) threshold, matching
-- reject_threshold and greylist_enabled (000016): NULL = use the system-wide
-- rspamd.spam_threshold from config.yaml.
--
-- Until this release the column was stored and settable but never rendered
-- into the Rspamd config, so no install has ever filtered on it. Every
-- existing value is therefore cleared to NULL: that keeps each domain on the
-- threshold it actually uses today (config.yaml's), rather than switching on
-- a dormant value such as the old 15.0 default, at which real spam is never
-- tagged. Setting an override is a Pro (advanced_spam) API operation.

ALTER TABLE domains
    ALTER COLUMN spam_threshold DROP NOT NULL,
    ALTER COLUMN spam_threshold DROP DEFAULT;

UPDATE domains SET spam_threshold = NULL WHERE spam_threshold IS NOT NULL;

COMMENT ON COLUMN domains.spam_threshold IS
    'Per-domain Rspamd add_header (spam) threshold override. NULL = use system-wide config.yaml value.';
