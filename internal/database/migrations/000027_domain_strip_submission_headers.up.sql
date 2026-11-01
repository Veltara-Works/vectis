-- 000027_domain_strip_submission_headers.up.sql
--
-- Per-domain list of extra headers to strip from mail the domain sends (#231),
-- Pro. Applied by an rspamd Lua rule (rspamd.local.lua) to outbound mail whose
-- envelope sender is this domain, ON TOP OF the host-wide
-- postfix.strip_submission_extra_headers list in config.yaml, which still
-- applies to every sender. NULL = no per-domain additions.
--
-- Names are validated by config.ValidateStripHeaders before they are stored:
-- letters, digits, '-' and '_' only, and never a header covered by the DKIM
-- signature (removal happens after signing).
--
-- Expand only: a new nullable column. The previous release's API never selects
-- it, so it keeps serving while an update applies.

ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS strip_submission_headers TEXT[] NULL;

COMMENT ON COLUMN domains.strip_submission_headers IS
    'Extra headers stripped from mail this domain sends, in addition to the host-wide config.yaml list. NULL = none.';
