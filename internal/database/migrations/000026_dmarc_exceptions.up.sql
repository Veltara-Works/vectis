-- 000026_dmarc_exceptions.up.sql
--
-- Per-domain DMARC exceptions (#265). DMARC enforcement (rspamd.enforce_dmarc)
-- rejects mail that fails DMARC for a p=reject domain. That is right for
-- forgeries but also turns away legitimate senders with broken DNS, and the
-- allow list can't help (it only applies to authenticated senders, which is
-- correct). An exception lets one sender domain through DMARC enforcement for
-- one recipient domain, but only from a stated sending network: an IP, a CIDR,
-- or a forward-confirmed hostname (suffix). Mail claiming the domain from
-- anywhere else is still rejected.
--
-- Stored as a third kind of per-domain spam-list entry so every renderer that
-- already loads the lists (api, orchestrator, CLI, render-configs) carries the
-- exceptions too: pattern = the sender (header From) domain, network = where
-- it must come from. A network is required for this kind and forbidden for the
-- others, so an exception can never be created from a domain alone.

ALTER TABLE domain_spam_lists ADD COLUMN IF NOT EXISTS network TEXT NULL;

ALTER TABLE domain_spam_lists DROP CONSTRAINT IF EXISTS domain_spam_lists_kind_check;
ALTER TABLE domain_spam_lists ADD CONSTRAINT domain_spam_lists_kind_check
    CHECK (kind IN ('allow', 'block', 'dmarc_exception'));

ALTER TABLE domain_spam_lists DROP CONSTRAINT IF EXISTS domain_spam_lists_network_check;
ALTER TABLE domain_spam_lists ADD CONSTRAINT domain_spam_lists_network_check
    CHECK ((kind = 'dmarc_exception') = (network IS NOT NULL AND network <> ''));

-- One sender domain may be excepted from several networks.
ALTER TABLE domain_spam_lists DROP CONSTRAINT IF EXISTS domain_spam_lists_domain_id_kind_scope_pattern_key;
CREATE UNIQUE INDEX IF NOT EXISTS domain_spam_lists_entry_key
    ON domain_spam_lists (domain_id, kind, scope, pattern, COALESCE(network, ''));

COMMENT ON COLUMN domain_spam_lists.network IS
    'dmarc_exception only (required): IP, CIDR, or hostname (".suffix" for a suffix) the excepted sender must come from. NULL for allow/block.';
COMMENT ON TABLE domain_spam_lists IS
    'Per-domain allow/block lists and DMARC exceptions (Pro). Rendered into rspamd map files by the api and the orchestrator.';
