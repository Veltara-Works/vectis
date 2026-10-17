-- 000026_dmarc_exceptions.down.sql
-- Tooling convention only: Vectis migrations are forward-only (rollback is a
-- pg_dump restore). Removes the DMARC exceptions and the network column.
DELETE FROM domain_spam_lists WHERE kind = 'dmarc_exception';
DROP INDEX IF EXISTS domain_spam_lists_entry_key;
ALTER TABLE domain_spam_lists ADD CONSTRAINT domain_spam_lists_domain_id_kind_scope_pattern_key UNIQUE (domain_id, kind, scope, pattern);
ALTER TABLE domain_spam_lists DROP CONSTRAINT IF EXISTS domain_spam_lists_network_check;
ALTER TABLE domain_spam_lists DROP CONSTRAINT IF EXISTS domain_spam_lists_kind_check;
ALTER TABLE domain_spam_lists ADD CONSTRAINT domain_spam_lists_kind_check CHECK (kind IN ('allow', 'block'));
ALTER TABLE domain_spam_lists DROP COLUMN IF EXISTS network;
