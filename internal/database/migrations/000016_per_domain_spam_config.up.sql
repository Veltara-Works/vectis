-- 000016_per_domain_spam_config.up.sql
--
-- Pro-tier "Advanced Spam" — schema for per-domain reject/greylist overrides
-- and per-domain allow/block lists (decisions D3 in plan
-- proceed-with-advanced-spam-splendid-creek). The API layer gates writes via
-- validonx FeatureAdvancedSpam; this migration adds only schema, no defaults
-- that would change behaviour for existing Free installs.
--
-- Both new domain columns are NULL = "use system-wide default", so a Free
-- install on this schema keeps behaving exactly as today (rspamd
-- spam_threshold/reject_threshold/greylist_enabled come from config.yaml).

ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS reject_threshold DECIMAL(4,1) NULL,
    ADD COLUMN IF NOT EXISTS greylist_enabled BOOLEAN NULL;

COMMENT ON COLUMN domains.reject_threshold IS
    'Per-domain Rspamd reject threshold override. NULL = use system-wide config.yaml value.';
COMMENT ON COLUMN domains.greylist_enabled IS
    'Per-domain greylisting toggle. NULL = use system-wide config.yaml value.';

CREATE TABLE domain_spam_lists (
    id          UUID PRIMARY KEY,
    domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('allow','block')),
    scope       TEXT NOT NULL CHECK (scope IN ('email','domain')),
    pattern     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, kind, scope, pattern)
);

CREATE INDEX idx_domain_spam_lists_domain ON domain_spam_lists(domain_id);
CREATE INDEX idx_domain_spam_lists_lookup ON domain_spam_lists(domain_id, kind, scope);

COMMENT ON TABLE domain_spam_lists IS
    'Per-domain allow/block lists (Pro). Consumed by the orchestrator when regenerating Rspamd multimap files.';

GRANT SELECT, INSERT, DELETE ON domain_spam_lists TO vectis_api;
