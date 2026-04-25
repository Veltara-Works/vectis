-- 000014_validonx_runtime_config.up.sql
--
-- Singleton table holding ValidonX licensing configuration that has been set
-- at runtime via the admin UI License page. Takes precedence over values in
-- secrets.yaml. Empty (no row) = use secrets.yaml or fall back to Free tier.
--
-- A single-row constraint is enforced via a generated singleton column +
-- unique index. We do not use `id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY`
-- because there must only ever be one configuration row.

CREATE TABLE IF NOT EXISTS validonx_config (
    id                       BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    singleton                BOOLEAN NOT NULL DEFAULT TRUE,
    base_url                 TEXT NOT NULL DEFAULT '',
    service_key              TEXT NOT NULL DEFAULT '',
    tenant_id                TEXT NOT NULL DEFAULT '',
    subscription_id          TEXT NOT NULL DEFAULT '',
    server_id                TEXT NOT NULL DEFAULT '',
    configured_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    configured_by_admin_id   UUID,
    CONSTRAINT validonx_config_singleton CHECK (singleton = TRUE)
);

CREATE UNIQUE INDEX IF NOT EXISTS validonx_config_singleton_idx
    ON validonx_config (singleton);

-- service_key is a sensitive credential; restrict reads to vectis_api.
GRANT SELECT, INSERT, UPDATE, DELETE ON validonx_config TO vectis_api;
GRANT USAGE, SELECT ON SEQUENCE validonx_config_id_seq TO vectis_api;

COMMENT ON TABLE validonx_config IS
    'Singleton ValidonX licensing config set via admin UI; overrides secrets.yaml when present.';
COMMENT ON COLUMN validonx_config.configured_by_admin_id IS
    'Admin who last saved this config (audit trail).';
