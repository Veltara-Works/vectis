-- 000017_branding_config.up.sql
--
-- Singleton table holding admin-UI customisation for the Custom Branding
-- Pro feature. Three fields: product_name, primary_color, logo_url. Empty
-- (no row) = use the built-in Vectis defaults at the chrome-render path.
--
-- Singleton-ness enforced via a dedicated boolean column + unique index,
-- mirroring validonx_config (000014). Free installs never write here;
-- the PUT/DELETE handlers are wrapped in FeatureGate(custom_branding).

CREATE TABLE IF NOT EXISTS branding_config (
    id                       BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    singleton                BOOLEAN NOT NULL DEFAULT TRUE,
    product_name             TEXT NOT NULL DEFAULT '',
    primary_color            TEXT NOT NULL DEFAULT '',
    logo_url                 TEXT NOT NULL DEFAULT '',
    configured_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    configured_by_admin_id   UUID,
    CONSTRAINT branding_config_singleton CHECK (singleton = TRUE)
);

CREATE UNIQUE INDEX IF NOT EXISTS branding_config_singleton_idx
    ON branding_config (singleton);

GRANT SELECT, INSERT, UPDATE, DELETE ON branding_config TO vectis_api;
GRANT USAGE, SELECT ON SEQUENCE branding_config_id_seq TO vectis_api;

COMMENT ON TABLE branding_config IS
    'Singleton admin-UI branding overrides (Pro feature: custom_branding).';
COMMENT ON COLUMN branding_config.primary_color IS
    'CSS hex string like #3b82f6; applied as --color-primary at chrome render.';
COMMENT ON COLUMN branding_config.logo_url IS
    'External URL or in-app static asset path; empty = render product_name as wordmark.';
COMMENT ON COLUMN branding_config.configured_by_admin_id IS
    'Admin who last saved this config (audit trail).';
