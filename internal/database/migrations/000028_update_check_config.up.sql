-- 000028_update_check_config.up.sql
--
-- Singleton table holding the admin-dashboard switches for the daily update
-- check (internal/updatecheck): whether to check for a newer release, and
-- whether to email the admin about one. No row = the defaults (both on).
-- Mirrors the validonx_config (000014) / branding_config (000017) /
-- backup_config (000018) singleton pattern.
--
-- config.yaml still wins when it explicitly turns something off
-- (`updates: {check: false}` / `{email: false}`): an operator can lock the check
-- off, e.g. on an air-gapped server, and the dashboard then shows the switch as
-- locked. The API falls back to config.yaml alone while this table doesn't exist
-- (an install updated by an orchestrator that predates this migration).

CREATE TABLE IF NOT EXISTS update_check_config (
    id                       BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    singleton                BOOLEAN NOT NULL DEFAULT TRUE,
    check_enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    email_enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    configured_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    configured_by_admin_id   UUID,
    CONSTRAINT update_check_config_singleton CHECK (singleton = TRUE)
);

CREATE UNIQUE INDEX IF NOT EXISTS update_check_config_singleton_idx
    ON update_check_config (singleton);

GRANT SELECT, INSERT, UPDATE, DELETE ON update_check_config TO vectis_api;
GRANT USAGE, SELECT ON SEQUENCE update_check_config_id_seq TO vectis_api;

COMMENT ON TABLE update_check_config IS
    'Admin-dashboard switches for the daily update check (singleton). config.yaml updates.check/email: false overrides.';
