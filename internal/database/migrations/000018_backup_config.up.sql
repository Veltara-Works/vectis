-- 000018_backup_config.up.sql
--
-- Singleton table holding the runtime-editable backup schedule set via the
-- admin UI Backups page. Takes precedence over the file config (config.yaml
-- `backup:`) when a row is present; no row = use the file defaults. Mirrors
-- the validonx_config (000014) / branding_config (000017) singleton pattern.
--
-- `timezone` is an IANA location name (e.g. "Australia/Sydney"); empty = the
-- container's local time (UTC). It is applied as a CRON_TZ= prefix on the
-- schedule so operators can pick a local backup window instead of UTC.

CREATE TABLE IF NOT EXISTS backup_config (
    id                       BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    singleton                BOOLEAN NOT NULL DEFAULT TRUE,
    enabled                  BOOLEAN NOT NULL DEFAULT FALSE,
    schedule                 TEXT NOT NULL DEFAULT '',
    timezone                 TEXT NOT NULL DEFAULT '',
    retain_days              INTEGER NOT NULL DEFAULT 0,
    configured_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    configured_by_admin_id   UUID,
    CONSTRAINT backup_config_singleton CHECK (singleton = TRUE)
);

CREATE UNIQUE INDEX IF NOT EXISTS backup_config_singleton_idx
    ON backup_config (singleton);

GRANT SELECT, INSERT, UPDATE, DELETE ON backup_config TO vectis_api;
GRANT USAGE, SELECT ON SEQUENCE backup_config_id_seq TO vectis_api;

COMMENT ON TABLE backup_config IS
    'Singleton admin-UI backup schedule overrides; takes precedence over config.yaml backup: when present.';
COMMENT ON COLUMN backup_config.timezone IS
    'IANA tz (e.g. Australia/Sydney) for the schedule; empty = UTC/container-local. Applied as CRON_TZ=.';
COMMENT ON COLUMN backup_config.configured_by_admin_id IS
    'Admin who last saved this config (audit trail).';
