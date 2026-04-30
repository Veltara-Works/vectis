-- 000015_validonx_license_key.down.sql

ALTER TABLE validonx_config
    DROP COLUMN IF EXISTS license_key;
