-- 000015_validonx_license_key.up.sql
--
-- Adds the license_key column to validonx_config so the admin UI License
-- page can configure licensing end-to-end. Previously license_key was
-- operator-only via secrets.yaml — that's a UX over-claim against the
-- License page docstring. This closes the gap.
--
-- license_key is the ValidonX-issued license string (VLDX-...) sent on the
-- wire to /api/v1/integration/licensing/resolve as `data.license_key`.
-- Distinct from subscription_id in ValidonX's data model (one subscription
-- → many license_keys).

ALTER TABLE validonx_config
    ADD COLUMN IF NOT EXISTS license_key TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN validonx_config.license_key IS
    'ValidonX-issued license string (VLDX-...). Sent as data.license_key on the wire.';
