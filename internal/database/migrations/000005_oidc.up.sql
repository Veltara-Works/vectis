-- Phase 2A.2: OIDC Single Sign-On
-- Adds OIDC identity columns to admins table for provider linking.

-- 1. Add OIDC identity columns. Both nullable — NULL means password-only auth.
ALTER TABLE admins ADD COLUMN oidc_provider VARCHAR(50);
ALTER TABLE admins ADD COLUMN oidc_subject  VARCHAR(255);

-- 2. A given provider+subject pair must be unique (prevent two admins linked to same identity).
CREATE UNIQUE INDEX idx_admins_oidc_identity
    ON admins(oidc_provider, oidc_subject)
    WHERE oidc_provider IS NOT NULL;

-- 3. Allow password_hash to be NULL for OIDC-only accounts.
ALTER TABLE admins ALTER COLUMN password_hash DROP NOT NULL;

COMMENT ON COLUMN admins.oidc_provider IS 'OIDC provider name (e.g. google, azure, keycloak). NULL = password-only.';
COMMENT ON COLUMN admins.oidc_subject  IS 'Subject claim (sub) from OIDC provider. Unique per provider.';
