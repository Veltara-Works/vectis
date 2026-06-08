-- Enterprise Phase 1: SAML 2.0 Single Sign-On
-- Adds SAML identity columns to admins table for provider linking.
-- Mirrors the OIDC columns from migration 000005. password_hash was already
-- made nullable there, so we do not repeat that here.

-- 1. Add SAML identity columns. Both nullable — NULL means no SAML link.
ALTER TABLE admins ADD COLUMN saml_provider VARCHAR(50);
ALTER TABLE admins ADD COLUMN saml_subject  VARCHAR(255);

-- 2. A given provider+subject (NameID) pair must be unique (prevent two admins
--    linked to the same federated identity).
CREATE UNIQUE INDEX idx_admins_saml_identity
    ON admins(saml_provider, saml_subject)
    WHERE saml_provider IS NOT NULL;

COMMENT ON COLUMN admins.saml_provider IS 'SAML provider name (e.g. okta, entra, adfs). NULL = no SAML link.';
COMMENT ON COLUMN admins.saml_subject  IS 'SAML NameID for this admin. Unique per provider.';
