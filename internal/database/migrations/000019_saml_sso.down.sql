-- Reverse Enterprise Phase 1 SAML SSO columns.
DROP INDEX IF EXISTS idx_admins_saml_identity;
ALTER TABLE admins DROP COLUMN IF EXISTS saml_subject;
ALTER TABLE admins DROP COLUMN IF EXISTS saml_provider;
