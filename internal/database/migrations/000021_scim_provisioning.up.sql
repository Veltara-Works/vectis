-- Enterprise: SCIM 2.0 user provisioning (RFC 7643/7644).
-- Lets an Enterprise IdP (Okta, Azure AD/Entra) auto-provision and deprovision
-- mailboxes on employee on/off-boarding. Follow-on to SAML SSO (000019).
-- Phase 1 targets mailboxes (not console admins); DELETE deactivates rather than
-- erasing (erasure stays a deliberate DSAR action — see 000020 tombstones).

-- 1. externalId on mailboxes: the IdP's stable user id. NULL = not IdP-managed.
--    Lets PUT/PATCH/DELETE re-find the mailbox independent of a renamed email.
--    Partial unique index so multiple non-SCIM mailboxes (NULL) coexist while
--    each IdP identity maps to at most one mailbox.
ALTER TABLE mailboxes ADD COLUMN external_id VARCHAR(255);

CREATE UNIQUE INDEX idx_mailboxes_external_id
    ON mailboxes(external_id)
    WHERE external_id IS NOT NULL;

COMMENT ON COLUMN mailboxes.external_id IS 'SCIM externalId — IdP stable user id. NULL = not IdP-managed.';

-- 2. SCIM bearer tokens. Machine-to-machine auth for /scim/v2 — a static
--    Bearer token, not a session. Store only the SHA-256 hash; the raw
--    scim_<hex> token is shown once at creation. Single active token per
--    install in Phase 1; table shape allows multiple/labelled tokens later
--    without migration churn.
CREATE TABLE scim_tokens (
    id           UUID         PRIMARY KEY,
    token_hash   CHAR(64)     NOT NULL UNIQUE,
    token_prefix VARCHAR(16)  NOT NULL,
    active       BOOLEAN      NOT NULL DEFAULT true,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scim_tokens_active ON scim_tokens(active) WHERE active;

COMMENT ON TABLE  scim_tokens IS 'SCIM 2.0 provisioning bearer tokens (hash only; raw token shown once at creation).';
COMMENT ON COLUMN scim_tokens.token_hash   IS 'SHA-256 hex of the raw scim_ token. Lookup key for scimAuthMiddleware.';
COMMENT ON COLUMN scim_tokens.token_prefix IS 'scim_ + first 8 hex of the raw token — display/identification only, not a secret.';
