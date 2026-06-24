-- Dovecot short-lived auth tokens. A server-side feature (currently the native
-- IMAP importer; later admin impersonation) sometimes needs to authenticate to
-- Dovecot AS a target mailbox without knowing that user's password. Rather than
-- a Dovecot master user (Valkey-dict, fiddly 2.4 semantics, total-auth-outage
-- blast radius), we add a SECOND ordinary passdb that is a near-copy of the
-- working mailbox passdb, pointed at this table: mint a row with a hashed,
-- short-lived password, authenticate with it, then revoke the row.
--
-- The companion Dovecot passdb (dovecot-sql.conf.ext) queries:
--   SELECT password_hash AS password FROM dovecot_auth_tokens
--    WHERE target_user = '%{user}' AND expires_at > NOW() ...
-- so an expired or absent token simply falls through to the real passdb.
CREATE TABLE dovecot_auth_tokens (
    id            UUID PRIMARY KEY,
    target_user   VARCHAR(255) NOT NULL,        -- full email; the Dovecot login it authenticates as
    password_hash TEXT NOT NULL,                -- argon2id PHC hash (same scheme as mailboxes.password_hash)
    purpose       VARCHAR(20) NOT NULL,         -- 'import' | 'impersonate'
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The hot path is the Dovecot passdb lookup by login, filtered on expiry.
CREATE INDEX idx_dovecot_auth_tokens_lookup ON dovecot_auth_tokens(target_user, expires_at);

-- Dovecot reads this table via the read-only vectis_dovecot role (the same role
-- used for the mailbox passdb — see 000001's `GRANT SELECT ... mailboxes`). The
-- auth_token passdb is consulted BEFORE the mailbox passdb on every login, so
-- without this grant the query errors with "permission denied", Dovecot returns
-- an internal failure, and logins are denied with temp_fail (and the importer's
-- mint→authenticate path can never succeed). Mirror the mailboxes grant.
GRANT SELECT ON dovecot_auth_tokens TO vectis_dovecot;
