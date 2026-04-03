-- Phase 2B.1: API Key Management
-- Stores hashed API keys for programmatic access (sending API, webhooks).

CREATE TABLE api_keys (
    id          UUID PRIMARY KEY,
    admin_id    UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    key_hash    TEXT NOT NULL,          -- SHA-256 of the raw key; raw key never stored
    key_prefix  VARCHAR(16) NOT NULL,   -- first 8 chars of raw key for identification
    scoped_domain_ids UUID[],           -- NULL = all domains the admin can access
    rate_limit  INT NOT NULL DEFAULT 60, -- requests per minute; 0 = unlimited
    active      BOOLEAN NOT NULL DEFAULT true,
    expires_at  TIMESTAMPTZ,            -- NULL = never expires
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_admin ON api_keys(admin_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

COMMENT ON TABLE api_keys IS 'API keys for programmatic access. Keys are SHA-256 hashed; the raw key is shown once at creation time.';
