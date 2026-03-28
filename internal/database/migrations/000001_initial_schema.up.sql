-- Vectis Mail Server — Initial Schema
-- Implements: docs/spec/B_Database_Schema.md
-- Forward-only migration (ADR-016)

-- =========================================================================
-- Extensions
-- =========================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- gen_random_bytes, used by Argon2 tooling

-- =========================================================================
-- Tables
-- =========================================================================

-- B.2 domains
CREATE TABLE domains (
    id              UUID PRIMARY KEY,
    name            VARCHAR(255) NOT NULL UNIQUE,
    active          BOOLEAN NOT NULL DEFAULT true,
    dkim_enabled    BOOLEAN NOT NULL DEFAULT true,
    dkim_selector   VARCHAR(63) NOT NULL DEFAULT 'default',
    dkim_key_path   VARCHAR(500),
    spam_threshold  DECIMAL(4,1) NOT NULL DEFAULT 15.0,
    max_mailboxes   INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_domains_name ON domains(name);

-- B.3 mailboxes
CREATE TABLE mailboxes (
    id              UUID PRIMARY KEY,
    domain_id       UUID NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
    local_part      VARCHAR(64) NOT NULL,
    password_hash   TEXT NOT NULL,
    display_name    VARCHAR(255),
    quota_mb        INTEGER NOT NULL DEFAULT 1024,
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (domain_id, local_part)
);

CREATE INDEX idx_mailboxes_domain ON mailboxes(domain_id);
CREATE INDEX idx_mailboxes_email ON mailboxes(domain_id, local_part);

-- B.4 aliases
CREATE TABLE aliases (
    id                  UUID PRIMARY KEY,
    domain_id           UUID NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
    source_local_part   VARCHAR(64) NOT NULL,
    destination         TEXT NOT NULL,
    active              BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (domain_id, source_local_part)
);

CREATE INDEX idx_aliases_domain ON aliases(domain_id);

-- B.5 admins
CREATE TABLE admins (
    id              UUID PRIMARY KEY,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT,
    totp_enabled    BOOLEAN NOT NULL DEFAULT false,
    role            VARCHAR(20) NOT NULL DEFAULT 'admin',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

-- B.6 sessions
CREATE TABLE sessions (
    id              UUID PRIMARY KEY,
    admin_id        UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_sessions_admin ON sessions(admin_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- B.7 orchestrator_history
CREATE TABLE orchestrator_history (
    id                  UUID PRIMARY KEY,
    action              VARCHAR(20) NOT NULL,
    status              VARCHAR(20) NOT NULL,
    config_hash         VARCHAR(64) NOT NULL,
    plan_summary        JSONB,
    snapshot_path       VARCHAR(500),
    container_versions  JSONB,
    error_message       TEXT,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    triggered_by        UUID REFERENCES admins(id) ON DELETE SET NULL
);

CREATE INDEX idx_orch_history_started ON orchestrator_history(started_at DESC);

-- B.8 audit_log
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY,
    admin_id        UUID REFERENCES admins(id) ON DELETE SET NULL,
    action          VARCHAR(50) NOT NULL,
    resource_type   VARCHAR(30) NOT NULL,
    resource_id     UUID,
    details         JSONB,
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_created ON audit_log(created_at DESC);
CREATE INDEX idx_audit_admin ON audit_log(admin_id, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);

-- =========================================================================
-- Database users and privileges (ADR-019)
-- Three Postgres users with different privilege levels:
--   vectis_api     — full access (used by Go API server)
--   vectis_postfix — read-only (used by Postfix SQL lookups)
--   vectis_dovecot — read-only (used by Dovecot SQL lookups)
--
-- NOTE: The users themselves are created by the bootstrap Docker Compose
-- init script (docker/postgres/init-users.sql). This migration grants
-- table-level privileges after the schema is created.
-- =========================================================================

-- vectis_api: full access to all tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vectis_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vectis_api;

-- vectis_postfix: read-only on domains, mailboxes, aliases (mail routing)
GRANT SELECT ON domains TO vectis_postfix;
GRANT SELECT ON mailboxes TO vectis_postfix;
GRANT SELECT ON aliases TO vectis_postfix;

-- vectis_dovecot: read-only on domains, mailboxes (authentication + userdb)
GRANT SELECT ON domains TO vectis_dovecot;
GRANT SELECT ON mailboxes TO vectis_dovecot;
