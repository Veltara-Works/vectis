-- Vectis Mail Server — Phase 1 Schema Additions
-- Forward-only migration (ADR-016)

-- =========================================================================
-- Backup jobs — tracks async backup/restore operations
-- =========================================================================

CREATE TABLE backup_jobs (
    id              UUID PRIMARY KEY,
    action          VARCHAR(20) NOT NULL,          -- 'create' or 'restore'
    status          VARCHAR(20) NOT NULL,          -- 'pending', 'running', 'completed', 'failed'
    backup_path     VARCHAR(500),                  -- path to backup archive
    progress        INTEGER NOT NULL DEFAULT 0,    -- percentage 0-100
    current_step    VARCHAR(100),                  -- e.g. "Dumping database", "Copying mail data"
    error_message   TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    triggered_by    UUID REFERENCES admins(id) ON DELETE SET NULL
);

CREATE INDEX idx_backup_jobs_started ON backup_jobs(started_at DESC);

-- =========================================================================
-- Alert history — for alert deduplication
-- =========================================================================

CREATE TABLE alert_history (
    id              UUID PRIMARY KEY,
    severity        VARCHAR(20) NOT NULL,          -- 'info', 'warn', 'error', 'critical'
    service         VARCHAR(30) NOT NULL,          -- service name or 'system'
    message         TEXT NOT NULL,
    dedup_key       VARCHAR(255) NOT NULL,         -- key for deduplication (e.g. "postfix:unhealthy")
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ                    -- NULL = still active
);

CREATE INDEX idx_alert_history_dedup ON alert_history(dedup_key, sent_at DESC);
CREATE INDEX idx_alert_history_active ON alert_history(resolved_at) WHERE resolved_at IS NULL;

-- =========================================================================
-- ValidonX license cache — cached entitlements for 30-day grace period
-- =========================================================================

CREATE TABLE validonx_cache (
    id              UUID PRIMARY KEY,
    tenant_id       VARCHAR(255) NOT NULL,
    subscription_id VARCHAR(255),
    license_data    JSONB NOT NULL,                -- cached license resolve response
    features        JSONB,                         -- cached feature flags
    status          VARCHAR(30) NOT NULL,          -- 'active', 'trialing', 'paused', 'canceled'
    last_check_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,          -- grace period expiry
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_validonx_cache_tenant ON validonx_cache(tenant_id);

-- =========================================================================
-- Admin recovery email — for password reset flow (Phase 1)
-- =========================================================================

ALTER TABLE admins ADD COLUMN IF NOT EXISTS recovery_email VARCHAR(255);

-- =========================================================================
-- Privilege grants for new tables
-- =========================================================================

-- vectis_api: full access to new tables
GRANT SELECT, INSERT, UPDATE, DELETE ON backup_jobs TO vectis_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON alert_history TO vectis_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON validonx_cache TO vectis_api;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vectis_api;
