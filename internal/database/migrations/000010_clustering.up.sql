-- Phase 3: Clustering & High Availability
-- Covers: 3.1 node discovery/registration, leader election, shared state

-- =========================================================================
-- 1. Cluster nodes — self-registration and health tracking
-- =========================================================================

CREATE TABLE cluster_nodes (
    id              UUID PRIMARY KEY,
    name            VARCHAR(255) NOT NULL UNIQUE,   -- human-readable node name (e.g. "node-1")
    advertise_addr  VARCHAR(255) NOT NULL,          -- host:port for inter-node communication
    api_addr        VARCHAR(255) NOT NULL,          -- this node's API address (e.g. "https://node-1:8080")
    role            VARCHAR(20) NOT NULL DEFAULT 'worker', -- 'leader', 'worker', 'standby'
    status          VARCHAR(20) NOT NULL DEFAULT 'joining', -- 'joining', 'active', 'draining', 'dead'
    services        TEXT[] NOT NULL DEFAULT '{}',    -- services running on this node (e.g. {"postfix","dovecot","api"})
    metadata        JSONB,                           -- arbitrary node metadata (OS, version, resources)
    last_heartbeat  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cluster_nodes_status ON cluster_nodes(status);
CREATE INDEX idx_cluster_nodes_heartbeat ON cluster_nodes(last_heartbeat);

COMMENT ON TABLE cluster_nodes IS 'Cluster node registry. Nodes self-register on startup and maintain heartbeats.';

-- =========================================================================
-- 2. Leader election — distributed lock via Postgres
-- =========================================================================

CREATE TABLE cluster_leader (
    id              INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1), -- singleton row
    node_id         UUID NOT NULL REFERENCES cluster_nodes(id) ON DELETE CASCADE,
    elected_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_expires   TIMESTAMPTZ NOT NULL,           -- leader must renew before this time
    term            INTEGER NOT NULL DEFAULT 1       -- monotonically increasing election term
);

COMMENT ON TABLE cluster_leader IS 'Singleton table for cluster leader election. Only one row allowed (id=1 constraint).';

-- =========================================================================
-- 3. Cluster operations — tracks distributed update/rollback across nodes
-- =========================================================================

CREATE TABLE cluster_operations (
    id              UUID PRIMARY KEY,
    operation_type  VARCHAR(20) NOT NULL,    -- 'rolling_update', 'rolling_rollback', 'config_sync'
    status          VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, in_progress, completed, failed
    initiated_by    UUID REFERENCES admins(id) ON DELETE SET NULL,
    plan_summary    JSONB,
    node_statuses   JSONB NOT NULL DEFAULT '{}', -- per-node status: {"node-1": "completed", "node-2": "in_progress"}
    error_message   TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_cluster_ops_status ON cluster_operations(status);

COMMENT ON TABLE cluster_operations IS 'Tracks multi-node operations (rolling updates, rollbacks, config syncs).';

-- =========================================================================
-- Grants
-- =========================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON cluster_nodes TO vectis_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON cluster_leader TO vectis_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON cluster_operations TO vectis_api;
