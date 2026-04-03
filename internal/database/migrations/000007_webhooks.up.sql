-- Phase 2B.1: Webhook configuration and delivery log.

-- 1. Webhook endpoints configured per domain (or globally when domain_id is NULL).
CREATE TABLE webhooks (
    id          UUID PRIMARY KEY,
    domain_id   UUID REFERENCES domains(id) ON DELETE CASCADE, -- NULL = global (all domains)
    url         TEXT NOT NULL,
    secret      TEXT NOT NULL,               -- HMAC-SHA256 signing secret
    events      TEXT[] NOT NULL DEFAULT '{}', -- event types to subscribe: mail.sent, mail.delivered, mail.bounced, mail.failed, mail.received, mail.spam
    active      BOOLEAN NOT NULL DEFAULT true,
    created_by  UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_domain ON webhooks(domain_id);
CREATE INDEX idx_webhooks_active ON webhooks(active) WHERE active = true;

-- 2. Delivery log for webhook attempts (retry + debugging).
CREATE TABLE webhook_deliveries (
    id           UUID PRIMARY KEY,
    webhook_id   UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type   VARCHAR(50) NOT NULL,
    payload      JSONB NOT NULL,
    status_code  INT,                 -- HTTP response code; NULL = not attempted yet
    response     TEXT,                -- truncated response body (first 1KB)
    attempt      INT NOT NULL DEFAULT 1,
    next_retry   TIMESTAMPTZ,         -- NULL = no more retries
    delivered_at TIMESTAMPTZ,         -- NULL = not yet delivered
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_pending ON webhook_deliveries(next_retry)
    WHERE delivered_at IS NULL AND next_retry IS NOT NULL;
CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id, created_at DESC);

COMMENT ON TABLE webhooks IS 'Webhook endpoint subscriptions. Per-domain or global. Events signed with HMAC-SHA256.';
COMMENT ON TABLE webhook_deliveries IS 'Webhook delivery attempts with retry tracking.';
