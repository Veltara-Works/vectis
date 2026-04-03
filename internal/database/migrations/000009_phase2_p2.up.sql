-- Phase 2 P2: Batch sending, message storage, analytics, impersonation, deliverability
-- Covers: 2B.1 batch sending, 2B.2 storage API, 2C.3 per-domain analytics,
--         2D.3 admin impersonation, 2D.4 advanced deliverability

-- =========================================================================
-- 1. Messages table — stores metadata for sent and received messages
-- =========================================================================

CREATE TABLE messages (
    id              UUID PRIMARY KEY,
    domain_id       UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    mailbox_id      UUID REFERENCES mailboxes(id) ON DELETE SET NULL,
    message_id      TEXT NOT NULL,           -- RFC 5322 Message-ID
    direction       VARCHAR(10) NOT NULL,    -- 'inbound' or 'outbound'
    sender          TEXT NOT NULL,
    recipients      TEXT[] NOT NULL,          -- all recipients (to + cc + bcc)
    subject         TEXT,
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    status          VARCHAR(20) NOT NULL DEFAULT 'queued', -- queued, sent, delivered, bounced, failed, spam
    spam_score      DECIMAL(6,2),
    spam_action     VARCHAR(30),
    queue_id        TEXT,                     -- Postfix queue ID
    headers         JSONB,                   -- selected headers for search (X-* etc.)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_messages_domain ON messages(domain_id, created_at DESC);
CREATE INDEX idx_messages_mailbox ON messages(mailbox_id, created_at DESC);
CREATE INDEX idx_messages_direction ON messages(domain_id, direction, created_at DESC);
CREATE INDEX idx_messages_message_id ON messages(message_id);
CREATE INDEX idx_messages_status ON messages(domain_id, status);
CREATE INDEX idx_messages_sender ON messages(sender);

-- Full-text search index on subject and sender.
CREATE INDEX idx_messages_fts ON messages USING gin(to_tsvector('english', coalesce(subject, '') || ' ' || sender));

COMMENT ON TABLE messages IS 'Message metadata for sent and received emails. Content is NOT stored — only metadata for search and analytics.';

-- =========================================================================
-- 2. Mail stats — hourly aggregated counters per domain
-- =========================================================================

CREATE TABLE mail_stats (
    id              UUID PRIMARY KEY,
    domain_id       UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    hour            TIMESTAMPTZ NOT NULL,    -- truncated to hour
    sent            INTEGER NOT NULL DEFAULT 0,
    received        INTEGER NOT NULL DEFAULT 0,
    bounced         INTEGER NOT NULL DEFAULT 0,
    spam            INTEGER NOT NULL DEFAULT 0,
    failed          INTEGER NOT NULL DEFAULT 0,
    size_bytes_total BIGINT NOT NULL DEFAULT 0,

    UNIQUE (domain_id, hour)
);

CREATE INDEX idx_mail_stats_domain_hour ON mail_stats(domain_id, hour DESC);

COMMENT ON TABLE mail_stats IS 'Hourly aggregated mail statistics per domain for analytics dashboards.';

-- =========================================================================
-- 3. IP warmup tracking
-- =========================================================================

CREATE TABLE ip_warmup (
    id              UUID PRIMARY KEY,
    ip_address      INET NOT NULL UNIQUE,
    label           VARCHAR(100),           -- friendly name (e.g. "primary IPv4")
    warmup_started  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    warmup_day      INTEGER NOT NULL DEFAULT 1,  -- current warmup day (1-30+)
    daily_limit     INTEGER NOT NULL DEFAULT 50,  -- target sends for current day
    daily_sent      INTEGER NOT NULL DEFAULT 0,   -- actual sends today
    last_reset_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- when daily_sent was last reset
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE ip_warmup IS 'IP reputation warmup schedule. Tracks daily volume targets and actual sends per IP.';

-- =========================================================================
-- 4. RBL (DNS Blacklist) check results
-- =========================================================================

CREATE TABLE rbl_checks (
    id              UUID PRIMARY KEY,
    ip_address      INET NOT NULL,
    rbl_name        VARCHAR(255) NOT NULL,  -- e.g. 'zen.spamhaus.org'
    listed          BOOLEAN NOT NULL DEFAULT false,
    response        TEXT,                    -- DNS response if listed
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rbl_checks_ip ON rbl_checks(ip_address, checked_at DESC);
CREATE INDEX idx_rbl_checks_listed ON rbl_checks(listed) WHERE listed = true;

COMMENT ON TABLE rbl_checks IS 'RBL/DNSBL monitoring results for server IP addresses.';

-- =========================================================================
-- 5. FBL (Feedback Loop) complaint reports
-- =========================================================================

CREATE TABLE fbl_reports (
    id              UUID PRIMARY KEY,
    domain_id       UUID REFERENCES domains(id) ON DELETE CASCADE,
    mailbox_id      UUID REFERENCES mailboxes(id) ON DELETE SET NULL,
    original_message_id TEXT,
    reporter_domain TEXT NOT NULL,           -- ISP that reported (e.g. 'yahoo.com')
    complaint_type  VARCHAR(50) NOT NULL DEFAULT 'abuse', -- abuse, fraud, virus, other
    feedback_id     TEXT,                    -- ARF feedback report ID
    details         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fbl_reports_domain ON fbl_reports(domain_id, created_at DESC);
CREATE INDEX idx_fbl_reports_mailbox ON fbl_reports(mailbox_id, created_at DESC);

COMMENT ON TABLE fbl_reports IS 'ISP feedback loop (ARF) complaint reports for deliverability monitoring.';

-- =========================================================================
-- 6. Admin impersonation sessions (audit trail)
-- =========================================================================

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS impersonation_target UUID REFERENCES mailboxes(id) ON DELETE SET NULL;

-- =========================================================================
-- Grants
-- =========================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON messages TO vectis_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON mail_stats TO vectis_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ip_warmup TO vectis_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON rbl_checks TO vectis_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON fbl_reports TO vectis_api;
