-- Phase 2B.3: Outbound Abuse Detection
-- Tracks sending suspensions and abuse events for IP reputation protection.

-- 1. Mailbox sending status — tracks throttle/suspend state.
--    Checked on every outbound send via the API.
ALTER TABLE mailboxes ADD COLUMN send_suspended BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE mailboxes ADD COLUMN send_suspended_at TIMESTAMPTZ;
ALTER TABLE mailboxes ADD COLUMN send_suspended_reason TEXT;

-- 2. Abuse events log — records detected anomalies and actions taken.
CREATE TABLE abuse_events (
    id          UUID PRIMARY KEY,
    domain_id   UUID REFERENCES domains(id) ON DELETE CASCADE,
    mailbox_id  UUID REFERENCES mailboxes(id) ON DELETE CASCADE,
    event_type  VARCHAR(50) NOT NULL,   -- 'rate_spike', 'pattern_anomaly', 'geo_anomaly', 'manual_suspend', 'auto_suspend', 'unsuspend'
    severity    VARCHAR(20) NOT NULL,   -- 'info', 'warn', 'critical'
    details     JSONB,                  -- structured event data (rates, thresholds, etc.)
    action      VARCHAR(30),            -- 'throttle', 'suspend', 'alert', 'none'
    resolved    BOOLEAN NOT NULL DEFAULT false,
    resolved_by UUID REFERENCES admins(id),
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_abuse_events_mailbox ON abuse_events(mailbox_id, created_at DESC);
CREATE INDEX idx_abuse_events_domain ON abuse_events(domain_id, created_at DESC);
CREATE INDEX idx_abuse_events_unresolved ON abuse_events(resolved) WHERE resolved = false;

COMMENT ON TABLE abuse_events IS 'Outbound abuse detection events. Tracks rate spikes, pattern anomalies, and suspension actions.';
