-- Engagement tracking persistence.
-- Records opt-in open/click events from tracking pixel + click-redirect handlers
-- so admins can query open/click rates per message and per domain.

CREATE TABLE email_events (
    id              UUID PRIMARY KEY,
    domain_id       UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    message_id      TEXT NOT NULL,             -- RFC 5322 Message-ID (links to messages.message_id)
    event_type      VARCHAR(20) NOT NULL,      -- 'open' or 'click'
    target_url      TEXT,                      -- click target (NULL for opens)
    user_agent      TEXT,
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_events_message ON email_events(message_id, event_type);
CREATE INDEX idx_email_events_domain_time ON email_events(domain_id, created_at DESC);
CREATE INDEX idx_email_events_domain_type ON email_events(domain_id, event_type, created_at DESC);

COMMENT ON TABLE email_events IS 'Engagement tracking events (opens, clicks) from opt-in tracking pixel and click redirect.';

GRANT SELECT, INSERT, DELETE ON email_events TO vectis_api;
