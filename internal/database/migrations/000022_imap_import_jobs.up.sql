-- IMAP import jobs — admin-triggered background sync of an external IMAP
-- account's mail into a Vectis mailbox (an imapsync-equivalent). Mirrors the
-- backup_jobs job model: one row per import, progress-tracked, pollable.
--
-- source_password is stored ENCRYPTED at rest (secretcrypto, "enc:v1:" prefix);
-- the application encrypts before insert and decrypts on read. Idempotent
-- re-runs (cutover deltas) only copy messages not already present at the
-- destination, counted in skipped_count.
CREATE TABLE imap_import_jobs (
    id               UUID PRIMARY KEY,
    mailbox_id       UUID NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    source_host      VARCHAR(255) NOT NULL,
    source_port      INTEGER NOT NULL DEFAULT 993,
    source_tls       BOOLEAN NOT NULL DEFAULT TRUE,
    source_user      VARCHAR(255) NOT NULL,
    source_password  TEXT NOT NULL,                          -- encrypted at rest
    status           VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending|running|completed|failed|cancelled
    progress         INTEGER NOT NULL DEFAULT 0,             -- 0-100; -1 = indeterminate
    total_messages   INTEGER NOT NULL DEFAULT 0,
    imported_count   INTEGER NOT NULL DEFAULT 0,
    skipped_count    INTEGER NOT NULL DEFAULT 0,             -- already present (idempotent re-run)
    current_folder   VARCHAR(255),
    error_message    TEXT,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMPTZ,
    triggered_by     UUID REFERENCES admins(id) ON DELETE SET NULL
);

CREATE INDEX idx_imap_import_jobs_mailbox ON imap_import_jobs(mailbox_id, started_at DESC);
-- Partial index for the worker's "pick up unfinished work" scan.
CREATE INDEX idx_imap_import_jobs_active ON imap_import_jobs(status) WHERE status IN ('pending', 'running');
