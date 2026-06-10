-- Enterprise Phase 4: DSAR erasure tombstones (GDPR Art.17).
-- A tombstone is the minimal suppression record kept after a data subject's
-- personal data is erased. Its sole purpose is to let Vectis re-apply the
-- erasure if a backup restore resurrects the subject's mailbox/mail/metadata —
-- the EDPB Feb-2026 coordinated-enforcement top finding ("erasure must survive
-- a restore"). Keeping a small suppression record is an established GDPR
-- practice (ICO "beyond use") and is itself the lawful basis for retaining the
-- identifiers below; nothing here carries message content.

CREATE TABLE erasure_tombstones (
    id            UUID        PRIMARY KEY,
    subject_email TEXT        NOT NULL,
    -- domain + local_part are the split of subject_email, stored explicitly so
    -- reconciliation can locate the mailbox without re-parsing addresses.
    domain        TEXT        NOT NULL,
    local_part    TEXT        NOT NULL,
    erased_at     TIMESTAMPTZ NOT NULL,
    -- The super-admin who triggered the erasure. Nullable + no FK on purpose:
    -- the tombstone must outlive admin churn and survive restores that predate
    -- the actor row. (audit_log keeps the FK-backed actor trail separately.)
    erased_by      UUID,
    reconciled_at  TIMESTAMPTZ,
    reconcile_runs INTEGER     NOT NULL DEFAULT 0,
    CONSTRAINT uq_erasure_tombstones_subject UNIQUE (subject_email)
);

CREATE INDEX idx_erasure_tombstones_domain_local
    ON erasure_tombstones (domain, local_part);

COMMENT ON TABLE  erasure_tombstones IS 'GDPR Art.17 suppression list — re-applies erasure after a backup restore. No message content.';
COMMENT ON COLUMN erasure_tombstones.subject_email  IS 'Erased data subject (full email). Minimal identifier needed to honour the erasure across restores.';
COMMENT ON COLUMN erasure_tombstones.reconcile_runs IS 'Number of reconcile passes that have re-checked this subject (bumped every pass, not only when data was re-purged).';
