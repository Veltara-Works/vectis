-- Reverse Enterprise Phase 4 DSAR erasure tombstones.
DROP INDEX IF EXISTS idx_erasure_tombstones_domain_local;
DROP TABLE IF EXISTS erasure_tombstones;
