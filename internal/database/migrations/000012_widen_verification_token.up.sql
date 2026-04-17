-- verification_token was declared VARCHAR(64) in migration 000003, but
-- types.NewVerificationToken() emits "vectis-verify=" (14 chars) + 64 hex
-- chars (32 bytes) = 78 chars. Every domain creation via the API therefore
-- failed with SQLSTATE 22001 ("value too long for type character varying(64)").
-- Widen to VARCHAR(128) so the current generator fits with headroom for
-- future format tweaks.
ALTER TABLE domains ALTER COLUMN verification_token TYPE VARCHAR(128);
