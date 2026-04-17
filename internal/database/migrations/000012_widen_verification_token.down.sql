-- Re-narrow verification_token back to VARCHAR(64). Safe only if all stored
-- tokens are <=64 chars (pre-000012 backfill tokens are md5 = 32 chars).
ALTER TABLE domains ALTER COLUMN verification_token TYPE VARCHAR(64);
