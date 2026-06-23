-- Reverse Enterprise SCIM 2.0 provisioning.
DROP TABLE IF EXISTS scim_tokens;
DROP INDEX IF EXISTS idx_mailboxes_external_id;
ALTER TABLE mailboxes DROP COLUMN IF EXISTS external_id;
