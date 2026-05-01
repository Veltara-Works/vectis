DROP TABLE IF EXISTS domain_spam_lists;

ALTER TABLE domains
    DROP COLUMN IF EXISTS greylist_enabled,
    DROP COLUMN IF EXISTS reject_threshold;
