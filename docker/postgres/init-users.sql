-- Bootstrap script run by Postgres container on first start.
-- Creates the three database users required by ADR-019.
-- Passwords are injected via environment variables in docker-compose.yml.
--
-- This script runs as the postgres superuser against the vectis database.

-- Create roles if they don't already exist (idempotent).
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vectis_api') THEN
        CREATE ROLE vectis_api LOGIN PASSWORD :'VECTIS_API_PASSWORD';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vectis_postfix') THEN
        CREATE ROLE vectis_postfix LOGIN PASSWORD :'VECTIS_POSTFIX_PASSWORD';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vectis_dovecot') THEN
        CREATE ROLE vectis_dovecot LOGIN PASSWORD :'VECTIS_DOVECOT_PASSWORD';
    END IF;
END
$$;
