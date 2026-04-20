#!/bin/bash
# Bootstrap script run by Postgres container on first start.
# Creates the three database users required by ADR-019.
# Passwords come from environment variables set in docker-compose.yml.

set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vectis_api') THEN
            CREATE ROLE vectis_api LOGIN PASSWORD '${VECTIS_API_PASSWORD}';
        END IF;
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vectis_postfix') THEN
            CREATE ROLE vectis_postfix LOGIN PASSWORD '${VECTIS_POSTFIX_PASSWORD}';
        END IF;
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vectis_dovecot') THEN
            CREATE ROLE vectis_dovecot LOGIN PASSWORD '${VECTIS_DOVECOT_PASSWORD}';
        END IF;
    END
    \$\$;

    -- vectis_api owns application tables and runs golang-migrate from the API
    -- binary, so it needs CREATE on schema public. Postgres 15+ removed this
    -- from PUBLIC by default; without an explicit grant, the very first
    -- migration fails with "permission denied for schema public".
    GRANT CREATE ON SCHEMA public TO vectis_api;

    -- Extensions can only be created by a superuser (or by a role with
    -- CREATE on the database for "trusted" extensions). Create the ones
    -- the migrations need here so vectis_api never has to.
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
EOSQL
