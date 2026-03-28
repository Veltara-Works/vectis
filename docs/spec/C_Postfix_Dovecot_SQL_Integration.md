# C. Postfix & Dovecot SQL Integration

**Status:** DRAFT — For review with Copilot before integration into Spec v1.1  
**Prepared by:** Claude (round 5)  
**Complements:** Vectis Architecture v1.3, Implementation Spec v1.0, Section B (Database Schema)

---

## C.1 Overview

Postfix and Dovecot query Postgres directly for operational data (domains, mailboxes, aliases). This is the critical integration point where the hybrid source-of-truth model meets the actual mail services.

**Key benefit:** Adding a mailbox, alias, or domain in the Admin UI takes effect immediately — no config file regeneration, no service reload, no container restart. Postfix and Dovecot query Postgres on each connection/delivery.

**What the config engine generates:** The SQL lookup configuration files (connection details, query templates). These are generated once and only change if the database connection details change (e.g., password rotation) or the query logic is updated (e.g., new schema version).

**What flows at runtime:** Actual domain/mailbox/alias data flows directly from Postgres to Postfix/Dovecot on each query.

---

## C.2 Mail User and Directory Conventions

All mail data is owned by a dedicated `vmail` user:

| Property | Value |
|----------|-------|
| User | vmail |
| UID | 5000 |
| GID | 5000 |
| Home | /var/vectis/mail |
| Mail path pattern | /var/vectis/mail/{domain}/{local_part}/Maildir/ |

This user exists inside both the Postfix and Dovecot containers. The bind mount at `/var/vectis/mail/` is shared between them.

Directory structure example for `user@example.com`:

```
/var/vectis/mail/
  example.com/
    user/
      Maildir/
        cur/
        new/
        tmp/
```

---

## C.3 Postfix SQL Lookups

Postfix uses the `pgsql:` map type to query Postgres. The config engine generates these `.cf` files into the Postfix config directory. Connection credentials come from secrets.yaml.

### C.3.1 Virtual Mailbox Domains

**File:** `/etc/postfix/pgsql_virtual_domains.cf`  
**Purpose:** Tells Postfix which domains to accept mail for.

```ini
hosts = postgres
user = vectis_postfix
password = {from secrets.yaml}
dbname = vectis
query = SELECT name FROM domains WHERE name = '%s' AND active = true
```

### C.3.2 Virtual Mailbox Maps

**File:** `/etc/postfix/pgsql_virtual_mailboxes.cf`  
**Purpose:** Tells Postfix which local addresses have mailboxes and where to deliver mail.

```ini
hosts = postgres
user = vectis_postfix
password = {from secrets.yaml}
dbname = vectis
query = SELECT CONCAT(d.name, '/', m.local_part, '/Maildir/') \
    FROM mailboxes m \
    JOIN domains d ON m.domain_id = d.id \
    WHERE CONCAT(m.local_part, '@', d.name) = '%s' \
    AND m.active = true AND d.active = true
```

The return value is a relative path under `virtual_mailbox_base`. Postfix delivers to `/var/vectis/mail/example.com/user/Maildir/`.

### C.3.3 Virtual Alias Maps

**File:** `/etc/postfix/pgsql_virtual_aliases.cf`  
**Purpose:** Tells Postfix how to resolve aliases to their destinations.

```ini
hosts = postgres
user = vectis_postfix
password = {from secrets.yaml}
dbname = vectis
query = SELECT a.destination \
    FROM aliases a \
    JOIN domains d ON a.domain_id = d.id \
    WHERE CONCAT(a.source_local_part, '@', d.name) = '%s' \
    AND a.active = true AND d.active = true
```

### C.3.4 Catch-All Aliases

Catch-all aliases (where `source_local_part = ''`) need special handling. Postfix queries alias maps with the full address first, then falls back to `@domain` format for catch-alls. The alias query should also handle this:

```ini
# Additional catch-all query (appended to virtual_alias_maps)
# File: /etc/postfix/pgsql_virtual_catchall.cf
query = SELECT a.destination \
    FROM aliases a \
    JOIN domains d ON a.domain_id = d.id \
    WHERE d.name = '%d' \
    AND a.source_local_part = '' \
    AND a.active = true AND d.active = true
```

### C.3.5 Postfix main.cf Integration

The config engine adds these directives to `main.cf`:

```ini
# Virtual domain hosting
virtual_mailbox_domains = pgsql:/etc/postfix/pgsql_virtual_domains.cf
virtual_mailbox_maps = pgsql:/etc/postfix/pgsql_virtual_mailboxes.cf
virtual_alias_maps = pgsql:/etc/postfix/pgsql_virtual_aliases.cf,
                     pgsql:/etc/postfix/pgsql_virtual_catchall.cf
virtual_mailbox_base = /var/vectis/mail
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
virtual_minimum_uid = 5000

# Transport (ADR-008: TCP LMTP to Dovecot on port 24)
virtual_transport = lmtp:inet:dovecot:24
```

### C.3.6 Postfix-to-Dovecot Delivery

Postfix delivers mail to Dovecot via LMTP (Local Mail Transfer Protocol) rather than writing directly to Maildir. This is important because:

- Dovecot handles quota enforcement at delivery time
- Dovecot handles Sieve filtering (Phase 2+)
- Dovecot maintains its index/cache correctly
- Avoids permission issues between Postfix and Dovecot processes

The `virtual_transport` directive routes all virtual mailbox delivery to Dovecot's LMTP socket.

---

## C.4 Dovecot SQL Integration

Dovecot uses SQL for both password verification (passdb) and user lookup (userdb).

### C.4.1 Password Database

**File:** `/etc/dovecot/dovecot-sql.conf.ext`

```ini
driver = pgsql
connect = host=postgres dbname=vectis user=vectis_dovecot password={from secrets.yaml}
default_pass_scheme = ARGON2ID

password_query = SELECT \
    CONCAT(m.local_part, '@', d.name) AS user, \
    m.password_hash AS password, \
    CONCAT('/var/vectis/mail/', d.name, '/', m.local_part) AS userdb_home, \
    CONCAT('maildir:/var/vectis/mail/', d.name, '/', m.local_part, '/Maildir') AS userdb_mail, \
    5000 AS userdb_uid, \
    5000 AS userdb_gid, \
    CONCAT('*:bytes=', m.quota_mb * 1048576) AS userdb_quota_rule \
    FROM mailboxes m \
    JOIN domains d ON m.domain_id = d.id \
    WHERE CONCAT(m.local_part, '@', d.name) = '%u' \
    AND m.active = true AND d.active = true
```

### C.4.2 User Database (Prefetch + Fallback)

The password query above returns `userdb_*` prefixed fields. This allows Dovecot to use "prefetch" — it gets both auth and user info in a single SQL query during login.

For LMTP delivery (where there's no authentication step), Dovecot needs a separate userdb lookup:

```ini
user_query = SELECT \
    CONCAT('/var/vectis/mail/', d.name, '/', m.local_part) AS home, \
    CONCAT('maildir:/var/vectis/mail/', d.name, '/', m.local_part, '/Maildir') AS mail, \
    5000 AS uid, \
    5000 AS gid, \
    CONCAT('*:bytes=', m.quota_mb * 1048576) AS quota_rule \
    FROM mailboxes m \
    JOIN domains d ON m.domain_id = d.id \
    WHERE CONCAT(m.local_part, '@', d.name) = '%u' \
    AND m.active = true AND d.active = true
```

### C.4.3 Dovecot Auth Configuration

The config engine generates:

```ini
# /etc/dovecot/conf.d/10-auth.conf
auth_mechanisms = plain login

passdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf.ext
}

# Prefetch: gets userdb data from passdb query (login path)
userdb {
    driver = prefetch
}

# SQL fallback: used by LMTP delivery (no auth step)
userdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf.ext
}
```

The two `userdb` blocks serve different purposes:
1. **Prefetch:** Used during normal IMAP/POP3 login. Gets user info from the password_query's `userdb_*` fields. Fast (no extra SQL query).
2. **SQL fallback:** Used by LMTP for delivery, where no authentication occurs. Runs the `user_query` to locate the mailbox.

---

## C.5 Database User Separation

For defence in depth, Postfix and Dovecot use separate Postgres users with minimal privileges:

| DB User | Can Read | Can Write | Purpose |
|---------|----------|-----------|---------|
| vectis_postfix | domains, mailboxes, aliases | Nothing | Postfix lookups (read-only) |
| vectis_dovecot | domains, mailboxes | Nothing | Dovecot auth + userdb (read-only) |
| vectis_api | All tables | All tables | API application user (full access) |

```sql
-- Created during initial migration
CREATE USER vectis_postfix WITH PASSWORD '{from secrets.yaml}';
GRANT SELECT ON domains, mailboxes, aliases TO vectis_postfix;

CREATE USER vectis_dovecot WITH PASSWORD '{from secrets.yaml}';
GRANT SELECT ON domains, mailboxes TO vectis_dovecot;

CREATE USER vectis_api WITH PASSWORD '{from secrets.yaml}';
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO vectis_api;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO vectis_api;
```

**Security rationale:** If Postfix or Dovecot is compromised, the attacker gets read-only access to domains and mailbox metadata (email addresses, quota info). They cannot modify data, cannot read other tables (sessions, admins, audit logs), and cannot access password hashes through the Postfix user.

---

## C.6 Updated Reload/Restart Matrix

Because Postfix and Dovecot query Postgres directly for operational data, the reload/restart matrix from Architecture v1.3 §7 gains an important new category: **database-driven changes that require no service action at all.**

| Change Type | Service Action | Mechanism |
|-------------|---------------|-----------|
| Add/remove mailbox | None (live query) | Postfix + Dovecot query Postgres per connection |
| Add/remove alias | None (live query) | Postfix queries Postgres per delivery |
| Add/remove domain | None (live query) | Postfix queries virtual_mailbox_domains per connection |
| Change mailbox password | None (live query) | Dovecot queries password_hash per login |
| Change mailbox quota | None (live query) | Dovecot queries quota_rule per login |
| Enable/disable mailbox | None (live query) | Active flag checked in SQL WHERE clause |
| Enable/disable domain | None (live query) | Active flag checked in SQL WHERE clause |
| Change DKIM key for domain | Rspamd reload | Rspamd config references key files |
| Change spam threshold for domain | Rspamd reload | Config engine regenerates Rspamd per-domain config |
| Change global TLS settings | Postfix + Dovecot reload | Config engine regenerates TLS config |
| Change ClamAV profile | ClamAV restart / full apply | Container may need to be added/removed |
| Change resource limits | Full orchestrator apply | Docker Compose must be regenerated |

**This is a significant simplification:** The six most common admin operations (add/remove/modify mailboxes, aliases, domains) require zero service restarts or reloads. They take effect immediately via SQL query. This dramatically improves operational ergonomics and reduces the risk of service disruption during routine administration.

---

## C.7 Connection Pooling Considerations

Postfix and Dovecot open database connections per lookup. On a busy server, this could mean hundreds of short-lived connections per minute. Considerations:

- **Postgres `max_connections`**: Default is 100. Should be increased to at least 200 for production profiles. Set via config engine.
- **Connection lifetime**: Postfix's `pgsql:` driver can maintain persistent connections (configured per lookup file). Enable this to reduce connection overhead.
- **PgBouncer**: For high-traffic deployments (Phase 3+), consider adding PgBouncer as a connection pooler between mail services and Postgres. Not needed for Phase 1.
- **The Go API uses pgxpool**: Connection pooling is handled application-side. Default pool size should be 25 connections, configurable via config.yaml.

---

## C.8 What the Config Engine Generates vs. What's Live

To avoid confusion, here's a clear boundary:

| Data | Source of Truth | Config Engine Generates | Runtime Lookup |
|------|----------------|------------------------|----------------|
| Which domains exist | Postgres | Nothing (SQL query) | Postfix → Postgres |
| Which mailboxes exist | Postgres | Nothing (SQL query) | Postfix/Dovecot → Postgres |
| Which aliases exist | Postgres | Nothing (SQL query) | Postfix → Postgres |
| SQL connection config | secrets.yaml | pgsql_*.cf files, dovecot-sql.conf.ext | Postfix/Dovecot read config on start |
| Postfix main.cf directives | config.yaml | main.cf (virtual_transport, TLS, etc.) | Postfix reads on start/reload |
| Dovecot auth config | config.yaml | 10-auth.conf | Dovecot reads on start/reload |
| DKIM signing config | Postgres (domain) + filesystem (keys) | Rspamd dkim_signing.conf | Rspamd reads on start/reload |
| Spam thresholds | Postgres (per-domain) + config.yaml (global) | Rspamd local.d configs | Rspamd reads on start/reload |
| TLS certificates | Traefik / Let's Encrypt | Traefik labels in Compose | Traefik auto-manages |

This table is the definitive reference for "where does this data come from and how does it reach the service?"
