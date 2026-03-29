# G. Container Networking Topology

**Status:** DRAFT — For review with Copilot before integration into Spec v1.1  
**Prepared by:** Claude (round 5)  
**Complements:** Vectis Architecture v1.3, Implementation Spec v1.0

---

## G.1 Overview

Vectis uses Docker Compose named networks to control which containers can communicate with each other. This follows the principle of least privilege: a container should only be able to reach the services it actually needs.

The config engine generates the network definitions in `docker-compose.yml`. All networks are internal Docker bridge networks (not exposed to the host network) except where port mapping is required.

---

## G.2 Network Definitions

| Network | Purpose | Type |
|---------|---------|------|
| `vectis-frontend` | Web-facing traffic (Traefik ↔ UI, API) | bridge, internal |
| `vectis-mail` | Mail service communication | bridge, internal |
| `vectis-data` | Database and cache access | bridge, internal |
| `vectis-orchestrator` | Orchestrator control plane | bridge, internal |

### Docker Compose network configuration

```yaml
networks:
  vectis-frontend:
    driver: bridge
    internal: false  # Traefik needs external access for ACME challenges
  vectis-mail:
    driver: bridge
    internal: true
  vectis-data:
    driver: bridge
    internal: true
  vectis-orchestrator:
    driver: bridge
    internal: true
```

Note: `vectis-frontend` is the only non-internal network because Traefik needs to reach the internet for Let's Encrypt ACME challenges and to accept incoming HTTP/HTTPS connections.

---

## G.3 Container Network Membership

| Container | vectis-frontend | vectis-mail | vectis-data | vectis-orchestrator |
|-----------|:-:|:-:|:-:|:-:|
| Traefik | ✓ | | | |
| Admin UI | ✓ | | | |
| Go API | ✓ | | ✓ | ✓ |
| Postfix | | ✓ | ✓ | |
| Dovecot | | ✓ | ✓ | |
| Rspamd | | ✓ | ✓ | |
| ClamAV | | ✓ | | |
| Postgres | | | ✓ | |
| Valkey | | | ✓ | |
| acme.sh | ✓ | | | |
| Orchestrator | | | ✓ | ✓ |
| ValidonX Agent | | | ✓ | |

---

## G.4 Connectivity Matrix

This matrix shows which containers can reach which. "✓" means the two containers share at least one network and can communicate. Blank means no direct network path.

| | Traefik | UI | API | Postfix | Dovecot | Rspamd | ClamAV | Postgres | Valkey | Orch. | ValidonX |
|-|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **Traefik** | — | ✓ | ✓ | | | | | | | | |
| **Admin UI** | ✓ | — | | | | | | | | | |
| **Go API** | ✓ | | — | | | | | ✓ | ✓ | ✓ | |
| **Postfix** | | | | — | ✓ | ✓ | ✓ | ✓ | | | |
| **Dovecot** | | | | ✓ | — | | | ✓ | | | |
| **Rspamd** | | | | ✓ | | — | ✓ | | ✓ | | |
| **ClamAV** | | | | ✓ | | ✓ | — | | | | |
| **Postgres** | | | ✓ | ✓ | ✓ | | | — | | | ✓ |
| **Valkey** | | | ✓ | | | ✓ | | | — | | |
| **Orch.** | | | ✓ | | | | | ✓ | ✓ | — | |
| **ValidonX** | | | | | | | | ✓ | | | — |

---

## G.5 Design Rationale

### Why Admin UI cannot reach Postgres or Valkey

The Admin UI is a React SPA served as static files. It communicates exclusively with the Go API via HTTP. There is no reason for the UI container to have network access to the database or cache. If the UI container were compromised (e.g., via a supply chain attack on an npm dependency), the blast radius is limited to what the UI can do through the API — which is authenticated and rate-limited.

### Why the Orchestrator requires data network access

The orchestrator requires `vectis-data` network access for Postgres advisory locks, crash recovery state queries, and `pg_dump`/`psql` snapshot operations. This is an acknowledged deviation from the original isolation design — the orchestrator's database access is limited to these operational functions and does not access mail entity data.

Specifically, the orchestrator connects to Postgres for:
- **Advisory lock** (`pg_advisory_lock(1)`): Ensures mutual exclusion during apply/rollback operations
- **Crash recovery**: On restart, checks `orchestrator_history` for orphaned `running` status and marks as `failed`
- **Snapshots**: Runs `pg_dump` before every apply and `psql` for rollback restore
- **State persistence**: Records operation history in `orchestrator_history` table

The orchestrator does not access mail entity tables (domains, mailboxes, aliases) or authentication tables (admins, sessions). Bearer token authentication on the internal API provides an additional security layer.

### Why Postfix reaches Postgres directly

Postfix queries Postgres for virtual domain, mailbox, and alias lookups on every mail delivery (see Section C). This is a direct SQL connection using a read-only database user (`vectis_postfix`). Routing these queries through the Go API would add latency to every mail delivery and create a single point of failure — if the API is down, mail delivery would stop.

### Why Dovecot reaches Postgres directly

Same rationale as Postfix. Dovecot queries Postgres for user authentication and mailbox location on every IMAP/POP3 connection. Using a read-only database user (`vectis_dovecot`).

### Why Rspamd reaches Valkey

Rspamd uses Valkey for several purposes:
- Bayes classifier training data
- Neural network model state
- Rate limiting counters
- Greylisting data
- Fuzzy hash storage

This data is stored in Valkey DB 0 (cache) and is ephemeral — losing it degrades spam detection temporarily but doesn't break mail flow.

### Why ClamAV is isolated to the mail network

ClamAV only needs to communicate with Rspamd (which passes messages to ClamAV for scanning) and Postfix (milter protocol). ClamAV does not need database access, cache access, or API access. Its signature updates are fetched directly from the internet by the freshclam process inside the container.

Note: If ClamAV uses the `none` profile, the container is omitted entirely from the Compose file, and Rspamd is configured to skip virus scanning.

### Why ValidonX Agent reaches Postgres

The ValidonX licensing agent needs to store license state and entitlement data. In Phase 1, it uses the Vectis Postgres database (with its own schema or dedicated tables). It does not need access to the mail network, API, or orchestrator. If ValidonX is unreachable, the agent uses cached entitlement data from Postgres (see 30-day grace period in Architecture v1.3 §15).

---

## G.6 Port Mapping (Host ↔ Container)

Only specific containers have ports mapped to the host:

| Container | Host Port | Container Port | Protocol | Notes |
|-----------|-----------|---------------|----------|-------|
| Traefik | 80 | 80 | TCP (HTTP) | HTTP → HTTPS redirect + ACME challenges |
| Traefik | 443 | 443 | TCP (HTTPS) | Admin UI + API (TLS terminated by Traefik) |
| Postfix | 25 | 25 | TCP (SMTP) | Inbound mail (direct mapping, not via Traefik) |
| Postfix | 465 | 465 | TCP (SMTPS) | Implicit TLS submission |
| Postfix | 587 | 587 | TCP (Submission) | STARTTLS submission |
| Dovecot | 993 | 993 | TCP (IMAPS) | IMAP over TLS (direct mapping, not via Traefik) |
| Dovecot | 995 | 995 | TCP (POP3S) | POP3 over TLS (direct mapping, not via Traefik) |

No other containers have host port mappings. All inter-container communication uses Docker DNS (service names as hostnames on shared networks).

### Why mail ports are direct-mapped (not via Traefik)

As established in Architecture v1.3 §3.3:
- HTTP/HTTPS → via Traefik (TLS termination, routing, rate limiting)
- SMTP/IMAP/POP3 → direct Docker port mapping

Mail protocols handle their own TLS (STARTTLS for SMTP, implicit TLS for IMAPS/POP3S/SMTPS). Routing them through Traefik would add complexity (TCP passthrough configuration, STARTTLS handling gotchas) without meaningful benefit in Phase 1.

---

## G.7 IPv6 Considerations

All networks support IPv6 if the Docker daemon is configured with IPv6 support (handled by the installer):

```json
// /etc/docker/daemon.json (generated by installer)
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80",
  "experimental": true,
  "ip6tables": true
}
```

Host port mappings bind to both IPv4 and IPv6 by default (Docker's default behaviour when the daemon has IPv6 enabled).

---

## G.8 Future Clustering Considerations

The current network topology is designed for single-node deployment. For Phase 3 clustering:

- Docker overlay networks will replace bridge networks for cross-node communication
- Traefik will use Docker Swarm or Kubernetes service discovery
- Postgres may move to a separate node (connection via overlay network or external address)
- Valkey may need a dedicated overlay network segment for replication traffic

The current network names and segmentation strategy (frontend / mail / data / orchestrator) will carry forward into the clustered topology. The separation of concerns doesn't change — only the network driver changes from bridge to overlay.

---

## G.9 Docker Compose Network Example

For reference, here's how the networks appear in the generated `docker-compose.yml`:

```yaml
services:
  traefik:
    networks:
      - vectis-frontend
    ports:
      - "80:80"
      - "443:443"

  admin-ui:
    networks:
      - vectis-frontend

  api:
    networks:
      - vectis-frontend
      - vectis-data
      - vectis-orchestrator

  postfix:
    networks:
      - vectis-mail
      - vectis-data
    ports:
      - "25:25"
      - "465:465"
      - "587:587"

  dovecot:
    networks:
      - vectis-mail
      - vectis-data
    ports:
      - "993:993"
      - "995:995"

  rspamd:
    networks:
      - vectis-mail
      - vectis-data

  clamav:
    networks:
      - vectis-mail

  postgres:
    networks:
      - vectis-data

  valkey:
    networks:
      - vectis-data

  orchestrator:
    networks:
      - vectis-orchestrator
      - vectis-data          # Required for pg_dump, advisory locks, crash recovery
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  validonx-agent:
    networks:
      - vectis-data
```

This is a simplified illustration — the actual generated Compose file will include resource limits, health checks, Traefik labels, environment variables, volume mounts, and other configuration from the config engine.
