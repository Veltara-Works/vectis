FROM alpine:3.24

RUN apk add --no-cache \
    rspamd \
    rspamd-controller \
    rspamd-proxy \
    ca-certificates \
    curl \
    unbound

# Config will be bind-mounted from generated configs
VOLUME ["/etc/rspamd/local.d", "/var/vectis/dkim"]

# Milter port for Postfix, controller for management
EXPOSE 11332 11334

# Static image config: module switches for Redis-dependent modules we do not
# run (neural, url_redirector) and the DNS override that points rspamd at the
# bundled resolver (options.inc). override.d, not local.d: local.d is a VOLUME
# and is populated by bind mounts from the config engine.
COPY docker/rspamd/override.d/ /etc/rspamd/override.d/
# Bundled recursion-only resolver for rspamd's DNS (ADR-026, #258).
COPY docker/rspamd/unbound.conf /etc/unbound/unbound.conf
COPY docker/rspamd/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Healthcheck via the controller HTTP endpoint (port 11334)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
    CMD curl -sf http://localhost:11334/ping && { [ "$VECTIS_RSPAMD_LOCAL_RESOLVER" = "false" ] || nslookup health.vectis.internal 127.0.0.1 >/dev/null; } || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["rspamd", "-f", "-u", "rspamd", "-g", "rspamd"]
