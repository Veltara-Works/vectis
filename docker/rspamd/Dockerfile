FROM alpine:3.23

RUN apk add --no-cache \
    rspamd \
    rspamd-controller \
    rspamd-proxy \
    ca-certificates \
    curl

# Config will be bind-mounted from generated configs
VOLUME ["/etc/rspamd/local.d", "/var/vectis/dkim"]

# Milter port for Postfix, controller for management
EXPOSE 11332 11334

COPY docker/rspamd/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Healthcheck via the controller HTTP endpoint (port 11334)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
    CMD curl -sf http://localhost:11334/ping || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["rspamd", "-f", "-u", "rspamd", "-g", "rspamd"]
