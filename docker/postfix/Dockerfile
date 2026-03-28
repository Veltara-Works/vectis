FROM alpine:3.21

RUN apk add --no-cache \
    postfix \
    postfix-pgsql \
    ca-certificates \
    && (addgroup -g 5000 vmail 2>/dev/null || true) \
    && (adduser -D -u 5000 -G vmail -h /var/vectis/mail vmail 2>/dev/null || true)

# Create required directories
RUN mkdir -p /var/vectis/mail && chown vmail:vmail /var/vectis/mail

# Config will be bind-mounted from generated configs
VOLUME ["/etc/postfix", "/var/vectis/mail", "/etc/ssl/mail"]

EXPOSE 25 465 587

# Postfix needs to run in foreground
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD postfix status || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postfix", "start-fg"]
