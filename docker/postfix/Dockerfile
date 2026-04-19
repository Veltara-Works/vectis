FROM alpine:3.21

RUN apk add --no-cache \
    postfix \
    postfix-pgsql \
    ca-certificates \
    curl \
 # Remove any pre-existing vmail user/group the postfix-pgsql package may
 # have created at a system UID (~100). We need vmail at numeric UID 5000
 # so the on-disk ownership matches the dovecot container (mail_uid=5000).
 # If we don't force this, every file touched by vmail inside this container
 # lands at a different uid from dovecot, and Dovecot LMTP can't traverse
 # the maildir → 451 errors on delivery.
 && (deluser vmail 2>/dev/null || true) \
 && (delgroup vmail 2>/dev/null || true) \
 && addgroup -g 5000 vmail \
 && adduser -D -u 5000 -G vmail -h /var/vectis/mail vmail

# Create required directories
RUN mkdir -p /var/vectis/mail && chown 5000:5000 /var/vectis/mail \
 && mkdir -p /var/log/postfix && chown postfix:postfix /var/log/postfix

# Config will be bind-mounted from generated configs
VOLUME ["/etc/postfix", "/var/vectis/mail", "/etc/ssl/mail", "/var/log/postfix"]

EXPOSE 25 465 587

# Postfix needs to run in foreground
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD postfix status || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postfix", "start-fg"]
