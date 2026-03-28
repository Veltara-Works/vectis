FROM alpine:3.21

RUN apk add --no-cache \
    dovecot \
    dovecot-lmtpd \
    dovecot-pop3d \
    dovecot-pigeonhole-plugin \
    dovecot-sql \
    dovecot-pgsql \
    ca-certificates \
    && (addgroup -g 5000 vmail 2>/dev/null || true) \
    && (adduser -D -u 5000 -G vmail -h /var/vectis/mail vmail 2>/dev/null || true)

# Create required directories
RUN mkdir -p /var/vectis/mail && chown vmail:vmail /var/vectis/mail

# Config will be bind-mounted from generated configs
VOLUME ["/etc/dovecot", "/var/vectis/mail", "/etc/ssl/mail"]

# IMAP(S), POP3(S), LMTP, SASL auth for Postfix
EXPOSE 993 995 24 12345

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD doveadm service status 2>/dev/null || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["dovecot", "-F"]
