#!/bin/sh
# acme.sh deploy hook for Vectis mail TLS certificates.
# Called by acme.sh after successful cert issuance/renewal.
# Copies certs to the shared mail-certs volume and signals Postfix/Dovecot.
#
# Environment variables set by acme.sh:
#   DOMAIN_PATH    — path to the cert directory
#   Le_Domain      — the domain name
#   Le_RealCertPath etc. — paths to the actual cert files

set -e

MAIL_CERT_DIR="/etc/ssl/mail"

echo "[vectis-acme] Deploying mail TLS certs for ${Le_Domain}"

# Copy cert files to the shared mail cert volume.
cp "${Le_RealFullChainPath}" "${MAIL_CERT_DIR}/fullchain.pem"
cp "${Le_RealKeyPath}" "${MAIL_CERT_DIR}/privkey.pem"

# Set permissions readable by mail services (vmail uid 5000).
chmod 644 "${MAIL_CERT_DIR}/fullchain.pem"
chmod 640 "${MAIL_CERT_DIR}/privkey.pem"

echo "[vectis-acme] Certs deployed to ${MAIL_CERT_DIR}"

# Signal Postfix and Dovecot to reload TLS certs.
# They share the Docker network so we can use the container names.
# Postfix: send SIGHUP to master process
if command -v docker >/dev/null 2>&1; then
    docker kill --signal=HUP vectis-postfix 2>/dev/null || true
    docker kill --signal=HUP vectis-dovecot 2>/dev/null || true
    echo "[vectis-acme] Signaled Postfix and Dovecot to reload TLS"
fi

echo "[vectis-acme] Deploy complete"
