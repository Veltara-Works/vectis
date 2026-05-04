#!/bin/sh
# Vectis: make the upstream-generated config.docker.inc.php include our
# config.vectis.inc.php (bind-mounted by the compose template). Adds the
# include line idempotently — safe on every container start.
set -e

DOCKER_CFG=/var/www/html/config/config.docker.inc.php

if [ ! -f "$DOCKER_CFG" ]; then
  # First boot before upstream's create_docker_config task ran; nothing to do.
  exit 0
fi

if grep -q "config.vectis.inc.php" "$DOCKER_CFG"; then
  # Already wired.
  exit 0
fi

cat >> "$DOCKER_CFG" <<'PHP'

// Vectis per-install overrides (bind-mounted by docker-compose).
if (file_exists(__DIR__ . '/config.vectis.inc.php')) {
    include __DIR__ . '/config.vectis.inc.php';
}
PHP
