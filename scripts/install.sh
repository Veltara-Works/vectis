#!/bin/bash
# Vectis Mail Server — Quick Installer
# Downloads the Vectis binary and runs the installation.
#
# Usage: curl -fsSL https://get.vectismail.com | bash
# Or:    bash install.sh

set -euo pipefail

VECTIS_VERSION="${VECTIS_VERSION:-latest}"
VECTIS_DIR="/opt/vectis"
CONFIG_DIR="/etc/vectis"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Check running as root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (or with sudo)."
    exit 1
fi

info "Vectis Mail Server Installer"
echo ""

# Check OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        warn "Vectis is tested on Ubuntu 24.04 LTS. Your OS: $PRETTY_NAME"
    fi
fi

# Install Docker if not present
if ! command -v docker &>/dev/null; then
    info "Installing Docker Engine..."
    curl -fsSL https://get.docker.com | bash
    systemctl enable docker
    systemctl start docker
    info "Docker installed."
else
    info "Docker already installed: $(docker --version)"
fi

# Check Docker Compose
if ! docker compose version &>/dev/null; then
    error "Docker Compose plugin not found. Install it with:"
    error "  apt-get install docker-compose-plugin"
    exit 1
fi

# Configure Docker for IPv6 and log rotation
DAEMON_JSON="/etc/docker/daemon.json"
if [ ! -f "$DAEMON_JSON" ]; then
    info "Configuring Docker daemon (log rotation, IPv6)..."
    cat > "$DAEMON_JSON" <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "5"
  },
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80",
  "ip6tables": true
}
EOF
    systemctl restart docker
fi

# Create directories
info "Creating Vectis directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p /var/vectis/{mail,dkim,backups,snapshots,certs,generated}

# Copy example configs if not present
if [ ! -f "$CONFIG_DIR/config.yaml" ] && [ -f "$VECTIS_DIR/config.yaml.example" ]; then
    cp "$VECTIS_DIR/config.yaml.example" "$CONFIG_DIR/config.yaml"
    info "Copied config.yaml.example to $CONFIG_DIR/config.yaml — edit it before running 'vectis install'"
fi

if [ ! -f "$CONFIG_DIR/secrets.yaml" ] && [ -f "$VECTIS_DIR/secrets.yaml.example" ]; then
    cp "$VECTIS_DIR/secrets.yaml.example" "$CONFIG_DIR/secrets.yaml"
    chmod 600 "$CONFIG_DIR/secrets.yaml"

    # Generate random secrets
    API_SECRET=$(openssl rand -hex 32)
    ADMIN_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    DB_API_PASS=$(openssl rand -hex 16)
    DB_PF_PASS=$(openssl rand -hex 16)
    DB_DC_PASS=$(openssl rand -hex 16)
    VK_PASS=$(openssl rand -hex 16)
    ORCH_TOKEN=$(openssl rand -hex 32)
    BACKUP_KEY=$(openssl rand -hex 32)

    sed -i "s/CHANGE_ME_api_password/$DB_API_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_postfix_password/$DB_PF_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_dovecot_password/$DB_DC_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_valkey_password/$VK_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_at_least_32_characters_long_random_string/$API_SECRET/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_admin_password/$ADMIN_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_orchestrator_bearer_token/$ORCH_TOKEN/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_backup_key/$BACKUP_KEY/" "$CONFIG_DIR/secrets.yaml"

    info "Generated random secrets in $CONFIG_DIR/secrets.yaml"
fi

info ""
info "Vectis directories and configs are ready."
info ""
info "Next steps:"
info "  1. Edit $CONFIG_DIR/config.yaml (set your hostname)"
info "  2. Edit $CONFIG_DIR/secrets.yaml (review generated secrets)"
info "  3. Run: vectis preflight"
info "  4. Run: vectis install"
