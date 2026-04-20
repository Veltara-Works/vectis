#!/bin/bash
# Vectis Mail Server — Quick Installer
# Downloads the Vectis binary, bootstraps Docker, and prepares config directories.
#
# Usage:
#   curl -fsSL https://get.vectismail.com | sudo bash
#   curl -fsSL https://dl.vectismail.com/latest/install.sh | sudo bash
#   VECTIS_VERSION=v0.1.0 bash install.sh

set -euo pipefail

VECTIS_VERSION="${VECTIS_VERSION:-latest}"
VECTIS_DOWNLOAD_BASE="${VECTIS_DOWNLOAD_BASE:-https://dl.vectismail.com}"
VECTIS_BIN_DEST="${VECTIS_BIN_DEST:-/usr/local/bin/vectis}"
VECTIS_DIR="/opt/vectis"
CONFIG_DIR="/etc/vectis"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (or with sudo)."
    exit 1
fi

info "Vectis Mail Server Installer"
echo ""

# --- OS + arch checks -------------------------------------------------------

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        warn "Vectis is tested on Ubuntu 24.04 LTS. Your OS: $PRETTY_NAME"
    fi
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) BIN_ARCH="amd64" ;;
    *) error "Unsupported architecture: $ARCH (only linux/amd64 is published)"; exit 1 ;;
esac

# --- Download + verify binary ----------------------------------------------

BIN_URL="${VECTIS_DOWNLOAD_BASE}/${VECTIS_VERSION}/vectis-linux-${BIN_ARCH}"
SHA_URL="${BIN_URL}.sha256"

info "Downloading Vectis binary (${VECTIS_VERSION}) from ${BIN_URL}"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fsSL --retry 3 -o "$TMP_DIR/vectis" "$BIN_URL" \
    || { error "Failed to download binary. Check $BIN_URL"; exit 1; }
curl -fsSL --retry 3 -o "$TMP_DIR/vectis.sha256" "$SHA_URL" \
    || { error "Failed to download checksum. Check $SHA_URL"; exit 1; }

info "Verifying SHA256 checksum"
EXPECTED=$(awk '{print $1}' "$TMP_DIR/vectis.sha256")
ACTUAL=$(sha256sum "$TMP_DIR/vectis" | awk '{print $1}')
if [ "$EXPECTED" != "$ACTUAL" ]; then
    error "Checksum mismatch!"
    error "  expected: $EXPECTED"
    error "  got:      $ACTUAL"
    exit 1
fi

install -m 0755 "$TMP_DIR/vectis" "$VECTIS_BIN_DEST"
info "Installed $($VECTIS_BIN_DEST version) → $VECTIS_BIN_DEST"

# --- Docker -----------------------------------------------------------------

if ! command -v docker &>/dev/null; then
    info "Installing Docker Engine..."
    curl -fsSL https://get.docker.com | bash
    systemctl enable docker
    systemctl start docker
    info "Docker installed."
else
    info "Docker already installed: $(docker --version)"
fi

if ! docker compose version &>/dev/null; then
    error "Docker Compose plugin not found. Install it with:"
    error "  apt-get install docker-compose-plugin"
    exit 1
fi

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

# --- Directories + configs --------------------------------------------------

info "Creating Vectis directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p /var/vectis/{mail,dkim,backups,snapshots,certs,generated}
mkdir -p "$VECTIS_DIR"

# Fetch example configs published alongside the binary.
EXAMPLES_BASE="${VECTIS_DOWNLOAD_BASE}/${VECTIS_VERSION}"
for example in config.yaml.example secrets.yaml.example; do
    if [ ! -f "$VECTIS_DIR/$example" ]; then
        curl -fsSL --retry 3 -o "$VECTIS_DIR/$example" "$EXAMPLES_BASE/$example" \
            || { error "Failed to download $example from $EXAMPLES_BASE"; exit 1; }
    fi
done

if [ -f "$VECTIS_DIR/config.yaml.example" ] && [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cp "$VECTIS_DIR/config.yaml.example" "$CONFIG_DIR/config.yaml"
    info "Copied config.yaml.example → $CONFIG_DIR/config.yaml (edit hostname before 'vectis install')"
fi

if [ -f "$VECTIS_DIR/secrets.yaml.example" ] && [ ! -f "$CONFIG_DIR/secrets.yaml" ]; then
    cp "$VECTIS_DIR/secrets.yaml.example" "$CONFIG_DIR/secrets.yaml"
    chmod 600 "$CONFIG_DIR/secrets.yaml"

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

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN} Vectis downloaded successfully${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo "  The binary is in place but nothing is running yet. Next steps:"
echo ""
echo "    1. Edit $CONFIG_DIR/config.yaml"
echo "         - set 'hostname' to your mail server's FQDN"
echo "         - set 'tls.email' to your admin email"
echo ""
echo "    2. vectis preflight    # verify system + ports + DNS"
echo "    3. vectis install      # deploy containers, run migrations, create admin"
echo ""
echo "  Config directory: $CONFIG_DIR"
echo "  Docs:             https://vectismail.com/getting-started/installation"
echo ""
