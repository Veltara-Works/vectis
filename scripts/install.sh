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

# --- cosign signature verification (Sigstore keyless) ----------------------
# Defence beyond the same-origin SHA256: the binary is signed in CI using
# GitHub OIDC (no key to manage). When cosign is available we verify the
# signature against the Vectis release-workflow identity and abort on
# failure. When cosign is absent we note it and continue on the checksum.
#   VECTIS_SKIP_COSIGN=1    skip verification entirely
#   VECTIS_REQUIRE_COSIGN=1 make a missing cosign / missing bundle fatal
COSIGN_ID_REGEXP='^https://github\.com/Veltara-Works/vectis/\.github/workflows/release\.yml@refs/tags/'
COSIGN_ISSUER='https://token.actions.githubusercontent.com'

if [ "${VECTIS_SKIP_COSIGN:-0}" = "1" ]; then
    warn "VECTIS_SKIP_COSIGN=1 — skipping cosign signature verification."
elif command -v cosign &>/dev/null; then
    info "Verifying cosign signature (keyless)"
    if curl -fsSL --retry 3 -o "$TMP_DIR/vectis.cosign.bundle" "${BIN_URL}.cosign.bundle"; then
        if cosign verify-blob \
            --bundle "$TMP_DIR/vectis.cosign.bundle" \
            --certificate-identity-regexp "$COSIGN_ID_REGEXP" \
            --certificate-oidc-issuer "$COSIGN_ISSUER" \
            "$TMP_DIR/vectis" >/dev/null 2>&1; then
            info "cosign signature verified"
        else
            error "cosign signature verification FAILED."
            error "The binary's signature does not match the expected Vectis release identity."
            error "Aborting. (Set VECTIS_SKIP_COSIGN=1 to bypass — NOT recommended.)"
            exit 1
        fi
    elif [ "${VECTIS_REQUIRE_COSIGN:-0}" = "1" ]; then
        error "VECTIS_REQUIRE_COSIGN=1 but no cosign bundle found at ${BIN_URL}.cosign.bundle"
        exit 1
    else
        warn "No cosign bundle published for ${VECTIS_VERSION} — relying on SHA256 only."
    fi
elif [ "${VECTIS_REQUIRE_COSIGN:-0}" = "1" ]; then
    error "VECTIS_REQUIRE_COSIGN=1 but cosign is not installed."
    error "Install cosign: https://docs.sigstore.dev/system_config/installation/"
    exit 1
else
    warn "cosign not found — skipping signature verification (SHA256 checksum still enforced)."
    warn "For full supply-chain verification see docs/notes/verifying-downloads.md"
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

# Add the invoking sudo user to the `docker` group so they can run
# `docker ps`, `docker logs`, etc. without prefixing every command with
# `sudo`. Only acts when install.sh was invoked via sudo (real
# non-root operator present) — `curl | sudo bash` exposes the original
# user through $SUDO_USER. Idempotent: usermod -aG is a no-op if the
# user is already in the group. Takes effect on the user's next login
# session (they may need to log out + back in, or `newgrp docker`).
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    if id -nG "$SUDO_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        : # already a member, nothing to do
    else
        info "Adding $SUDO_USER to the 'docker' group (log out + back in for it to take effect)"
        usermod -aG docker "$SUDO_USER" || warn "usermod failed — you'll need to prefix docker commands with sudo"
    fi
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
    DB_SUPER_PASS=$(openssl rand -hex 16)
    DB_API_PASS=$(openssl rand -hex 16)
    DB_PF_PASS=$(openssl rand -hex 16)
    DB_DC_PASS=$(openssl rand -hex 16)
    VK_PASS=$(openssl rand -hex 16)
    ORCH_TOKEN=$(openssl rand -hex 32)
    BACKUP_KEY=$(openssl rand -hex 32)

    sed -i "s/CHANGE_ME_superuser_password/$DB_SUPER_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_api_password/$DB_API_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_postfix_password/$DB_PF_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_dovecot_password/$DB_DC_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_valkey_password/$VK_PASS/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_at_least_32_characters_long_random_string/$API_SECRET/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_orchestrator_bearer_token/$ORCH_TOKEN/" "$CONFIG_DIR/secrets.yaml"
    sed -i "s/CHANGE_ME_backup_key/$BACKUP_KEY/" "$CONFIG_DIR/secrets.yaml"

    # Deliberately leave CHANGE_ME_admin_password alone — `vectis admin init`
    # (during `vectis install`) generates the admin password itself and
    # prints it once in the success banner, BinaryLane-style. Seeding a
    # random value here would hide the password from that banner because
    # admin init would treat the secrets.yaml value as "user-set".

    info "Generated random secrets in $CONFIG_DIR/secrets.yaml"
fi

# --- Hostname + TLS email -------------------------------------------------
#
# Try to save the operator from having to hand-edit config.yaml. Detect the
# public IPv4 and look up its PTR — if the VPS provider has set reverse DNS
# (the recommended prereq), that's the hostname they mean. Fall back to an
# interactive prompt via /dev/tty, or leave the placeholder if we're running
# non-interactively (CI, headless).

config_hostname_value() {
    # Reads the live 'hostname:' value (trimmed, unquoted).
    awk '/^hostname:/ { sub(/^hostname: */,""); gsub(/"/,""); print; exit }' "$CONFIG_DIR/config.yaml"
}

set_config_hostname() {
    # Idempotent: replaces whatever 'hostname:' line currently exists.
    local new="$1"
    sed -i -E "s|^hostname:.*$|hostname: $new|" "$CONFIG_DIR/config.yaml"
}

set_config_tls_email() {
    # Only touch lines where email: already has an address on the right of
    # the colon — there are other `email:` *block* headers in the file
    # (e.g. alerts.email:) that we must not clobber. Trailing `# comment`
    # is preserved.
    local new="$1"
    sed -i -E "s|^(\\s*)email:\\s+[^[:space:]#]+@[^[:space:]#]+(\\s*#.*)?$|\\1email: $new\\2|" "$CONFIG_DIR/config.yaml"
}

set_secrets_admin_email() {
    # Rewrites the `admin_email:` line in secrets.yaml. Only touches lines
    # that already have an address value (not block headers).
    local new="$1"
    sed -i -E "s|^(\\s*)admin_email:\\s+[^[:space:]#]+@[^[:space:]#]+(\\s*#.*)?$|\\1admin_email: $new\\2|" "$CONFIG_DIR/secrets.yaml"
}

current_hostname=$(config_hostname_value)
if [ "$current_hostname" = "mail.example.com" ] || [ -z "$current_hostname" ]; then
    # Public IPv4 detection — best effort, 3s per endpoint.
    PUBLIC_IP=""
    for url in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
        ip=$(curl -fsS --max-time 3 -4 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            PUBLIC_IP="$ip"
            break
        fi
    done

    # Reverse-DNS lookup. Must hit real DNS, not /etc/hosts: cloud-init on
    # most VPS providers writes a line like `<public-ip> <short-hostname>`
    # there, and `getent hosts` would happily return that fiction instead
    # of the actual PTR record set at the provider's panel.
    #
    # Prefer dig/host queried against 1.1.1.1 directly so we bypass both
    # /etc/hosts and any flaky local resolver. Install dnsutils if neither
    # tool is present (Ubuntu Server minimal doesn't ship them). Falling
    # back to getent only happens if the apt install is also unavailable.
    if ! command -v dig &>/dev/null && ! command -v host &>/dev/null; then
        info "Installing dnsutils for PTR lookup..."
        apt-get update -qq 2>/dev/null || true
        if apt-get install -y -qq dnsutils 2>&1 | tail -3; then
            :
        else
            warn "apt-get install dnsutils failed — PTR detection may fall back to /etc/hosts"
        fi
    fi

    DETECTED_FQDN=""
    DETECTED_VIA=""
    if [ -n "$PUBLIC_IP" ]; then
        if command -v dig &>/dev/null; then
            DETECTED_FQDN=$(dig +short +time=2 +tries=1 -x "$PUBLIC_IP" @1.1.1.1 2>/dev/null | sed 's/\.$//' | head -1)
            [ -n "$DETECTED_FQDN" ] && DETECTED_VIA="dig @1.1.1.1"
        fi
        if [ -z "$DETECTED_FQDN" ] && command -v host &>/dev/null; then
            DETECTED_FQDN=$(host "$PUBLIC_IP" 1.1.1.1 2>/dev/null | awk '/pointer/ {print $NF}' | sed 's/\.$//' | head -1)
            [ -n "$DETECTED_FQDN" ] && DETECTED_VIA="host @1.1.1.1"
        fi
        if [ -z "$DETECTED_FQDN" ]; then
            # Last resort — getent reads /etc/hosts first which on most VPSes
            # contains a cloud-init line `<public-ip> <short-hostname>`. Flag
            # the source so the operator knows the default isn't authoritative.
            DETECTED_FQDN=$(getent hosts "$PUBLIC_IP" 2>/dev/null | awk '{print $2}' | head -1)
            [ -n "$DETECTED_FQDN" ] && DETECTED_VIA="getent hosts (may be /etc/hosts entry — verify against your VPS panel)"
        fi
    fi

    # Reject obvious non-answers (IP-shaped strings, single-label names).
    if [[ "$DETECTED_FQDN" =~ ^[0-9.]+$ ]] || ! [[ "$DETECTED_FQDN" == *.* ]]; then
        DETECTED_FQDN=""
    fi

    # Default tls.email to admin@<apex-of-hostname> when we have a hostname.
    DETECTED_EMAIL=""
    if [ -n "$DETECTED_FQDN" ]; then
        # Strip the leftmost label if there are ≥3 labels (mail.foo.com → foo.com),
        # otherwise use the whole FQDN (foo.com → foo.com).
        apex=$(echo "$DETECTED_FQDN" | awk -F. '{
            if (NF >= 3) { for (i=2; i<=NF; i++) printf "%s%s", $i, (i<NF?".":"") }
            else { print $0 }
        }')
        DETECTED_EMAIL="admin@$apex"
    fi

    echo ""
    if [ -n "$PUBLIC_IP" ]; then
        info "Detected public IPv4: $PUBLIC_IP"
    else
        warn "Could not detect public IPv4 — set the hostname manually below."
    fi
    if [ -n "$DETECTED_FQDN" ]; then
        info "Reverse DNS (PTR): $DETECTED_FQDN  [via $DETECTED_VIA]"
    else
        warn "No usable PTR found for this IP — set reverse DNS at your VPS provider for production."
    fi

    # ── Input validators ────────────────────────────────────────────────
    # Both catch the class of fat-finger error that rc25 found: user
    # typing `vectis preflight` at the hostname prompt, script accepting
    # it blind, then deriving `admin@vectis preflight` as the email
    # default. FQDN shape check is the first line of defence; the
    # `vectis install` guardrail is the second.
    #
    # Rules:
    #   - ≥1 dot (so `localhost` is rejected)
    #   - no whitespace
    #   - only letters/digits/hyphen/dot (no `@`, spaces, shell metachars)
    #   - labels can't start/end with hyphen, can't be empty
    is_valid_fqdn() {
        local s="$1"
        [[ "$s" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]
    }

    is_valid_email() {
        local s="$1"
        # local@domain with domain being a valid FQDN. Local part is
        # intentionally permissive (RFC 5322 is vast); we mostly care
        # that there's no whitespace and the domain is FQDN-shaped.
        [[ "$s" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
    }

    # Prompt the operator if we have a TTY. curl | sudo bash redirects stdin
    # to the pipe, so read from /dev/tty explicitly.
    FQDN_INPUT=""
    EMAIL_INPUT=""
    if [ -t 0 ] || [ -e /dev/tty ]; then
        prompt_default="${DETECTED_FQDN:-mail.yourdomain.com}"

        # Re-prompt until the user gives a valid FQDN (or accepts the
        # detected default by pressing Enter).
        while :; do
            read -r -p "Mail server hostname [$prompt_default]: " FQDN_INPUT </dev/tty || true
            FQDN_INPUT="${FQDN_INPUT:-$DETECTED_FQDN}"
            if [ -z "$FQDN_INPUT" ]; then
                warn "Hostname is required. Please enter a fully-qualified domain (e.g. mail.yourdomain.com)."
                continue
            fi
            if ! is_valid_fqdn "$FQDN_INPUT"; then
                warn "'$FQDN_INPUT' is not a valid hostname. An FQDN needs ≥1 dot, no spaces, and only letters/digits/hyphens (e.g. mail.yourdomain.com)."
                continue
            fi
            break
        done

        # Recompute default email from whatever hostname was chosen.
        apex=$(echo "$FQDN_INPUT" | awk -F. '{
            if (NF >= 3) { for (i=2; i<=NF; i++) printf "%s%s", $i, (i<NF?".":"") }
            else { print $0 }
        }')
        email_default="admin@$apex"

        while :; do
            read -r -p "TLS / admin email [$email_default]: " EMAIL_INPUT </dev/tty || true
            EMAIL_INPUT="${EMAIL_INPUT:-$email_default}"
            if ! is_valid_email "$EMAIL_INPUT"; then
                warn "'$EMAIL_INPUT' is not a valid email address. Must be local@domain with no spaces (e.g. admin@yourdomain.com)."
                continue
            fi
            break
        done

        # Read-back confirmation before writing to config files. Catches
        # the shape-valid-but-wrong case (e.g. user typed mail.example.com
        # when they meant mail.vectismail.com). Default Y → one keystroke
        # happy path.
        echo ""
        echo "  About to write:"
        echo "    hostname:    $FQDN_INPUT"
        echo "    tls.email:   $EMAIL_INPUT"
        echo "    admin_email: $EMAIL_INPUT"
        echo ""
        CONFIRM=""
        read -r -p "Proceed? [Y/n]: " CONFIRM </dev/tty || true
        case "${CONFIRM,,}" in
            ""|y|yes) ;;  # happy path
            *)
                warn "Aborted by user. Re-run the installer when you're ready."
                exit 1
                ;;
        esac
    else
        # Non-interactive: only write what we detected; leave placeholder
        # otherwise so `vectis install`'s guardrail catches it. Still
        # validate so we don't write garbage in automated contexts.
        FQDN_INPUT="$DETECTED_FQDN"
        EMAIL_INPUT="$DETECTED_EMAIL"
        if [ -n "$FQDN_INPUT" ] && ! is_valid_fqdn "$FQDN_INPUT"; then
            warn "Detected FQDN '$FQDN_INPUT' is not valid — leaving placeholder for vectis install to flag."
            FQDN_INPUT=""
        fi
        if [ -n "$EMAIL_INPUT" ] && ! is_valid_email "$EMAIL_INPUT"; then
            warn "Derived email '$EMAIL_INPUT' is not valid — leaving placeholder for vectis install to flag."
            EMAIL_INPUT=""
        fi
    fi

    if [ -n "$FQDN_INPUT" ]; then
        set_config_hostname "$FQDN_INPUT"
        info "Set hostname → $FQDN_INPUT in $CONFIG_DIR/config.yaml"
    fi
    if [ -n "$EMAIL_INPUT" ]; then
        set_config_tls_email "$EMAIL_INPUT"
        set_secrets_admin_email "$EMAIL_INPUT"
        info "Set tls.email + admin_email → $EMAIL_INPUT"
    fi
fi

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN} Vectis downloaded successfully${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo "  The binary is in place but nothing is running yet. Next steps:"
echo ""
current_hostname=$(config_hostname_value)
if [ "$current_hostname" = "mail.example.com" ] || [ -z "$current_hostname" ]; then
    echo "    1. Edit $CONFIG_DIR/config.yaml"
    echo "         - set 'hostname' to your mail server's FQDN"
    echo "         - set 'tls.email' to your admin email"
    echo ""
    echo "    2. vectis preflight    # verify system + ports + DNS"
    echo "    3. vectis install      # deploy containers, run migrations, create admin"
else
    echo "    1. Review $CONFIG_DIR/config.yaml (hostname: $current_hostname)"
    echo "    2. vectis preflight    # verify system + ports + DNS"
    echo "    3. vectis install      # deploy containers, run migrations, create admin"
fi
echo ""
echo "  Config directory: $CONFIG_DIR"
echo "  Docs:             https://vectismail.com/getting-started/installation"
echo ""
