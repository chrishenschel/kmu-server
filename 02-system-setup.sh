#!/bin/bash

# --- Formatting ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file optional: set LOG_FILE to a path to append logs, or leave unset to only print
LOG_FILE="${LOG_FILE:-/dev/null}"

log() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1" | tee -a "$LOG_FILE" >&2
}

# Usage: ./02-system-setup.sh [domain] [username] [fullname] [password] [email]
# Values can be provided as positional arguments or will be prompted interactively.
domain="${1:-}"
username="${2:-}"
userfullname="${3:-}"
password="${4:-}"
email="${5:-}"

[ -z "$domain" ]       && read -p "Enter domain (example.com): " domain
[ -z "$username" ]     && read -p "Enter username: (mmustermann) " username
[ -z "$userfullname" ] && read -p "Enter Full Name (Max Mustermann): " userfullname
[ -z "$password" ]     && read -p "Enter password: " password
[ -z "$email" ]        && read -p "Enter email: " email

### --- Base env, Synapse, blueprints, and Jitsi setup ---
. ./scripts/setup-env-and-config.sh

log "Bringing up full stack (including Jitsi)..."
# Export image/version variables from .env.versions so docker compose
# can resolve image placeholders like ${CADDY_IMAGE}, ${IMMICH_SERVER_IMAGE}, etc.
if [ -f .env.versions ]; then
  set -a
  # shellcheck source=/dev/null
  . ./.env.versions
  set +a
fi
docker compose up -d --remove-orphans

### --- POST-DEPLOY: Paperless, Stalwart, Nextcloud, Immich ---
. ./scripts/post-deploy-apps.sh

### --- Diun: Matrix bot user + room (fully automated) ---
. ./scripts/post-deploy-matrix-diun.sh
log "Restarting Diun..."
docker compose down diun
docker compose up -d diun

### --- DNS Records ---

log "Fetching recommended DNS records from Stalwart..."
DNS_CONFIG_WRITTEN=false
for attempt in 1 2 3 4 5; do
    DNS_JSON=$(curl -ks -u "admin:$password" "$STALWART_URL/api/dns/records/$domain" 2>&1)
    if echo "$DNS_JSON" | python3 -c "import sys,json; json.load(sys.stdin)['data']" >/dev/null 2>&1; then
        {
            echo ""
            echo "============================================"
            echo "  DNS RECORDS TO ADD FOR $domain"
            echo "============================================"
            echo ""
            echo "1. MX Record:"
            echo "   Type: MX | Host: @ | Value: mail.$domain | Priority: 10"
            echo ""
            echo "$DNS_JSON" | python3 -c "
import sys, json
records = json.load(sys.stdin)['data']
i = 2
for r in records:
    if r['type'] == 'MX' or r['type'] == 'CNAME':
        continue
    print(f\"{i}. {r['type']} Record:\")
    print(f\"   Type: {r['type']} | Host: {r['name'].rstrip('.')} | Value: {r['content']}\")
    print()
    i += 1
"
            echo "============================================"
        } | tee dns-config.txt
        DNS_CONFIG_WRITTEN=true
        success "DNS records written to dns-config.txt"
        break
    fi
    if [ "$attempt" -lt 5 ]; then
        log "  Attempt $attempt - Stalwart DNS API not ready yet, retrying in 5s..."
        sleep 5
    fi
done

if [ "$DNS_CONFIG_WRITTEN" != "true" ]; then
    log "Could not fetch DNS records from Stalwart API; writing fallback dns-config.txt with essential records."
    {
        echo ""
        echo "============================================"
        echo "  DNS RECORDS TO ADD FOR $domain (fallback)"
        echo "============================================"
        echo ""
        echo "Stalwart API did not return full DNS data. Add at least:"
        echo ""
        echo "1. MX Record:"
        echo "   Type: MX | Host: @ | Value: mail.$domain | Priority: 10"
        echo ""
        echo "2. Get DKIM, SPF, and DMARC from Stalwart:"
        echo "   Open https://mail.$domain → sign in as admin → manage domain → DNS / DKIM"
        echo ""
        echo "============================================"
    } | tee dns-config.txt
    success "Fallback DNS instructions written to dns-config.txt"
fi

success "Setup complete! All services are running."
success "User sync container will automatically provision Stalwart mailboxes for new Authentik users."
