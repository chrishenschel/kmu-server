#!/bin/bash

# --- Formatting ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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


PG_PASS="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 48)"
AUTHENTIK_BOOTSTRAP_PASSWORD="$(openssl rand -base64 60 | tr -d '\n')"
AUTHENTIK_BOOTSTRAP_TOKEN="$(openssl rand -base64 60 | tr -d '\n')"
AUTHENTIK_BOOTSTRAP_EMAIL="hostmaster@$domain"
AUTHENTIK_SECRET_KEY=$(openssl rand -base64 60 | tr -d '\n')


# Generate environment variables
echo "PG_PASS=$PG_PASS" >> .env
echo "AUTHENTIK_SECRET_KEY=$AUTHENTIK_SECRET_KEY" >> .env
echo "AUTHENTIK_BOOTSTRAP_PASSWORD=$AUTHENTIK_BOOTSTRAP_PASSWORD" >> .env
echo "AUTHENTIK_BOOTSTRAP_TOKEN=$AUTHENTIK_BOOTSTRAP_TOKEN" >> .env
echo "AUTHENTIK_BOOTSTRAP_EMAIL=$AUTHENTIK_BOOTSTRAP_EMAIL" >> .env
echo "DOMAIN=$domain" >> .env
echo "USERNAME=$username" >> .env
echo "USERFULLNAME=$userfullname" >> .env
echo "PASSWORD=$password" >> .env

# PASSWORD_HASH=$(python3 -c '
# import hashlib, base64, secrets, sys
# password = sys.argv[1]
# salt = secrets.token_urlsafe(12)
# iterations = 600000
# dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
# b64_hash = base64.b64encode(dk).decode("ascii").strip()
# print(f"pbkdf2_sha256${iterations}${salt}${b64_hash}")
# ' "$password")

# DOCKER_SAFE_HASH="${PASSWORD_HASH//$/$$}"
# to fix the $ treated as variable 
# echo "PASSWORD_HASH=$DOCKER_SAFE_HASH" >> .env
# echo "PASSWORD_HASH=$PASSWORD_HASH" >> .env

docker network create caddy-proxy
docker network create database

# Generate Synapse config
docker run -it --rm \
    --mount type=volume,src=infra_synapse_data,dst=/data \
    -e SYNAPSE_SERVER_NAME=$domain \
    -e SYNAPSE_REPORT_STATS=no ghcr.io/element-hq/synapse:latest generate

cp /var/lib/docker/volumes/infra_synapse_data/_data/$domain.log.config ./synapse/data/$domain.log.config
cp /var/lib/docker/volumes/infra_synapse_data/_data/$domain.signing.key ./synapse/data/$domain.signing.key
cp /var/lib/docker/volumes/infra_synapse_data/_data/homeserver.yaml ./synapse/data/homeserver.yaml
chown 991:991 ./synapse/data/$domain.signing.key

# yq -iy \
#   --arg user "$username" \
#   --arg name "$userfullname" \
#   --arg email "$email" \
#   --arg pwd "$PASSWORD_HASH" \
#   --arg domain "$domain" \
#   '
#   .metadata.name = $domain+" Initial User Creation" |
#   .entries[0].identifiers.username = $user |
#   .entries[0].attrs.name = $name |
#   .entries[0].attrs.email = $email |
#   .entries[0].attrs.password = $pwd
#   ' ./authentik/blueprints/admin-user.yaml

sed -i \
    -e "s|__DOMAIN__|$domain|g" \
    "./caddy/Caddyfile"

sed -i \
    -e "s|__DOMAIN__|$domain|g" \
    -e "s|__USER__|$username|g" \
    -e "s|__NAME__|$userfullname|g" \
    -e "s|__EMAIL__|$email|g" \
    -e "s|__PASSWORD_HASH__|$password|g" \
    "./authentik/blueprints/admin-user.yaml"


yq -iy --arg pass "$PG_PASS" --arg baseurl "https://matrix.$domain" '
  .public_baseurl = $baseurl |
  .database.name = "psycopg2" |
  .database.allow_unsafe_locale = true |  
  .database.args.host = "postgres" |
  .database.args.user = "postgres" |
  .database.args.password = $pass |
  .database.args.database = "matrix" |
  .database.args.port = 5432 |
  .database.args.cp_min = 5 |
  .database.args.cp_max = 10 |  
  .media_store_path = "/data/media_store" |
  .max_upload_size = "50M" |
  .enable_registration = false |
  .enable_registration_without_verification = false |
  .rc_message.per_second = 0.2 |
  .rc_message.burst_count = 10 |
  .rc_registration.per_second = 0.17 |
  .rc_registration.burst_count = 3 |
  .retention.enabled = true |
  .retention.default_policy.min_lifetime = "1d" |
  .retention.default_policy.max_lifetime = "365d" |
  .url_preview_enabled = true |
  .url_preview_ip_range_blacklist = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] |
  .report_stats = false 
' ./synapse/data/homeserver.yaml

# MATRIX Config!
# The domain where your Matrix Synapse is reachable (e.g., matrix.example.com)
MATRIX_DOMAIN="matrix.$domain"
OUTPUT_FILE="./authentik/blueprints/synapse.yaml"

# --- GENERATE CREDENTIALS ---
echo "Generating secure credentials..."
# Generate random 40-char strings for ID and Secret
MATRIX_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
MATRIX_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)

echo "MATRIX_CLIENT_ID=$MATRIX_CLIENT_ID" >> .env
echo "MATRIX_CLIENT_SECRET=$MATRIX_CLIENT_SECRET" >> .env

# --- PROCESS WITH YQ (Python Version) ---
# We use --arg to pass variables safely into the query
echo "Injecting values into template..."

# yq -iy \
#   --arg id "$MATRIX_CLIENT_ID" \
#   --arg secret "$MATRIX_CLIENT_SECRET" \
#   --arg domain "$MATRIX_DOMAIN" \
#   --arg domain "$domain" \
#   '
#   .metadata.name = $domain+" Matrix Synapse Integration" |  
#   .entries[0].attrs.client_id = $id |
#   .entries[0].attrs.client_secret = $secret |
#   .entries[0].attrs.redirect_uris[0] |= sub("PLACEHOLDER_DOMAIN"; $domain)
#   ' ./authentik/blueprints/synapse.yaml
sed -i \
    -e "s|__CLIENT_ID__|$MATRIX_CLIENT_ID|g" \
    -e "s|__CLIENT_SECRET__|$MATRIX_CLIENT_SECRET|g" \
    -e "s|__DOMAIN__|$domain|g" \
    -e "s|__MATRIX_DOMAIN__|$MATRIX_DOMAIN|g" \
    "./authentik/blueprints/synapse.yaml"

yq -iy \
  --arg id "$MATRIX_CLIENT_ID" \
  --arg secret "$MATRIX_CLIENT_SECRET" \
  --arg issuer "https://auth.$domain/application/o/matrix-synapse/" \
  '
  .oidc_providers[0].idp_id = "authentik" |
  .oidc_providers[0].idp_name = "Authentik" |
  .oidc_providers[0].discover = true |
  .oidc_providers[0].issuer = $issuer |
  .oidc_providers[0].client_id = $id |
  .oidc_providers[0].client_secret = $secret |
  .oidc_providers[0].scopes = ["openid", "profile", "email"] |
  .oidc_providers[0].user_mapping_provider.config.localpart_template = "{{ user.preferred_username }}" |
  .oidc_providers[0].user_mapping_provider.config.display_name_template = "{{ user.name }}"
  ' ./synapse/data/homeserver.yaml


# ELEMENT
MATRIX_HOMESERVER="https://$MATRIX_DOMAIN"
BRAND_NAME="$domain Chat"

sed -i \
    -e "s|PLACEHOLDER_BRAND|$BRAND_NAME|g" \
    -e "s|PLACEHOLDER_HOMESERVER|$MATRIX_HOMESERVER|g" \
    "./element/config.json"

  # STALWART
  # --- GENERATE LDAP CONFIG ---
LDAP_BASE_DN=$(echo "$domain" | sed 's/\./,dc=/g' | sed 's/^/dc=/')
echo "LDAP_BASE_DN=$LDAP_BASE_DN" >> .env

# --- UPDATE BLUEPRINT ---
sed -i \
    -e "s|__LDAP_BASE_DN__|$LDAP_BASE_DN|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/stalwart.yaml"

sed -i \
    -e "s|__PG_PASS__|$PG_PASS|g" \
    -e "s|__LDAP_BASE_DN__|$LDAP_BASE_DN|g" \
    -e "s|__BIND_USER__|$username|g" \
    -e "s|__BIND_PASSWORD__|$password|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./stalwart/data/etc/config.toml"

# dozzle blueprint update
sed -i \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/dozzle.yaml"

# CRITICAL: Strip CRLF (\r) line endings from all blueprints to ensure Authentik can parse them
sed -i 's/\r$//' ./authentik/blueprints/*.yaml


docker compose up -d

### --- POST-DEPLOY: LDAP Outpost Token + Stalwart Admin Promotion ---

log "Waiting for Authentik to be ready and blueprints to be applied..."

ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT + 1))

    TOKEN_KEY=$(docker exec authentik-server python3 -c "
import django, os, sys
os.environ['DJANGO_SETTINGS_MODULE'] = 'authentik.root.settings'
sys.stderr = open(os.devnull, 'w')
django.setup()
from authentik.outposts.models import Outpost
try:
    outpost = Outpost.objects.get(name='Stalwart LDAP Outpost')
    print(outpost.token.key, end='')
except Exception:
    sys.exit(1)
" 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$TOKEN_KEY" ]; then
        success "Got outpost token: ${TOKEN_KEY:0:8}..."

        sed -i '/LDAP_OUTPOST_TOKEN/d' .env
        echo "LDAP_OUTPOST_TOKEN=$TOKEN_KEY" >> .env

        docker compose up -d authentik-ldap
        success "LDAP outpost restarted with correct token."
        break
    fi

    log "  Attempt $ATTEMPT - outpost not ready yet, waiting 10s..."
    sleep 10
done

STALWART_URL="https://mail.${domain}"

log "Waiting for Stalwart and LDAP outpost to be ready..."
for i in $(seq 1 30); do
    if curl -ksf -o /dev/null "$STALWART_URL/login" 2>/dev/null; then
        break
    fi
    sleep 2
done
sleep 10

ADMIN_PERMS='[{"action":"set","field":"enabledPermissions","value":["ai-model-interact","api-key-create","api-key-delete","api-key-get","api-key-list","api-key-update","authenticate","authenticate-oauth","blob-fetch","individual-create","individual-delete","individual-get","individual-list","individual-update","group-create","group-delete","group-get","group-list","group-update","domain-create","domain-delete","domain-get","domain-list","domain-update","role-create","role-delete","role-get","role-list","role-update","principal-create","principal-delete","principal-get","principal-list","principal-update","settings-list","settings-update","settings-delete","settings-reload","logs-view","tracing-get","tracing-list","tracing-live","troubleshoot","metrics-list","metrics-live","manage-encryption","manage-passwords","message-queue-delete","message-queue-get","message-queue-list","message-queue-update","incoming-report-delete","incoming-report-get","incoming-report-list","outgoing-report-delete","outgoing-report-get","outgoing-report-list","dkim-signature-create","dkim-signature-get","spam-filter-test","spam-filter-train","spam-filter-update","mailing-list-create","mailing-list-delete","mailing-list-get","mailing-list-list","mailing-list-update","oauth-client-create","oauth-client-delete","oauth-client-get","oauth-client-list","oauth-client-update","oauth-client-override","oauth-client-registration","tenant-create","tenant-delete","tenant-get","tenant-list","tenant-update","purge-account","purge-blob-store","purge-data-store","purge-in-memory-store","fts-reindex","restart","undelete","impersonate","unlimited-requests","unlimited-uploads","webadmin-update","email-send","email-receive"]}]'

log "Triggering account creation and promoting $username to Stalwart admin..."
ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT + 1))
    curl -ks -u "$username:$password" "$STALWART_URL/api/principal" >/dev/null 2>&1
    sleep 2
    RESULT=$(curl -ks -X PATCH \
        -u "admin:$password" \
        "$STALWART_URL/api/principal/$username" \
        -H "Content-Type: application/json" \
        -d "$ADMIN_PERMS" 2>&1)
    if echo "$RESULT" | grep -q "error"; then
        log "  Attempt $ATTEMPT - account not ready yet, retrying in 5s..."
        sleep 5
    else
        success "User $username promoted to admin in Stalwart."
        break
    fi
done

### --- Configure Stalwart: Domain + Mailbox ---

log "Creating domain $domain in Stalwart..."
RESULT=$(curl -ks -X POST \
    -u "admin:$password" \
    "$STALWART_URL/api/principal" \
    -H "Content-Type: application/json" \
    -d "{\"type\": \"domain\", \"name\": \"$domain\"}" 2>&1)
if echo "$RESULT" | grep -q "error"; then
    log "Domain creation note: $RESULT"
else
    success "Domain $domain created."
fi

log "Adding email ${username}@${domain} to $username..."
RESULT=$(curl -ks -X PATCH \
    -u "admin:$password" \
    "$STALWART_URL/api/principal/$username" \
    -H "Content-Type: application/json" \
    -d "[{\"action\": \"set\", \"field\": \"emails\", \"value\": [\"$username@$domain\"]}]" 2>&1)
if echo "$RESULT" | grep -q "error"; then
    log "Email assignment note: $RESULT"
else
    success "Email addresses assigned to $username."
fi

log "Generating DKIM key for $domain..."
RESULT=$(curl -ks -X POST \
    -u "admin:$password" \
    "$STALWART_URL/api/dkim" \
    -H "Content-Type: application/json" \
    -d "{\"algorithm\": \"Ed25519\", \"domain\": \"$domain\"}" 2>&1)
if echo "$RESULT" | grep -q "error"; then
    log "DKIM generation note: $RESULT"
else
    success "DKIM key generated for $domain."
fi

log "Fetching recommended DNS records from Stalwart..."
DNS_JSON=$(curl -ks -u "admin:$password" "$STALWART_URL/api/dns/records/$domain" 2>&1)
if echo "$DNS_JSON" | python3 -c "import sys,json; json.load(sys.stdin)['data']" >/dev/null 2>&1; then
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
fi

success "Setup complete! All services are running."
success "User sync container will automatically provision Stalwart mailboxes for new Authentik users."
