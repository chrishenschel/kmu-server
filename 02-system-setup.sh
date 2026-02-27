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
echo "USERFULLNAME=\"$userfullname\"" >> .env
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
JITSI_DOMAIN="meet.$domain"

sed -i \
    -e "s|PLACEHOLDER_BRAND|$BRAND_NAME|g" \
    -e "s|PLACEHOLDER_HOMESERVER|$MATRIX_HOMESERVER|g" \
    -e "s|PLACEHOLDER_JITSI_DOMAIN|$JITSI_DOMAIN|g" \
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

sed -i \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/admin.yaml"

sed -i \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/element-proxy.yaml"

sed -i \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/outpost-proxy.yaml"

# NEXTCLOUD
NC_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
NC_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)

echo "NC_CLIENT_ID=$NC_CLIENT_ID" >> .env
echo "NC_CLIENT_SECRET=$NC_CLIENT_SECRET" >> .env

sed -i \
    -e "s|__NC_CLIENT_ID__|$NC_CLIENT_ID|g" \
    -e "s|__NC_CLIENT_SECRET__|$NC_CLIENT_SECRET|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/nextcloud.yaml"

# CRITICAL: Strip CRLF (\r) line endings from all blueprints to ensure Authentik can parse them
sed -i 's/\r$//' ./authentik/blueprints/*.yaml

# Nextcloud: config/data/apps/theme must be writable by www-data (uid 33) inside the container
log "Setting Nextcloud directory permissions for www-data (uid 33)..."
mkdir -p nextcloud/config nextcloud/data nextcloud/apps nextcloud/theme
chown -R 33:33 nextcloud/config nextcloud/data nextcloud/apps nextcloud/theme
success "Nextcloud directories ready."

### --- Jitsi Meet configuration ---

log "Preparing Jitsi Meet configuration..."

# Ensure Jitsi env file exists (committed with placeholders)
if [ -f jitsi/.env.meet ]; then
    # Patch domain placeholder on first run; subsequent runs are no-ops
    if grep -q "__DOMAIN__" jitsi/.env.meet; then
        sed -i "s|__DOMAIN__|$domain|g" jitsi/.env.meet
    fi

    # Generate strong random passwords for internal XMPP components on first run
    if grep -q "__JICOFO_AUTH_PASSWORD__" jitsi/.env.meet; then
        JICOFO_AUTH_PASSWORD="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 48)"
        sed -i "s|__JICOFO_AUTH_PASSWORD__|$JICOFO_AUTH_PASSWORD|g" jitsi/.env.meet
    fi

    if grep -q "__JVB_AUTH_PASSWORD__" jitsi/.env.meet; then
        JVB_AUTH_PASSWORD="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 48)"
        sed -i "s|__JVB_AUTH_PASSWORD__|$JVB_AUTH_PASSWORD|g" jitsi/.env.meet
    fi

    # Generate TURN credentials for coturn + Jitsi on first run
    if grep -q "__TURN_USER__" jitsi/.env.meet; then
        TURN_USER="jitsi-$(head -c 50 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8)"
        TURN_PASS="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)"
        sed -i \
            -e "s|__TURN_USER__|$TURN_USER|g" \
            -e "s|__TURN_PASS__|$TURN_PASS|g" \
            jitsi/.env.meet
    fi

    success "Jitsi Meet env patched."
else
    log "jitsi/.env.meet not found; skipping Jitsi configuration (no Jitsi deployment)."
fi

# Patch coturn configuration with realm and credentials to match Jitsi
if [ -f coturn/turnserver.conf ]; then
    if grep -q "__TURN_REALM__" coturn/turnserver.conf; then
        sed -i "s|__TURN_REALM__|$domain|g" coturn/turnserver.conf
    fi
    if grep -q "__TURN_USER__" coturn/turnserver.conf && grep -q "__TURN_PASS__" coturn/turnserver.conf; then
        # Reuse TURN_USER / TURN_PASS from Jitsi env if set, otherwise generate
        if [ -z "${TURN_USER:-}" ] || [ -z "${TURN_PASS:-}" ]; then
            TURN_USER="jitsi-$(head -c 50 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8)"
            TURN_PASS="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)"
        fi
        sed -i \
            -e "s|__TURN_USER__|$TURN_USER|g" \
            -e "s|__TURN_PASS__|$TURN_PASS|g" \
            coturn/turnserver.conf
    fi
    success "coturn configuration patched."
else
    log "coturn/turnserver.conf not found; skipping coturn configuration."
fi

log "Bringing up full stack (including Jitsi)..."
docker compose up -d

### --- POST-DEPLOY: LDAP Outpost Token + Stalwart Admin Promotion ---

log "Waiting for Authentik to be ready and blueprints to be applied (this might take a while)..."

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

log "Creating noreply@${domain} mail account (in Authentik; Stalwart uses LDAP) for Nextcloud outgoing mail..."
NOREPLY_PASS=$(openssl rand -hex 16)
export NOREPLY_PASS
[ -f .env ] && set -a && source .env && set +a
if [ -z "${AUTHENTIK_BOOTSTRAP_TOKEN:-}" ]; then
    log "AUTHENTIK_BOOTSTRAP_TOKEN not set, skipping noreply creation."
else
    AUTH_URL="https://auth.${domain}"
    CREATE_RESULT=$(curl -ks -X POST \
        -H "Authorization: Bearer $AUTHENTIK_BOOTSTRAP_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"noreply\", \"name\": \"noreply\", \"email\": \"noreply@$domain\", \"path\": \"users\", \"type\": \"internal\", \"is_active\": true}" \
        "$AUTH_URL/api/v3/core/users/" 2>&1)
    if echo "$CREATE_RESULT" | grep -q '"pk"'; then
        NOREPLY_PK=$(echo "$CREATE_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('pk',''))")
        if [ -n "$NOREPLY_PK" ]; then
            PW_RESULT=$(curl -ks -X POST \
                -H "Authorization: Bearer $AUTHENTIK_BOOTSTRAP_TOKEN" \
                -H "Content-Type: application/json" \
                -d "{\"password\": \"$NOREPLY_PASS\"}" \
                "$AUTH_URL/api/v3/core/users/$NOREPLY_PK/set_password/" 2>&1)
            if [ "${PW_RESULT}" = "" ] || echo "$PW_RESULT" | grep -q "204\|200"; then
                success "noreply@${domain} created in Authentik (LDAP -> Stalwart)."
            else
                log "noreply set_password note: $PW_RESULT"
            fi
        else
            log "Could not get noreply user pk from response."
        fi
    elif echo "$CREATE_RESULT" | grep -qi "unique\|already exists"; then
        log "noreply user already exists in Authentik; reusing NOREPLY_MAIL_PASSWORD from .env if set."
        [ -f .env ] && set -a && source .env && set +a
        NOREPLY_PASS="${NOREPLY_MAIL_PASSWORD:-$NOREPLY_PASS}"
    else
        log "noreply creation note: $CREATE_RESULT"
    fi
fi
grep -q '^NOREPLY_EMAIL=' .env 2>/dev/null || echo "NOREPLY_EMAIL=noreply@${domain}" >> .env
# Only persist password when we actually set it (created user); avoid appending unknown password when user already exists
if echo "$CREATE_RESULT" 2>/dev/null | grep -q '"pk"'; then
    grep -q '^NOREPLY_MAIL_PASSWORD=' .env 2>/dev/null || echo "NOREPLY_MAIL_PASSWORD=$NOREPLY_PASS" >> .env
else
    [ -f .env ] && set -a && source .env && set +a
    NOREPLY_PASS="${NOREPLY_MAIL_PASSWORD:-$NOREPLY_PASS}"
fi

### --- POST-DEPLOY: Nextcloud OIDC Configuration ---

log "Waiting for Nextcloud container to be ready..."
ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT + 1))
    if docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: true"; then
        success "Nextcloud is already installed."
        break
    fi
    if docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: false"; then
        log "Nextcloud is not installed. Removing partial config so install command is available..."
        docker exec nextcloud rm -f /var/www/html/config/config.php /var/www/html/config/autoconfig.php 2>/dev/null || true
        sleep 2
        if docker exec --user www-data nextcloud php occ maintenance:install --help &>/dev/null; then
            log "Running maintenance:install..."
            docker exec --user www-data nextcloud php occ maintenance:install \
                --database=pgsql \
                --database-name=nextcloud \
                --database-user=postgres \
                --database-pass="$PG_PASS" \
                --database-host=postgres \
                --admin-user="$username" \
                --admin-pass="$password" \
                --data-dir=/var/www/html/data
            success "Nextcloud installed."
        else
            log "Install command still not available. Triggering install via container entrypoint (restart)..."
            docker compose restart nextcloud
            log "Waiting for Nextcloud to install (entrypoint runs on start)..."
            for i in $(seq 1 60); do
                sleep 10
                if docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: true"; then
                    success "Nextcloud installed via entrypoint."
                    break
                fi
                log "  Waiting... ($i/60)"
            done
        fi
        if docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: true"; then
            log "Configuring trusted domain and overwrite URL..."
            docker exec --user www-data nextcloud php occ config:system:set trusted_domains 0 --value="cloud.${domain}"
            docker exec --user www-data nextcloud php occ config:system:set overwriteprotocol --value=https
            docker exec --user www-data nextcloud php occ config:system:set overwrite.cli.url --value="https://cloud.${domain}"
            success "Nextcloud base config set."
        fi
        break
    fi
    if [ $ATTEMPT -ge 60 ]; then
        error "Nextcloud did not become ready after 60 attempts. Skipping OIDC config."
        break
    fi
    log "  Attempt $ATTEMPT - Nextcloud container not ready yet, waiting 10s..."
    sleep 10
done

log "Ensuring HTTPS/overwrite settings (required for OIDC behind reverse proxy)..."
docker exec --user www-data nextcloud php occ config:system:set overwriteprotocol --value=https
docker exec --user www-data nextcloud php occ config:system:set overwrite.cli.url --value="https://cloud.${domain}"
docker exec --user www-data nextcloud php occ config:system:set overwritehost --value="cloud.${domain}"
# Trust Caddy (and other Docker proxies); Nextcloud will then honour X-Forwarded-Proto
docker exec --user www-data nextcloud php occ config:system:set trusted_proxies 0 --value="172.16.0.0/12"
docker exec --user www-data nextcloud php occ config:system:set trusted_proxies 1 --value="10.0.0.0/8" 2>/dev/null || true

log "Allowing local remote servers (needed for Docker-internal OIDC discovery)..."
docker exec --user www-data nextcloud php occ config:system:set allow_local_remote_servers --value=true --type=boolean

log "Setting default language to German..."
docker exec --user www-data nextcloud php occ config:system:set default_language --value=de

log "Installing OpenID Connect user backend app..."
docker exec --user www-data nextcloud php occ app:install user_oidc
success "user_oidc app installed."

log "Creating OIDC provider for Authentik..."
docker exec --user www-data nextcloud php occ user_oidc:provider authentik \
    --clientid="$NC_CLIENT_ID" \
    --clientsecret="$NC_CLIENT_SECRET" \
    --discoveryuri="https://auth.${domain}/application/o/nextcloud/.well-known/openid-configuration" \
    --scope="email profile nextcloud openid" \
    --mapping-uid="user_id" \
    --mapping-display-name="name" \
    --mapping-email="email" \
    --mapping-quota="quota" \
    --mapping-groups="groups" \
    --unique-uid=0 \
    --group-provisioning=1
success "OIDC provider created."

log "Setting OIDC as the default login method..."
docker exec --user www-data nextcloud php occ config:app:set --value=0 user_oidc allow_multiple_user_backends
success "Nextcloud OIDC configuration complete."

log "Setting up Nextcloud apps..."
docker exec --user www-data nextcloud php occ app:disable twofactor_totp
docker exec --user www-data nextcloud php occ app:enable files_accesscontrol files_retention calendar richdocumentscode contacts mail richdocuments deck groupfolders whiteboard collectives tables jitsi
log "Configuring Nextcloud Jitsi integration..."
docker exec --user www-data nextcloud php occ config:app:set --value="https://meet.${domain}/" jitsi jitsi_server_url
success "Nextcloud apps setup complete (including Jitsi integration)."

log "Configuring Nextcloud to send mail via noreply@${domain} (Stalwart SMTP)..."
docker exec --user www-data nextcloud php occ config:system:set mail_smtpmode --value=smtp
docker exec --user www-data nextcloud php occ config:system:set mail_smtphost --value=stalwart-mail
docker exec --user www-data nextcloud php occ config:system:set mail_smtpport --value=465 --type=integer
docker exec --user www-data nextcloud php occ config:system:set mail_smtpsecure --value=ssl
docker exec --user www-data nextcloud php occ config:system:set mail_smtpauth --value=1 --type=integer
docker exec --user www-data nextcloud php occ config:system:set mail_smtpname --value="noreply@${domain}"
docker exec --user www-data nextcloud php occ config:system:set mail_smtppassword --value="$NOREPLY_PASS"
docker exec --user www-data nextcloud php occ config:system:set mail_from_address --value=noreply
docker exec --user www-data nextcloud php occ config:system:set mail_domain --value="${domain}"
success "Nextcloud outgoing mail set to noreply@${domain}."

### --- DNS Records ---

log "Fetching recommended DNS records from Stalwart..."
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
fi

success "Setup complete! All services are running."
success "User sync container will automatically provision Stalwart mailboxes for new Authentik users."
