#!/bin/bash

# Assumes: log/success/error functions, and variables:
#   domain, username, userfullname, password, email

PG_PASS="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 48)"
AUTHENTIK_BOOTSTRAP_PASSWORD="$(openssl rand -base64 60 | tr -d '\n')"
AUTHENTIK_BOOTSTRAP_TOKEN="$(openssl rand -base64 60 | tr -d '\n')"
AUTHENTIK_BOOTSTRAP_EMAIL="hostmaster@$domain"
AUTHENTIK_SECRET_KEY=$(openssl rand -base64 60 | tr -d '\n')
PAPERLESS_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')
PAPERLESS_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
PAPERLESS_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)
STIRLING_INITIAL_PASSWORD=$(openssl rand -base64 24 | tr -d '\n')
STIRLING_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
STIRLING_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)

# Generate environment variables
echo "PG_PASS=$PG_PASS" >> .env
echo "AUTHENTIK_SECRET_KEY=$AUTHENTIK_SECRET_KEY" >> .env
echo "AUTHENTIK_BOOTSTRAP_PASSWORD=$AUTHENTIK_BOOTSTRAP_PASSWORD" >> .env
echo "AUTHENTIK_BOOTSTRAP_TOKEN=$AUTHENTIK_BOOTSTRAP_TOKEN" >> .env
echo "AUTHENTIK_BOOTSTRAP_EMAIL=$AUTHENTIK_BOOTSTRAP_EMAIL" >> .env
echo "PAPERLESS_SECRET_KEY=$PAPERLESS_SECRET_KEY" >> .env
echo "PAPERLESS_CLIENT_ID=$PAPERLESS_CLIENT_ID" >> .env
echo "PAPERLESS_CLIENT_SECRET=$PAPERLESS_CLIENT_SECRET" >> .env
echo "DOMAIN=$domain" >> .env
echo "WIKI_ADMIN_EMAIL=$email" >> .env
echo "USERNAME=$username" >> .env
echo "USERFULLNAME=\"$userfullname\"" >> .env
echo "PASSWORD=$password" >> .env

docker network create caddy-proxy
docker network create database

# Generate Synapse config (volume-based bootstrap)
docker run -it --rm \
    --mount type=volume,src=infra_synapse_data,dst=/data \
    -e SYNAPSE_SERVER_NAME=$domain \
    -e SYNAPSE_REPORT_STATS=no ghcr.io/element-hq/synapse:latest generate

cp /var/lib/docker/volumes/infra_synapse_data/_data/$domain.log.config ./synapse/data/$domain.log.config
cp /var/lib/docker/volumes/infra_synapse_data/_data/$domain.signing.key ./synapse/data/$domain.signing.key
cp /var/lib/docker/volumes/infra_synapse_data/_data/homeserver.yaml ./synapse/data/homeserver.yaml
chown 991:991 ./synapse/data/$domain.signing.key

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

# Synapse DB + OIDC config
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

MATRIX_DOMAIN="matrix.$domain"
OUTPUT_FILE="./authentik/blueprints/synapse.yaml"

log "Generating Matrix OIDC client credentials..."
MATRIX_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
MATRIX_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)

echo "MATRIX_CLIENT_ID=$MATRIX_CLIENT_ID" >> .env
echo "MATRIX_CLIENT_SECRET=$MATRIX_CLIENT_SECRET" >> .env

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

# Element branding + homeserver URL
MATRIX_HOMESERVER="https://$MATRIX_DOMAIN"
BRAND_NAME="$domain Chat"
JITSI_DOMAIN="meet.$domain"

sed -i \
    -e "s|PLACEHOLDER_BRAND|$BRAND_NAME|g" \
    -e "s|PLACEHOLDER_HOMESERVER|$MATRIX_HOMESERVER|g" \
    -e "s|PLACEHOLDER_JITSI_DOMAIN|$JITSI_DOMAIN|g" \
    "./element/config.json"

# Stalwart LDAP / config
LDAP_BASE_DN=$(echo "$domain" | sed 's/\./,dc=/g' | sed 's/^/dc=/')
echo "LDAP_BASE_DN=$LDAP_BASE_DN" >> .env

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

# Authentik blueprints for various apps
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/dozzle.yaml"
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/admin.yaml"
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/element-proxy.yaml"
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/outpost-proxy.yaml"
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/meet.yaml"
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/startpage.yaml"
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/paperless.yaml"
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/stirling.yaml"
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/convertx.yaml"
sed -i -e "s|__DOMAIN__|$domain|g" "./authentik/blueprints/it-tools.yaml"

if [ -f .env ] && ! grep -q '^PAPERLESS_SECRET_KEY=' .env 2>/dev/null; then
  echo "PAPERLESS_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')" >> .env
fi

if [ -f .env ] && ! grep -q '^PAPERLESS_CLIENT_ID=' .env 2>/dev/null; then
  PAPERLESS_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
  PAPERLESS_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)
  echo "PAPERLESS_CLIENT_ID=$PAPERLESS_CLIENT_ID" >> .env
  echo "PAPERLESS_CLIENT_SECRET=$PAPERLESS_CLIENT_SECRET" >> .env
fi

if [ -f .env ] && ! grep -q '^WIKI_ADMIN_EMAIL=' .env 2>/dev/null; then
  echo "WIKI_ADMIN_EMAIL=$email" >> .env
fi

set -a
[ -f .env ] && . ./.env
set +a

sed -i \
    -e "s|__PAPERLESS_CLIENT_ID__|${PAPERLESS_CLIENT_ID:-__PAPERLESS_CLIENT_ID__}|g" \
    -e "s|__PAPERLESS_CLIENT_SECRET__|${PAPERLESS_CLIENT_SECRET:-__PAPERLESS_CLIENT_SECRET__}|g" \
    "./authentik/blueprints/paperless.yaml"

# Nextcloud OIDC client
NC_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
NC_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)
echo "NC_CLIENT_ID=$NC_CLIENT_ID" >> .env
echo "NC_CLIENT_SECRET=$NC_CLIENT_SECRET" >> .env

sed -i \
    -e "s|__NC_CLIENT_ID__|$NC_CLIENT_ID|g" \
    -e "s|__NC_CLIENT_SECRET__|$NC_CLIENT_SECRET|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/nextcloud.yaml"

# Vaultwarden OIDC
VW_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
VW_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)
echo "VW_CLIENT_ID=$VW_CLIENT_ID" >> .env
echo "VW_CLIENT_SECRET=$VW_CLIENT_SECRET" >> .env
sed -i \
    -e "s|__VW_CLIENT_ID__|$VW_CLIENT_ID|g" \
    -e "s|__VW_CLIENT_SECRET__|$VW_CLIENT_SECRET|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/vaultwarden.yaml"

# Immich OIDC
IMMICH_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
IMMICH_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)
echo "IMMICH_CLIENT_ID=$IMMICH_CLIENT_ID" >> .env
echo "IMMICH_CLIENT_SECRET=$IMMICH_CLIENT_SECRET" >> .env
sed -i \
    -e "s|__IMMICH_CLIENT_ID__|$IMMICH_CLIENT_ID|g" \
    -e "s|__IMMICH_CLIENT_SECRET__|$IMMICH_CLIENT_SECRET|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/immich.yaml"
sed -i \
    -e "s|__IMMICH_CLIENT_ID__|$IMMICH_CLIENT_ID|g" \
    -e "s|__IMMICH_CLIENT_SECRET__|$IMMICH_CLIENT_SECRET|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./immich/immich.json"

# Wiki.js OIDC
WIKI_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
WIKI_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)
echo "WIKI_CLIENT_ID=$WIKI_CLIENT_ID" >> .env
echo "WIKI_CLIENT_SECRET=$WIKI_CLIENT_SECRET" >> .env
sed -i \
    -e "s|__WIKI_CLIENT_ID__|$WIKI_CLIENT_ID|g" \
    -e "s|__WIKI_CLIENT_SECRET__|$WIKI_CLIENT_SECRET|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/wiki.yaml"

# Normalize blueprint line endings
sed -i 's/\r$//' ./authentik/blueprints/*.yaml

# Data directories and permissions
log "Setting Nextcloud directory permissions for www-data (uid 33)..."
mkdir -p nextcloud/config nextcloud/data nextcloud/apps nextcloud/theme
chown -R 33:33 nextcloud/config nextcloud/data nextcloud/apps nextcloud/theme
success "Nextcloud directories ready."

mkdir -p vaultwarden/data
success "Vaultwarden data directory ready."

mkdir -p immich/library
mkdir -p paperless/data paperless/media paperless/export paperless/consume
mkdir -p stirling-pdf/configs stirling-pdf/logs
mkdir -p convertx/data
mkdir -p wiki/data
chown -R 1000:1000 wiki/data
success "Immich library and other app directories ready."

### Jitsi & coturn bootstrap
log "Preparing Jitsi Meet configuration..."
if [ -f jitsi/.env.meet ]; then
    if grep -q "__DOMAIN__" jitsi/.env.meet; then
        sed -i "s|__DOMAIN__|$domain|g" jitsi/.env.meet
    fi

    if grep -q "__JICOFO_AUTH_PASSWORD__" jitsi/.env.meet; then
        JICOFO_AUTH_PASSWORD="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 48)"
        sed -i "s|__JICOFO_AUTH_PASSWORD__|$JICOFO_AUTH_PASSWORD|g" jitsi/.env.meet
    fi

    if grep -q "__JVB_AUTH_PASSWORD__" jitsi/.env.meet; then
        JVB_AUTH_PASSWORD="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 48)"
        sed -i "s|__JVB_AUTH_PASSWORD__|$JVB_AUTH_PASSWORD|g" jitsi/.env.meet
    fi

    if grep -q "__JVB_ADVERTISE_IPS__" jitsi/.env.meet; then
        JVB_PUBLIC_IP=$(curl -4 -sf https://api.ipify.org || curl -4 -sf https://ifconfig.me || echo "")
        if [ -n "$JVB_PUBLIC_IP" ]; then
            sed -i "s|__JVB_ADVERTISE_IPS__|$JVB_PUBLIC_IP|g" jitsi/.env.meet
            success "JVB will advertise public IP: $JVB_PUBLIC_IP"
        else
            log "Could not auto-detect public IP; set JVB_ADVERTISE_IPS manually in jitsi/.env.meet"
        fi
    fi

    if grep -q "__TURN_USER__" jitsi/.env.meet; then
        TURN_USER="jitsi-$(head -c 50 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8)"
        TURN_PASS="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)"
        sed -i \
            -e "s|__TURN_USER__|$TURN_USER|g" \
            -e "s|__TURN_PASS__|$TURN_PASS|g" \
            jitsi/.env.meet
    fi

    if grep -q "__JWT_APP_ID__" jitsi/.env.meet; then
        JWT_APP_ID="jitsi"
        JWT_APP_SECRET="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 48)"
        sed -i \
            -e "s|__JWT_APP_ID__|$JWT_APP_ID|g" \
            -e "s|__JWT_APP_SECRET__|$JWT_APP_SECRET|g" \
            jitsi/.env.meet
        echo "JWT_APP_ID=$JWT_APP_ID" >> .env
        echo "JWT_APP_SECRET=$JWT_APP_SECRET" >> .env
        echo "MEET_DOMAIN=meet.$domain" >> .env
    fi

    success "Jitsi Meet env patched."
else
    log "jitsi/.env.meet not found; skipping Jitsi configuration (no Jitsi deployment)."
fi

if [ -f coturn/turnserver.conf ]; then
    if grep -q "__TURN_REALM__" coturn/turnserver.conf; then
        sed -i "s|__TURN_REALM__|$domain|g" coturn/turnserver.conf
    fi
    if grep -q "__TURN_USER__" coturn/turnserver.conf && grep -q "__TURN_PASS__" coturn/turnserver.conf; then
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

