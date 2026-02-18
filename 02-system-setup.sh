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

# ask for domain, username, user, password and store into local variables
read -p "Enter domain (example.com): " domain
read -p "Enter username: (mmustermann) " username
read -p "Enter Full Name (Max Mustermann): " userfullname
read -p "Enter password: " password
read -p "Enter email: " email


PG_PASS="$(openssl rand -base64 36 | tr -d '\n')"
AUTHENTIK_BOOTSTRAP_PASSWORD="$(openssl rand -base64 60 | tr -d '\n')"
AUTHENTIK_BOOTSTRAP_TOKEN="$(openssl rand -base64 60 | tr -d '\n')"
AUTHENTIK_BOOTSTRAP_EMAIL="hostmaster@$domain"


# Generate environment variables
echo "PG_PASS=$PG_PASS" >> .env
echo "AUTHENTIK_SECRET_KEY=$(openssl rand -base64 60 | tr -d '\n')" >> .env
echo "AUTHENTIK_BOOTSTRAP_PASSWORD=$AUTHENTIK_BOOTSTRAP_PASSWORD" >> .env
echo "AUTHENTIK_BOOTSTRAP_TOKEN=$AUTHENTIK_BOOTSTRAP_TOKEN" >> .env
echo "AUTHENTIK_BOOTSTRAP_EMAIL=$AUTHENTIK_BOOTSTRAP_EMAIL" >> .env
echo "DOMAIN=$domain" >> .env
echo "USERNAME=$username" >> .env
echo "USERFULLNAME=$userfullname" >> .env
echo "PASSWORD=$password" >> .env

PASSWORD_HASH=$(docker run --rm ghcr.io/goauthentik/server:latest python -c "from django.contrib.auth.hashers import make_password; print(make_password('$password'))")
echo "PASSWORD_HASH=$PASSWORD_HASH" >> .env

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

yq -iy \
  --arg user "$username" \
  --arg name "$userfullname" \
  --arg email "$email" \
  --arg pwd "$PASSWORD_HASH" \
  --arg domain "$domain" \
  '
  .metadata.name = $domain+" Initial User Creation" |
  .entries[0].identifiers.username = $user |
  .entries[0].attrs.name = $name |
  .entries[0].attrs.email = $email |
  .entries[0].attrs.password = $pwd
  ' ./authentik/blueprints/admin-user.yaml

yq -iy --arg pass "$PG_PASS" '
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

yq -iy \
  --arg id "$MATRIX_CLIENT_ID" \
  --arg secret "$MATRIX_CLIENT_SECRET" \
  --arg domain "$MATRIX_DOMAIN" \
  '
  .entries[0].attrs.client_id = $id |
  .entries[0].attrs.client_secret = $secret |
  .entries[0].attrs.redirect_uris[0] |= sub("PLACEHOLDER_DOMAIN"; $domain)
  ' ./authentik/blueprints/synapse.yaml

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
IDENTITY_SERVER="https://$MATRIX_DOMAIN" 
BRAND_NAME="$domain Chat"

yq -iy \
  --arg hs_url "$MATRIX_HOMESERVER" \
  --arg is_url "$IDENTITY_SERVER" \
  --arg brand "$BRAND_NAME" \
  '
  .default_server_config["m.homeserver"].base_url = $hs_url |
  .default_server_config["m.homeserver"].server_name = $hs_url |
  .default_server_config["m.identity_server"].base_url = $is_url |
  .brand = $brand |
  .disable_custom_urls = true |
  .disable_guests = true |
  .disable_login_language_selector = false |
  .disable_3pid_login = true
  ' ./element/config.json