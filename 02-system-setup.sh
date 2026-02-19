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


PG_PASS="$(openssl rand -base64 36 | tr -d '\n')"
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
IDENTITY_SERVER="https://$MATRIX_DOMAIN" 
BRAND_NAME="$domain Chat"

sed -i \
    -e "s|PLACEHOLDER_BRAND|$BRAND_NAME|g" \
    -e "s|PLACEHOLDER_HOMESERVER|$MATRIX_HOMESERVER|g" \
    -e "s|PLACEHOLDER_IDENTITY_SERVER|$IDENTITY_SERVER|g" \
    "./element/config.json"

  # STALWART
  # --- GENERATE CREDENTIALS ---
STALWART_CLIENT_ID=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)
STALWART_CLIENT_SECRET=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 60)
echo "STALWART_CLIENT_ID=$STALWART_CLIENT_ID" >> .env
echo "STALWART_CLIENT_SECRET=$STALWART_CLIENT_SECRET" >> .env
echo "Generated Stalwart Client ID: $STALWART_CLIENT_ID"

# --- UPDATE BLUEPRINT ---
sed -i \
    -e "s|__CLIENT_ID__|$STALWART_CLIENT_ID|g" \
    -e "s|__CLIENT_SECRET__|$STALWART_CLIENT_SECRET|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/stalwart.yaml"

sed -i \
    -e "s|__PG_PASS__|$PG_PASS|g" \
    -e "s|__CLIENT_ID__|$STALWART_CLIENT_ID|g" \
    -e "s|__CLIENT_SECRET__|$STALWART_CLIENT_SECRET|g" \
    -e "s|__DOMAIN__|$domain|g" \
    "./stalwart/data/etc/config.toml"

# dozzle blueprint update
sed -i \
    -e "s|__DOMAIN__|$domain|g" \
    "./authentik/blueprints/dozzle.yaml"

# CRITICAL: Strip CRLF (\r) line endings from all blueprints to ensure Authentik can parse them
sed -i 's/\r$//' ./authentik/blueprints/*.yaml


### maybe later?
# Promote your OIDC user to superuser
#./stalwart-cli acl add superuser chris@tudels.com