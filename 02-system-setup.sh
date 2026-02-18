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


