#!/bin/bash
# Apply or fix Nextcloud OIDC (Authentik) configuration.
# Run from repo root after loading .env (or set DOMAIN, NC_CLIENT_ID, NC_CLIENT_SECRET).
# Use: ./scripts/nextcloud-oidc-setup.sh

set -e
cd "$(dirname "$0")/.."

if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

for v in DOMAIN NC_CLIENT_ID NC_CLIENT_SECRET; do
    if [ -z "${!v}" ]; then
        echo "ERROR: $v is not set. Source .env or export it." >&2
        exit 1
    fi
done

echo "Using domain=$DOMAIN, client_id=${NC_CLIENT_ID:0:8}..."

if ! docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: true"; then
    echo "ERROR: Nextcloud is not installed. Run maintenance:install first." >&2
    exit 1
fi

echo "Ensuring HTTPS/overwrite settings (required for OIDC behind reverse proxy)..."
docker exec --user www-data nextcloud php occ config:system:set overwriteprotocol --value=https
docker exec --user www-data nextcloud php occ config:system:set overwrite.cli.url --value="https://cloud.${DOMAIN}"
docker exec --user www-data nextcloud php occ config:system:set overwritehost --value="cloud.${DOMAIN}"
docker exec --user www-data nextcloud php occ config:system:set trusted_proxies 0 --value="172.16.0.0/12"
docker exec --user www-data nextcloud php occ config:system:set trusted_proxies 1 --value="10.0.0.0/8" 2>/dev/null || true

echo "Setting allow_local_remote_servers..."
docker exec --user www-data nextcloud php occ config:system:set allow_local_remote_servers --value=true --type=boolean

echo "Setting default language to German..."
docker exec --user www-data nextcloud php occ config:system:set default_language --value=de

echo "Ensuring user_oidc app is installed..."
docker exec --user www-data nextcloud php occ app:enable user_oidc 2>/dev/null || \
    docker exec --user www-data nextcloud php occ app:install user_oidc

if docker exec --user www-data nextcloud php occ user_oidc:providers 2>/dev/null | grep -q "authentik"; then
    echo "Provider 'authentik' already exists. Skipping create (run provider:delete authentik first to recreate)."
else
    echo "Creating OIDC provider 'authentik'..."
    docker exec --user www-data nextcloud php occ user_oidc:provider authentik \
        --clientid="$NC_CLIENT_ID" \
        --clientsecret="$NC_CLIENT_SECRET" \
        --discoveryuri="https://auth.${DOMAIN}/application/o/nextcloud/.well-known/openid-configuration" \
        --scope="email profile nextcloud openid" \
        --mapping-uid="user_id" \
        --mapping-display-name="name" \
        --mapping-email="email" \
        --mapping-quota="quota" \
        --mapping-groups="groups" \
        --unique-uid=0 \
        --group-provisioning=1
fi

echo "Setting OIDC as default login..."
docker exec --user www-data nextcloud php occ config:app:set --value=0 user_oidc allow_multiple_user_backends

# Mail app: default account for Stalwart so users get mail.DOMAIN pre-configured
[ -f "./scripts/nextcloud-mail-default.sh" ] && ./scripts/nextcloud-mail-default.sh || true

echo ""
echo "Nextcloud OIDC configuration done."
echo ""
echo "In Authentik, ensure the Nextcloud provider has these redirect URIs (exact):"
echo "  - https://cloud.${DOMAIN}/apps/user_oidc/code"
echo "  - https://cloud.${DOMAIN}/index.php/apps/user_oidc/code"
echo ""
echo "If login still fails, check:"
echo "  - Nextcloud log: docker exec nextcloud cat /var/www/html/data/nextcloud.log"
echo "  - Browser DevTools (F12) Network tab when clicking 'OpenID Connect' login"


echo "Setting up Nextcloud apps..."
docker exec --user www-data nextcloud php occ app:disable twofactor_totp
docker exec --user www-data nextcloud php occ app:enable files_accesscontrol files_retention calendar richdocumentscode contacts mail richdocuments deck groupfolders whiteboard collectives tables
