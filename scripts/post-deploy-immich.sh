#!/bin/bash

# Immich: bootstrap first user so OAuth login is shown instead of Admin Registration

IMMICH_URL="https://immich.${domain}"
log "Waiting for Immich to be ready and creating bootstrap admin (so login shows OAuth instead of registration)..."
IMMICH_BOOTSTRAP_EMAIL="noreply@${domain}"
IMMICH_BOOTSTRAP_NAME="Immich Bootstrap"
IMMICH_BOOTSTRAP_PASSWORD="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -sk -o /tmp/immich_signup.json -w "%{http_code}" -X POST \
        "$IMMICH_URL/api/auth/admin-sign-up" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$IMMICH_BOOTSTRAP_EMAIL\",\"name\":\"$IMMICH_BOOTSTRAP_NAME\",\"password\":\"$IMMICH_BOOTSTRAP_PASSWORD\"}" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "201" ]; then
        success "Immich bootstrap admin created ($IMMICH_BOOTSTRAP_EMAIL). Login page will show OAuth (Authentik)."
        break
    fi
    if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "409" ]; then
        log "Immich already has an admin (HTTP $HTTP_CODE); skipping bootstrap."
        break
    fi
    log "  Attempt $attempt - Immich not ready or sign-up failed (HTTP $HTTP_CODE), retrying in 10s..."
    sleep 10
done
rm -f /tmp/immich_signup.json

