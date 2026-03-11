#!/bin/bash

# LDAP Outpost token + Stalwart bootstrap (domain, admin, noreply)

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

log "Giving Caddy time to obtain TLS certificate for mail.${domain}..."
sleep 15
log "Restarting Stalwart so it picks up TLS certificates from Caddy."
docker compose restart stalwart-mail >/dev/null 2>&1 || true
sleep 5

ADMIN_PERMS='[{"action":"set","field":"enabledPermissions","value":["ai-model-interact","api-key-create","api-key-delete","api-key-get","api-key-list","api-key-update","authenticate","authenticate-oauth","blob-fetch","individual-create","individual-delete","individual-get","individual-list","individual-update","group-create","group-delete","group-get","group-list","group-update","domain-create","domain-delete","domain-get","domain-list","domain-update","role-create","role-delete","role-get","role-list","role-update","principal-create","principal-delete","principal-get","principal-list","principal-update","settings-list","settings-update","settings-delete","settings-reload","logs-view","tracing-get","tracing-list","tracing-live","troubleshoot","metrics-list","metrics-live","manage-encryption","manage-passwords","message-queue-delete","message-queue-get","message-queue-list","message-queue-update","incoming-report-delete","incoming-report-get","incoming-report-list","outgoing-report-delete","outgoing-report-get","outgoing-report-list","dkim-signature-create","dkim-signature-get","spam-filter-test","spam-filter-train","spam-filter-update","mailing-list-create","mailing-list-delete","mailing-list-get","mailing-list-list","mailing-list-update","oauth-client-create","oauth-client-delete","oauth-client-get","oauth-client-list","oauth-client-update","oauth-client-override","oauth-client-registration","tenant-create","tenant-delete","tenant-get","tenant-list","tenant-update","purge-account","purge-blob-store","purge-data-store","purge-in-memory-store","fts-reindex","restart","undelete","impersonate","unlimited-requests","unlimited-uploads","webadmin-update","email-send","email-receive"]}]]

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
        log "noreply user already exists in Authentik; reusing or resetting password and ensuring NOREPLY_MAIL_PASSWORD in .env."
        [ -f .env ] && set -a && source .env && set +a
        NOREPLY_PASS="${NOREPLY_MAIL_PASSWORD:-$NOREPLY_PASS}"
        NOREPLY_PK=$(curl -ks -s -H "Authorization: Bearer $AUTHENTIK_BOOTSTRAP_TOKEN" \
            "$AUTH_URL/api/v3/core/users/?username=noreply&page_size=1" | \
            python3 -c "import sys,json; d=json.load(sys.stdin); r=d.get('results',[]); print(r[0].get('pk','') if r else '')" 2>/dev/null)
        if [ -n "$NOREPLY_PK" ]; then
            # Ensure we have a known password in .env: set password via API so downstream (Wiki, Nextcloud, etc.) can use it
            PW_RESULT=$(curl -ks -X POST \
                -H "Authorization: Bearer $AUTHENTIK_BOOTSTRAP_TOKEN" \
                -H "Content-Type: application/json" \
                -d "{\"password\": \"$NOREPLY_PASS\"}" \
                "$AUTH_URL/api/v3/core/users/$NOREPLY_PK/set_password/" 2>&1)
            if [ "${PW_RESULT}" = "" ] || echo "$PW_RESULT" | grep -q "204\|200"; then
                grep -q '^NOREPLY_MAIL_PASSWORD=' .env 2>/dev/null || echo "NOREPLY_MAIL_PASSWORD=$NOREPLY_PASS" >> .env
                success "noreply password synced; NOREPLY_MAIL_PASSWORD written to .env."
            fi
        fi
    else
        log "noreply creation note: $CREATE_RESULT"
    fi
fi
grep -q '^NOREPLY_EMAIL=' .env 2>/dev/null || echo "NOREPLY_EMAIL=noreply@${domain}" >> .env
if echo "$CREATE_RESULT" 2>/dev/null | grep -q '"pk"'; then
    grep -q '^NOREPLY_MAIL_PASSWORD=' .env 2>/dev/null || echo "NOREPLY_MAIL_PASSWORD=$NOREPLY_PASS" >> .env
else
    [ -f .env ] && set -a && source .env && set +a
    NOREPLY_PASS="${NOREPLY_MAIL_PASSWORD:-$NOREPLY_PASS}"
fi

