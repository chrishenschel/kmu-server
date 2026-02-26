#!/bin/bash

echo "Waiting for Authentik to be ready and blueprints to be applied..."

MAX_ATTEMPTS=30
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
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
        echo "Got outpost token: ${TOKEN_KEY:0:8}..."

        sed -i '/LDAP_OUTPOST_TOKEN/d' .env
        echo "LDAP_OUTPOST_TOKEN=$TOKEN_KEY" >> .env

        docker compose up -d authentik-ldap
        echo "LDAP outpost restarted with correct token."

        # Promote setup user to Stalwart admin
        STALWART_USER=$(grep '^USERNAME=' .env | cut -d= -f2-)
        STALWART_ADMIN_PASS=$(grep '^PASSWORD=' .env | cut -d= -f2-)
        STALWART_DOMAIN=$(grep '^DOMAIN=' .env | cut -d= -f2-)
        STALWART_URL="https://mail.${STALWART_DOMAIN}"

        echo "Waiting for Stalwart to be ready..."
        for i in $(seq 1 30); do
            if curl -ksf -o /dev/null "$STALWART_URL/login" 2>/dev/null; then
                break
            fi
            sleep 2
        done

        # Trigger first login to create the account in Stalwart
        echo "Triggering account creation for $STALWART_USER..."
        curl -ks -u "$STALWART_USER:$STALWART_ADMIN_PASS" "$STALWART_URL/api/principal" >/dev/null 2>&1
        sleep 3

        echo "Promoting $STALWART_USER to Stalwart admin..."
        ADMIN_PERMS='[{"action":"set","field":"enabledPermissions","value":["ai-model-interact","api-key-create","api-key-delete","api-key-get","api-key-list","api-key-update","authenticate","authenticate-oauth","blob-fetch","individual-create","individual-delete","individual-get","individual-list","individual-update","group-create","group-delete","group-get","group-list","group-update","domain-create","domain-delete","domain-get","domain-list","domain-update","role-create","role-delete","role-get","role-list","role-update","principal-create","principal-delete","principal-get","principal-list","principal-update","settings-list","settings-update","settings-delete","settings-reload","logs-view","tracing-get","tracing-list","tracing-live","troubleshoot","metrics-list","metrics-live","manage-encryption","manage-passwords","message-queue-delete","message-queue-get","message-queue-list","message-queue-update","incoming-report-delete","incoming-report-get","incoming-report-list","outgoing-report-delete","outgoing-report-get","outgoing-report-list","dkim-signature-create","dkim-signature-get","spam-filter-test","spam-filter-train","spam-filter-update","mailing-list-create","mailing-list-delete","mailing-list-get","mailing-list-list","mailing-list-update","oauth-client-create","oauth-client-delete","oauth-client-get","oauth-client-list","oauth-client-update","oauth-client-override","oauth-client-registration","tenant-create","tenant-delete","tenant-get","tenant-list","tenant-update","purge-account","purge-blob-store","purge-data-store","purge-in-memory-store","fts-reindex","restart","undelete","impersonate","unlimited-requests","unlimited-uploads","webadmin-update","email-send","email-receive"]}]'
        RESULT=$(curl -ks -X PATCH \
            -u "admin:$STALWART_ADMIN_PASS" \
            "$STALWART_URL/api/principal/$STALWART_USER" \
            -H "Content-Type: application/json" \
            -d "$ADMIN_PERMS" 2>&1)
        if echo "$RESULT" | grep -q "error"; then
            echo "WARNING: Could not promote $STALWART_USER ($RESULT). Do it manually via the Stalwart admin panel."
        else
            echo "User $STALWART_USER promoted to admin in Stalwart."
        fi

        exit 0
    fi

    echo "  Attempt $ATTEMPT/$MAX_ATTEMPTS - outpost not ready yet, waiting 10s..."
    sleep 10
done

echo "ERROR: Could not retrieve LDAP outpost token after $MAX_ATTEMPTS attempts."
echo "Check that blueprints were applied: https://auth.<your-domain>/if/admin/#/core/system"
exit 1
