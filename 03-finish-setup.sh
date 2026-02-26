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
        exit 0
    fi

    echo "  Attempt $ATTEMPT/$MAX_ATTEMPTS - outpost not ready yet, waiting 10s..."
    sleep 10
done

echo "ERROR: Could not retrieve LDAP outpost token after $MAX_ATTEMPTS attempts."
echo "Check that blueprints were applied: https://auth.<your-domain>/if/admin/#/core/system"
exit 1
