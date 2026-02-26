#!/bin/bash

echo "Retrieving LDAP outpost token from Authentik..."

TOKEN_KEY=$(docker exec -t authentik-server python3 manage.py shell -c "
from authentik.outposts.models import Outpost
outpost = Outpost.objects.get(name='Stalwart LDAP Outpost')
token = outpost.token
print(token.key)
" 2>/dev/null)

TOKEN_KEY=$(echo "$TOKEN_KEY" | tr -d '\r\n ')

if [ -z "$TOKEN_KEY" ]; then
    echo "ERROR: Could not retrieve LDAP outpost token."
    echo "Make sure Authentik is running and the blueprint has been applied."
    echo "You can check blueprint status at: https://auth.<your-domain>/if/admin/#/core/system"
    exit 1
fi

echo "Got token: ${TOKEN_KEY:0:8}..."

sed -i '/LDAP_OUTPOST_TOKEN/d' .env
echo "LDAP_OUTPOST_TOKEN=$TOKEN_KEY" >> .env

docker compose up -d authentik-ldap
echo "LDAP outpost restarted with correct token."
