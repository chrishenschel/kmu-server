#!/bin/bash

# Define the names exactly as they appear in Authentik
OUTPOST_NAME="authentik Embedded Outpost"
PROVIDER_NAME="Dozzle Proxy"

echo "Linking '$PROVIDER_NAME' to '$OUTPOST_NAME'..."

# Run a python script inside the Authentik container to safely append the provider
docker exec -t authentik-server python3 manage.py shell -c "
from authentik.outposts.models import Outpost
from authentik.providers.proxy.models import ProxyProvider

try:
    # 1. Find the Outpost
    outpost = Outpost.objects.get(name='$OUTPOST_NAME')
    
    # 2. Find the Provider
    provider = ProxyProvider.objects.get(name='$PROVIDER_NAME')
    
    # 3. Add the provider to the outpost (if not already there)
    if provider not in outpost.providers.all():
        outpost.providers.add(provider)
        outpost.save()
        print(f'SUCCESS: Added {provider} to {outpost}')
    else:
        print(f'SKIP: {provider} is already linked.')

except Outpost.DoesNotExist:
    print(f'ERROR: Outpost \"$OUTPOST_NAME\" not found.')
except ProxyProvider.DoesNotExist:
    print(f'ERROR: Provider \"$PROVIDER_NAME\" not found.')
"