#!/bin/bash

# Paperless-ngx: create Django superuser if none exists (idempotent; uses same credentials as bootstrap admin)
log "Waiting for Paperless to be ready, then ensuring superuser exists..."
set -a
[ -f .env ] && . ./.env
set +a

ATTEMPT=0
while true; do
  ATTEMPT=$((ATTEMPT + 1))
  if docker compose exec -T paperless python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/', timeout=3)" 2>/dev/null; then
    success "Paperless is reachable after $ATTEMPT attempts."
    break
  fi
  log "  Attempt $ATTEMPT - Paperless not ready yet, waiting 5s..."
  sleep 5
done

docker compose exec -T \
  -e DJANGO_SUPERUSER_USERNAME="${USERNAME:-admin}" \
  -e DJANGO_SUPERUSER_EMAIL="${WIKI_ADMIN_EMAIL:-hostmaster@${DOMAIN}}" \
  -e DJANGO_SUPERUSER_PASSWORD="${PASSWORD}" \
  paperless python3 manage.py createsuperuser --noinput 2>/dev/null || true
success "Paperless superuser ensured (or already existed)."

