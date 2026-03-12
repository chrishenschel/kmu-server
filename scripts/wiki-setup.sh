#!/usr/bin/env sh
set -euo pipefail

echo "[wiki-setup] Starting wiki first-run automation..."

WIKI_URL="${WIKI_URL:-http://wiki:3000}"

if [ -z "${DOMAIN:-}" ]; then
  echo "[wiki-setup] ERROR: DOMAIN env var is required."
  exit 1
fi

WIKI_ADMIN_EMAIL="${WIKI_ADMIN_EMAIL:-hostmaster@${DOMAIN}}"
WIKI_ADMIN_PASSWORD="${WIKI_ADMIN_PASSWORD:-${PASSWORD:-}}"
WIKI_SITE_URL="${WIKI_SITE_URL:-https://wiki.${DOMAIN}}"

if [ -z "${WIKI_ADMIN_PASSWORD}" ]; then
  echo "[wiki-setup] ERROR: WIKI_ADMIN_PASSWORD or PASSWORD env var must be set."
  exit 1
fi

echo "[wiki-setup] Using site URL: ${WIKI_SITE_URL}"
echo "[wiki-setup] Using admin email: ${WIKI_ADMIN_EMAIL}"

echo "[wiki-setup] Waiting for Wiki.js at ${WIKI_URL}..."
for i in $(seq 1 60); do
  if curl -fsS "${WIKI_URL}" >/dev/null 2>&1; then
    echo "[wiki-setup] Wiki.js is reachable."
    break
  fi
  echo "[wiki-setup] Wiki.js not ready yet (attempt ${i}/60), sleeping 5s..."
  sleep 5
done

if ! curl -fsS "${WIKI_URL}" >/dev/null 2>&1; then
  echo "[wiki-setup] ERROR: Wiki.js did not become reachable in time."
  exit 1
fi

JSON_PAYLOAD=$(cat <<EOF
{"adminEmail":"${WIKI_ADMIN_EMAIL}","adminPassword":"${WIKI_ADMIN_PASSWORD}","adminPasswordConfirm":"${WIKI_ADMIN_PASSWORD}","siteUrl":"${WIKI_SITE_URL}","telemetry":false}
EOF
)

echo "[wiki-setup] Sending finalize request to Wiki.js..."
HTTP_CODE=$(curl -sS -o /tmp/wiki-setup-response.txt -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  --data "${JSON_PAYLOAD}" \
  "${WIKI_URL}/finalize" || true)

echo "[wiki-setup] /finalize HTTP status: ${HTTP_CODE}"

case "${HTTP_CODE}" in
  200|201)
    echo "[wiki-setup] Wiki.js setup completed successfully."
    exit 0
    ;;
  400|401|403|409)
    echo "[wiki-setup] Wiki.js likely already configured or rejected setup; treating as non-fatal."
    cat /tmp/wiki-setup-response.txt || true
    exit 0
    ;;
  *)
    echo "[wiki-setup] ERROR: Unexpected response from Wiki.js finalize endpoint."
    cat /tmp/wiki-setup-response.txt || true
    exit 1
    ;;
esac

