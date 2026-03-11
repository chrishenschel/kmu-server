#!/bin/bash

# Wiki.js post-deploy: log in as admin, then configure outbound mail via GraphQL.
# No manual API token needed: we use authentication.login then mail.updateConfig.
# Assumes: log/success/error functions and variables: domain, username, password.

# Load .env from repo root (parent of scripts/) so we always see NOREPLY_* set by post-deploy-stalwart
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -f "$REPO_ROOT/.env" ]; then
  set -a
  # shellcheck source=/dev/null
  . "$REPO_ROOT/.env"
  set +a
fi

WIKI_BASE_URL="https://wiki.${domain}"

# Prefer explicit wiki admin email, fallback to setup email
WIKI_ADMIN="${WIKI_ADMIN_EMAIL:-$email}"
if [ -z "${WIKI_ADMIN:-}" ]; then
  log "WIKI_ADMIN_EMAIL / email not set; skipping Wiki.js mail configuration."
  return 0 2>/dev/null || exit 0
fi

if [ -z "${NOREPLY_EMAIL:-}" ] || [ -z "${NOREPLY_MAIL_PASSWORD:-}" ]; then
  log "NOREPLY_EMAIL or NOREPLY_MAIL_PASSWORD not set; skipping Wiki.js mail configuration."
  return 0 2>/dev/null || exit 0
fi

log "Waiting for Wiki.js to become reachable at ${WIKI_BASE_URL}..."
for i in $(seq 1 30); do
  if curl -ksf -o /dev/null "${WIKI_BASE_URL}/login" 2>/dev/null; then
    break
  fi
  sleep 2
done

# --- 1) Login to get JWT (no token required)
LOGIN_PAYLOAD=$(WIKI_USER="$WIKI_ADMIN" WIKI_PASS="$PASSWORD" python3 << 'PYLOGIN'
import os, json
username = os.environ.get("WIKI_USER", "")
password = os.environ.get("WIKI_PASS", "")
q = """mutation Login($username: String!, $password: String!, $strategy: String!) {
  authentication {
    login(username: $username, password: $password, strategy: $strategy) {
      responseResult { succeeded message }
      jwt
    }
  }
}"""
print(json.dumps({
  "query": q,
  "variables": {"username": username, "password": password, "strategy": "local"}
}))
PYLOGIN
)

LOGIN_RESPONSE=$(curl -ks "${WIKI_BASE_URL}/graphql" \
  -H "Content-Type: application/json" \
  -d "$LOGIN_PAYLOAD")

JWT=$(echo "$LOGIN_RESPONSE" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    j = d.get('data', {}).get('authentication', {}).get('login', {})
    if j.get('responseResult', {}).get('succeeded') and j.get('jwt'):
        print(j['jwt'], end='')
    else:
        sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null)

if [ -z "$JWT" ]; then
  log "Wiki.js admin login failed (wrong credentials or not ready). Skipping mail configuration."
  log "Login response: $LOGIN_RESPONSE"
  return 0 2>/dev/null || exit 0
fi

# --- 2) Update mail config using JWT
SMTP_HOST="mail.${DOMAIN:-$domain}"
SMTP_PORT=587
SMTP_NAME="wiki.${DOMAIN:-$domain}"

MAIL_PAYLOAD=$(SENDER_NAME="${DOMAIN:-$domain} Wiki" SENDER_EMAIL="$NOREPLY_EMAIL" SMTP_HOST="$SMTP_HOST" SMTP_PORT="$SMTP_PORT" SMTP_NAME="$SMTP_NAME" SMTP_PASS="$NOREPLY_MAIL_PASSWORD" python3 << 'PYMAIL'
import os, json
q = """mutation UpdateMailConfig($senderName: String!, $senderEmail: String!, $host: String!, $port: Int!, $name: String!, $secure: Boolean!, $verifySSL: Boolean!, $user: String!, $pass: String!, $useDKIM: Boolean!, $dkimDomainName: String!, $dkimKeySelector: String!, $dkimPrivateKey: String!) {
  mail {
    updateConfig(
      senderName: $senderName
      senderEmail: $senderEmail
      host: $host
      port: $port
      name: $name
      secure: $secure
      verifySSL: $verifySSL
      user: $user
      pass: $pass
      useDKIM: $useDKIM
      dkimDomainName: $dkimDomainName
      dkimKeySelector: $dkimKeySelector
      dkimPrivateKey: $dkimPrivateKey
    ) {
      responseResult { succeeded message }
    }
  }
}"""
print(json.dumps({
  "query": q,
  "variables": {
    "senderName": os.environ.get("SENDER_NAME", ""),
    "senderEmail": os.environ.get("SENDER_EMAIL", ""),
    "host": os.environ.get("SMTP_HOST", ""),
    "port": int(os.environ.get("SMTP_PORT", "587")),
    "name": os.environ.get("SMTP_NAME", ""),
    "secure": False,
    "verifySSL": True,
    "user": os.environ.get("SENDER_EMAIL", ""),
    "pass": os.environ.get("SMTP_PASS", ""),
    "useDKIM": False,
    "dkimDomainName": "",
    "dkimKeySelector": "",
    "dkimPrivateKey": ""
  }
}))
PYMAIL
)

log "Configuring Wiki.js mail settings via GraphQL..."
MAIL_RESPONSE=$(curl -ks "${WIKI_BASE_URL}/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d "$MAIL_PAYLOAD")

if echo "$MAIL_RESPONSE" | grep -q '"succeeded":[[:space:]]*true'; then
  success "Wiki.js mail configuration applied successfully (using ${NOREPLY_EMAIL})."
else
  log "Wiki.js mail configuration may have failed. Response: $MAIL_RESPONSE"
fi

