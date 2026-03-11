### --- Diun: Matrix bot user + room (fully automated) ---

log "Ensuring Diun Matrix bot user and room..."

# Load existing values from .env if present so reruns are idempotent
set -a
[ -f .env ] && . ./.env
set +a

MATRIX_SERVER="${MATRIX_SERVER:-https://matrix.${domain}}"
MATRIX_ADMIN_LOCALPART="${MATRIX_ADMIN_LOCALPART:-matrix-admin}"
MATRIX_ADMIN_USER="${MATRIX_ADMIN_USER:-@${MATRIX_ADMIN_LOCALPART}:${domain}}"
MATRIX_ADMIN_PASSWORD="${MATRIX_ADMIN_PASSWORD:-$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)}"
MATRIX_REG_SHARED_SECRET="${MATRIX_REG_SHARED_SECRET:-$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 40)}"

# Persist (or update) these values in .env
sed -i '/^MATRIX_REG_SHARED_SECRET=/d' .env 2>/dev/null || true
sed -i '/^MATRIX_ADMIN_USER=/d' .env 2>/dev/null || true
sed -i '/^MATRIX_ADMIN_PASSWORD=/d' .env 2>/dev/null || true
sed -i '/^MATRIX_SERVER=/d' .env 2>/dev/null || true
sed -i '/^MATRIX_ADMIN_LOCALPART=/d' .env 2>/dev/null || true

echo "MATRIX_REG_SHARED_SECRET=$MATRIX_REG_SHARED_SECRET" >> .env
echo "MATRIX_ADMIN_USER=$MATRIX_ADMIN_USER" >> .env
echo "MATRIX_ADMIN_PASSWORD=$MATRIX_ADMIN_PASSWORD" >> .env
echo "MATRIX_SERVER=$MATRIX_SERVER" >> .env
echo "MATRIX_ADMIN_LOCALPART=$MATRIX_ADMIN_LOCALPART" >> .env

# Ensure registration_shared_secret is set so we can create an admin user non-interactively
if ! grep -q '^registration_shared_secret:' synapse/data/homeserver.yaml 2>/dev/null; then
  log "Injecting registration_shared_secret into Synapse homeserver.yaml..."
  printf '\nregistration_shared_secret: "%s"\n' "${MATRIX_REG_SHARED_SECRET}" >> synapse/data/homeserver.yaml
else
  MATRIX_REG_SHARED_SECRET="$(grep '^registration_shared_secret:' synapse/data/homeserver.yaml | sed 's/registration_shared_secret:[[:space:]]*\"\\{0,1\\}//' | tr -d '"' )"
fi

log "Waiting for Synapse client API to be ready before creating admin user/login..."
ATTEMPT=0
while true; do
  ATTEMPT=$((ATTEMPT + 1))
  if docker compose exec -T synapse curl -sSf \
    'http://localhost:8008/_matrix/client/versions' >/dev/null 2>&1; then
    success "Synapse client API is reachable."
    break
  fi
  log "  Attempt $ATTEMPT - Synapse client API not ready yet, waiting 10s..."
  sleep 10
done

log "Ensuring local Synapse admin user ${MATRIX_ADMIN_USER} exists..."
ADMIN_CREATE_OUTPUT="$(docker compose exec -T synapse register_new_matrix_user \
  -c /data/homeserver.yaml \
  -u "${MATRIX_ADMIN_LOCALPART}" \
  -p "${MATRIX_ADMIN_PASSWORD}" \
  -a 2>&1 || true)"

if echo "$ADMIN_CREATE_OUTPUT" | grep -qi "User ID already taken"; then
  log "Synapse admin user ${MATRIX_ADMIN_USER} already exists."
elif echo "$ADMIN_CREATE_OUTPUT" | grep -qi "Success!"; then
  success "Synapse admin user ${MATRIX_ADMIN_USER} created."
else
  log "Warning: could not verify creation of Synapse admin user ${MATRIX_ADMIN_USER}. Output:"
  echo "$ADMIN_CREATE_OUTPUT"
fi

log "Logging in as Synapse admin to obtain access token..."
MATRIX_ADMIN_ACCESS_TOKEN="$(docker compose exec -T synapse curl -sS -X POST \
  -H 'Content-Type: application/json' \
  'http://localhost:8008/_matrix/client/v3/login' \
  -d '{
  "type": "m.login.password",
  "identifier": { "type": "m.id.user", "user": "'"${MATRIX_ADMIN_USER}"'" },
  "password": "'"${MATRIX_ADMIN_PASSWORD}"'"
}' | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)"

if [ -n "${MATRIX_ADMIN_ACCESS_TOKEN}" ]; then
  success "Got Synapse admin access token."
fi

if [ -z "${MATRIX_ADMIN_ACCESS_TOKEN}" ]; then
  log "Could not obtain Synapse admin access token; skipping Diun Matrix bootstrap."
else
  BOT_LOCALPART="diun-bot"
  BOT_USER="@${BOT_LOCALPART}:${domain}"
  BOT_PASSWORD="$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)"
  ADMIN_USER="@${username}:${domain}"
  ROOM_ALIAS_LOCALPART="bot-updates"
  ROOM_ALIAS="#${ROOM_ALIAS_LOCALPART}:${domain}"

  log "Creating/updating Matrix user ${BOT_USER} via Synapse admin API..."
  curl -sS -X PUT \
      -H "Authorization: Bearer ${MATRIX_ADMIN_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      "${MATRIX_SERVER}/_synapse/admin/v2/users/${BOT_USER}" \
      -d '{
  "password": "'"${BOT_PASSWORD}"'",
  "displayname": "Diun Bot",
  "admin": false,
  "deactivated": false
}' >/dev/null 2>&1 || log "Could not create/update Diun bot user; check Synapse config."

  log "Logging in as Diun bot to obtain access token..."
  BOT_TOKEN="$(docker compose exec -T synapse curl -sS -X POST \
      -H 'Content-Type: application/json' \
      'http://localhost:8008/_matrix/client/v3/login' \
      -d '{
  "type": "m.login.password",
  "identifier": { "type": "m.id.user", "user": "'"${BOT_USER}"'" },
  "password": "'"${BOT_PASSWORD}"'"
}' | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)"

  if [ -z "${BOT_TOKEN}" ]; then
      log "Could not obtain Diun bot access token; skipping Matrix Diun bootstrap."
  else
      echo "MATRIX_BOT_TOKEN=$BOT_TOKEN" >> .env
      log "Ensuring Matrix room ${ROOM_ALIAS} exists..."
      CREATE_RESP="$(docker compose exec -T synapse curl -sS -X POST \
          -H "Authorization: Bearer ${BOT_TOKEN}" \
          -H 'Content-Type: application/json' \
          'http://localhost:8008/_matrix/client/v3/createRoom' \
          -d '{
  "preset": "private_chat",
  "name": "Diun Updates",
  "room_alias_name": "'"${ROOM_ALIAS_LOCALPART}"'"
}' 2>/dev/null || true)"

      ROOM_ID="$(echo "${CREATE_RESP}" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('room_id',''))" 2>/dev/null || true)"

      if [ -z "${ROOM_ID}" ]; then
          ROOM_ID="$(docker compose exec -T synapse curl -sS \
              "http://localhost:8008/_matrix/client/v3/directory/room/${ROOM_ALIAS}" \
              | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('room_id',''))" 2>/dev/null || true)"
      fi

      if [ -z "${ROOM_ID}" ]; then
          log "Could not resolve room id for ${ROOM_ALIAS}; skipping Diun Matrix env export."
      else
          log "Inviting admin user ${ADMIN_USER} to ${ROOM_ID}..."
          curl -sS -X POST \
              -H "Authorization: Bearer ${BOT_TOKEN}" \
              -H "Content-Type: application/json" \
              "${MATRIX_SERVER}/_matrix/client/v3/rooms/${ROOM_ID}/invite" \
              -d '{ "user_id": "'"${ADMIN_USER}"'" }' >/dev/null 2>&1 || true

          # Ensure .env contains the Diun Matrix settings (overwrite any old values)
          sed -i '/^DIUN_MATRIX_HOMESERVER_URL=/d' .env 2>/dev/null || true
          sed -i '/^DIUN_MATRIX_USER=/d' .env 2>/dev/null || true
          sed -i '/^DIUN_MATRIX_PASSWORD=/d' .env 2>/dev/null || true
          sed -i '/^DIUN_MATRIX_ROOM_ID=/d' .env 2>/dev/null || true

          echo "DIUN_MATRIX_HOMESERVER_URL=${MATRIX_SERVER}" >> .env
          echo "DIUN_MATRIX_USER=${BOT_USER}" >> .env
          echo "DIUN_MATRIX_PASSWORD=${BOT_PASSWORD}" >> .env
          echo "DIUN_MATRIX_ROOM_ID=${ROOM_ID}" >> .env

          success "Diun Matrix bot ${BOT_USER} and room ${ROOM_ALIAS} bootstrapped. Env values written to .env."
      fi
  fi
fi

