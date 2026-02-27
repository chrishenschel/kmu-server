#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Default: stop stack before backup so no files are written during backup.
# Use --online to backup while the stack is running (faster, but not guaranteed consistent for all files).
STOP_STACK=true
for arg in "$@"; do
  case "$arg" in
    --online)
      STOP_STACK=false
      ;;
    -h|--help)
      echo "Usage: $0 [--online]"
      echo ""
      echo "  (default)  Stop the stack, then take a snapshot (no writes during backup)."
      echo "  --online   Take snapshot while the stack is running (no downtime; files may be in use)."
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Use --help for usage." >&2
      exit 1
      ;;
  esac
done

SNAPSHOT_BASE="backups/snapshots"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
SNAPSHOT_DIR="${SNAPSHOT_BASE}/${TIMESTAMP}"

mkdir -p "$SNAPSHOT_DIR"

echo "Creating KMU snapshot in ${SNAPSHOT_DIR}"
if [ "$STOP_STACK" = true ]; then
  echo "Mode: stack will be stopped during backup (no writes)."
else
  echo "Mode: online backup (stack keeps running)."
fi

if [ -f ".env" ]; then
  echo "Copying .env into snapshot"
  cp .env "${SNAPSHOT_DIR}/env"
else
  echo "WARNING: .env not found; secrets will not be included in this snapshot."
fi

if [ "$STOP_STACK" = true ]; then
  echo "Stopping the full stack..."
  docker compose down
  echo "Starting postgres only for dump..."
  docker compose up -d postgres
fi

echo "Ensuring postgres service is running..."
docker compose up -d postgres

echo "Waiting for postgres to become ready..."
until docker compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; do
  echo "  postgres not ready yet, retrying in 2s..."
  sleep 2
done

echo "Dumping Postgres cluster to ${SNAPSHOT_DIR}/postgres.sql ..."
docker compose exec -T postgres pg_dumpall -U postgres -c > "${SNAPSHOT_DIR}/postgres.sql"

if [ "$STOP_STACK" = true ]; then
  echo "Stopping postgres so data directories are idle..."
  docker compose down
fi

echo "Archiving service data directories..."

declare -a PATHS=(
  "authentik/data"
  "authentik/blueprints"
  "authentik/custom-templates"
  "synapse/data"
  "nextcloud/apps"
  "nextcloud/config"
  "nextcloud/data"
  "nextcloud/theme"
  "stalwart/data"
  "vaultwarden/data"
  "immich/library"
  "immich/immich.json"
  "caddy/data"
  "caddy/config"
  "caddy/logs"
  "jitsi/config"
  "backups/postgres"
)

MANIFEST="${SNAPSHOT_DIR}/paths.manifest"
touch "$MANIFEST"

for path in "${PATHS[@]}"; do
  if [ -e "$path" ]; then
    slug="$(echo "$path" | tr '/.' '__')"
    echo "${slug} ${path}" >> "$MANIFEST"
    echo "  Archiving ${path} -> ${slug}.tar.gz"
    tar czf "${SNAPSHOT_DIR}/${slug}.tar.gz" "$path"
  else
    echo "  Skipping missing path: ${path}"
  fi
done

if [ "$STOP_STACK" = true ]; then
  echo "Starting the full stack again..."
  docker compose up -d
fi

echo "Snapshot completed successfully: ${SNAPSHOT_DIR}"

