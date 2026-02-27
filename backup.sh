#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

SNAPSHOT_BASE="backups/snapshots"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
SNAPSHOT_DIR="${SNAPSHOT_BASE}/${TIMESTAMP}"

mkdir -p "$SNAPSHOT_DIR"

echo "Creating KMU snapshot in ${SNAPSHOT_DIR}"

if [ -f ".env" ]; then
  echo "Copying .env into snapshot"
  cp .env "${SNAPSHOT_DIR}/env"
else
  echo "WARNING: .env not found; secrets will not be included in this snapshot."
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

echo "Archiving service data directories..."

declare -a PATHS=(
  "authentik/data"
  "synapse/data"
  "nextcloud/apps"
  "nextcloud/config"
  "nextcloud/data"
  "nextcloud/theme"
  "stalwart/data"
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

echo "Snapshot completed successfully: ${SNAPSHOT_DIR}"

