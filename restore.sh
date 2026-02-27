#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

SNAPSHOT_DIR="${1:-}"

if [ -z "$SNAPSHOT_DIR" ]; then
  echo "Usage: $0 backups/snapshots/<timestamp>"
  echo
  echo "Example:"
  echo "  ./restore.sh backups/snapshots/20260227-120000"
  exit 1
fi

if [ ! -d "$SNAPSHOT_DIR" ]; then
  echo "ERROR: Snapshot directory not found: ${SNAPSHOT_DIR}"
  exit 1
fi

if [ ! -f "${SNAPSHOT_DIR}/postgres.sql" ]; then
  echo "ERROR: No postgres.sql found in snapshot: ${SNAPSHOT_DIR}"
  exit 1
fi

echo "About to restore KMU server from snapshot:"
echo "  ${SNAPSHOT_DIR}"
echo
echo "This will:"
echo "- Stop the current docker compose stack (docker compose down)"
echo "- Overwrite service data directories from the snapshot"
echo "- Restore the entire Postgres cluster from postgres.sql"
echo
read -rp "Continue? [y/N] " answer
case "$answer" in
  y|Y|yes|YES) ;;
  *) echo "Aborted."; exit 1 ;;
esac

echo "Stopping docker compose stack..."
docker compose down

MANIFEST="${SNAPSHOT_DIR}/paths.manifest"
if [ -f "$MANIFEST" ]; then
  echo "Restoring data directories from snapshot..."
  while read -r slug path; do
    [ -z "$slug" ] && continue
    archive="${SNAPSHOT_DIR}/${slug}.tar.gz"
    if [ ! -f "$archive" ]; then
      echo "  Archive missing for ${path} (${slug}), skipping"
      continue
    fi
    echo "  Restoring ${path} from $(basename "$archive")"
    rm -rf "$path"
    mkdir -p "$(dirname "$path")"
    tar xzf "$archive"
  done < "$MANIFEST"
else
  echo "WARNING: No paths.manifest found in snapshot; skipping data directory restore."
fi

if [ -f "${SNAPSHOT_DIR}/env" ]; then
  echo
  read -rp "Snapshot contains an env file. Overwrite current .env with snapshot env? [y/N] " env_answer
  case "$env_answer" in
    y|Y|yes|YES)
      cp "${SNAPSHOT_DIR}/env" .env
      echo "  Restored .env from snapshot."
      ;;
    *)
      echo "  Keeping existing .env."
      ;;
  esac
fi

echo "Starting postgres service..."
docker compose up -d postgres

echo "Waiting for postgres to become ready..."
until docker compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; do
  echo "  postgres not ready yet, retrying in 2s..."
  sleep 2
done

echo "Restoring Postgres cluster from dump..."
cat "${SNAPSHOT_DIR}/postgres.sql" | docker compose exec -T postgres psql -U postgres postgres

echo "Bringing up full docker compose stack..."
docker compose up -d

echo "Restore completed successfully from snapshot: ${SNAPSHOT_DIR}"

