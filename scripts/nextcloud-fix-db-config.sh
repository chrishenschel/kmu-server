#!/bin/bash
# Fix Nextcloud config.php to use PostgreSQL user "postgres" instead of "oc_admin".
# Run from repo root. Requires .env with PG_PASS set.
# Usage: ./scripts/nextcloud-fix-db-config.sh

set -e
cd "$(dirname "$0")/.."

CONFIG="nextcloud/config/config.php"
if [ ! -f "$CONFIG" ]; then
    echo "No $CONFIG found. Nothing to fix." >&2
    exit 0
fi

if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

if [ -z "${PG_PASS:-}" ]; then
    echo "ERROR: PG_PASS not set. Source .env or export it." >&2
    exit 1
fi

echo "Updating dbuser to 'postgres' in $CONFIG"
sed -i "s/'dbuser' => '[^']*'/'dbuser' => 'postgres'/" "$CONFIG"

echo "Updating dbpassword from .env"
export PG_PASS
python3 - "$CONFIG" << 'PY'
import os, re, sys
path = sys.argv[1]
pg_pass = os.environ.get("PG_PASS", "")
# Escape for PHP single-quoted string: \ -> \\, ' -> '\''
escaped = pg_pass.replace("\\", "\\\\").replace("'", "\\'")
with open(path) as f:
    c = f.read()
c = re.sub(r"('dbpassword' => )'[^']*'", r"\1'" + escaped + "'", c)
with open(path, "w") as f:
    f.write(c)
PY

echo "Done. Restart Nextcloud: docker compose restart nextcloud"
grep -E "'dbuser'|'dbpassword'" "$CONFIG" | sed "s/'dbpassword' => '[^']*'/'dbpassword' => '***'/"
