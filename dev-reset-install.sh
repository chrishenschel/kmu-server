#!/bin/bash
# Dev reset: tear down stack, remove generated data and .env, then pull latest and re-run setup.
# Keeps caddy/ (certificates). Does not remove backups/ by default.
docker compose down -v
rm -f .env
rm -rf ./synapse/
rm -rf ./stalwart/
rm -rf ./element/
rm -rf ./authentik/
# rm -rf ./caddy/   # keep caddy (certificates)
rm -rf ./postgres/
rm -rf ./nextcloud/
rm -rf ./static/
rm -rf ./coturn/
rm -rf ./jitsi/
rm -rf ./vaultwarden/
rm -rf ./immich/
rm -f dns-config.txt
docker volume rm infra_synapse_data 2>/dev/null || true

git stash && git pull && chmod a+x dev-reset-install.sh 02-system-setup.sh backup.sh restore.sh