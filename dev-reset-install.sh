#!/bin/bash
docker compose down -v
rm .env
rm -rf ./synapse/
rm -rf ./stalwart/
rm -rf ./element/
rm -rf ./authentic/
rm -rf ./caddy/
rm -rf ./postgres/
rm -rf ./static/

git stash && git pull && chmod a+x dev-reset-install.sh && chmod a+x 02-system-setup.sh