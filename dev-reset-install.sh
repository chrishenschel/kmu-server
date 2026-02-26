#!/bin/bash
docker compose down -v
rm .env
rm -rf ./synapse/
rm -rf ./stalwart/
rm -rf ./element/
rm -rf ./authentic/
#rm -rf ./caddy/ #keep caddy, because we do not want to get rid of the certificates
rm -rf ./postgres/
rm -rf ./static/
docker volume rm infra_synapse_data

git stash && git pull && chmod a+x dev-reset-install.sh && chmod a+x 02-system-setup.sh && chmod a+x 03-finish-setup.sh