#!/bin/bash
docker compose down -v
rm .env
rm /synapse/data/*
rm -rf /stalwart/data/etc
rm -rf /stalwart/data/logs
rm -rf /stalwart/data/data

git stash && git pull && chmod a+x dev-reset-install.sh && chmod a+x 02-system-setup.sh