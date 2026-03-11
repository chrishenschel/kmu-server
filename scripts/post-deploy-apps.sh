#!/bin/bash

# Assumes: log/success/error, domain/username/password, PG_PASS, etc. and stack is up.

. ./scripts/post-deploy-paperless.sh
. ./scripts/post-deploy-stalwart.sh
. ./scripts/post-deploy-nextcloud.sh
. ./scripts/post-deploy-immich.sh
. ./scripts/post-deploy-wiki.sh


