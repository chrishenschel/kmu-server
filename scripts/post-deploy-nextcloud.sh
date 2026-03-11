#!/bin/bash

# Nextcloud OIDC configuration and app setup

log "Waiting for Nextcloud container to be ready..."
ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT + 1))
    if docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: true"; then
        success "Nextcloud is already installed."
        break
    fi
    if docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: false"; then
        log "Nextcloud is not installed. Removing partial config so install command is available..."
        docker exec nextcloud rm -f /var/www/html/config/config.php /var/www/html/config/autoconfig.php 2>/dev/null || true
        sleep 2
        if docker exec --user www-data nextcloud php occ maintenance:install --help &>/dev/null; then
            log "Running maintenance:install..."
            docker exec --user www-data nextcloud php occ maintenance:install \
                --database=pgsql \
                --database-name=nextcloud \
                --database-user=postgres \
                --database-pass="$PG_PASS" \
                --database-host=postgres \
                --admin-user="$username" \
                --admin-pass="$password" \
                --data-dir=/var/www/html/data
            success "Nextcloud installed."
        else
            log "Install command still not available. Triggering install via container entrypoint (restart)..."
            docker compose restart nextcloud
            log "Waiting for Nextcloud to install (entrypoint runs on start)..."
            for i in $(seq 1 60); do
                sleep 10
                if docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: true"; then
                    success "Nextcloud installed via entrypoint."
                    break
                fi
                log "  Waiting... ($i/60)"
            done
        fi
        if docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: true"; then
            log "Configuring trusted domain and overwrite URL..."
            docker exec --user www-data nextcloud php occ config:system:set trusted_domains 0 --value="cloud.${domain}"
            docker exec --user www-data nextcloud php occ config:system:set overwriteprotocol --value=https
            docker exec --user www-data nextcloud php occ config:system:set overwrite.cli.url --value="https://cloud.${domain}"
            success "Nextcloud base config set."
        fi
        break
    fi
    if [ $ATTEMPT -ge 60 ]; then
        error "Nextcloud did not become ready after 60 attempts. Skipping OIDC config."
        break
    fi
    log "  Attempt $ATTEMPT - Nextcloud container not ready yet, waiting 10s..."
    sleep 10
done

log "Ensuring HTTPS/overwrite settings (required for OIDC behind reverse proxy)..."
docker exec --user www-data nextcloud php occ config:system:set overwriteprotocol --value=https
docker exec --user www-data nextcloud php occ config:system:set overwrite.cli.url --value="https://cloud.${domain}"
docker exec --user www-data nextcloud php occ config:system:set overwritehost --value="cloud.${domain}"
docker exec --user www-data nextcloud php occ config:system:set trusted_proxies 0 --value="172.16.0.0/12"
docker exec --user www-data nextcloud php occ config:system:set trusted_proxies 1 --value="10.0.0.0/8" 2>/dev/null || true

log "Allowing local remote servers (needed for Docker-internal OIDC discovery)..."
docker exec --user www-data nextcloud php occ config:system:set allow_local_remote_servers --value=true --type=boolean

log "Setting default language to German..."
docker exec --user www-data nextcloud php occ config:system:set default_language --value=de

log "Installing OpenID Connect user backend app..."
docker exec --user www-data nextcloud php occ app:install user_oidc
success "user_oidc app installed."

log "Creating OIDC provider for Authentik..."
docker exec --user www-data nextcloud php occ user_oidc:provider authentik \
    --clientid="$NC_CLIENT_ID" \
    --clientsecret="$NC_CLIENT_SECRET" \
    --discoveryuri="https://auth.${domain}/application/o/nextcloud/.well-known/openid-configuration" \
    --scope="email profile nextcloud openid" \
    --mapping-uid="user_id" \
    --mapping-display-name="name" \
    --mapping-email="email" \
    --mapping-quota="quota" \
    --mapping-groups="groups" \
    --unique-uid=0 \
    --group-provisioning=1
success "OIDC provider created."

log "Setting OIDC as the default login method..."
docker exec --user www-data nextcloud php occ config:app:set --value=0 user_oidc allow_multiple_user_backends
success "Nextcloud OIDC configuration complete."

log "Setting up Nextcloud apps..."
docker exec --user www-data nextcloud php occ app:disable twofactor_totp
docker exec --user www-data nextcloud php occ app:enable files_accesscontrol files_retention calendar richdocumentscode contacts mail richdocuments deck groupfolders whiteboard collectives tables jitsi drawio
log "Configuring Nextcloud Jitsi integration..."
docker exec --user www-data nextcloud php occ config:app:set --value="https://meet.${domain}/" jitsi jitsi_server_url
success "Nextcloud apps setup complete (including Jitsi integration)."

log "Configuring Nextcloud to send mail via noreply@${domain} (Stalwart SMTP)..."
docker exec --user www-data nextcloud php occ config:system:set mail_smtpmode --value=smtp
docker exec --user www-data nextcloud php occ config:system:set mail_smtphost --value=stalwart-mail
docker exec --user www-data nextcloud php occ config:system:set mail_smtpport --value=465 --type=integer
docker exec --user www-data nextcloud php occ config:system:set mail_smtpsecure --value=ssl
docker exec --user www-data nextcloud php occ config:system:set mail_smtpauth --value=1 --type=integer
docker exec --user www-data nextcloud php occ config:system:set mail_smtpname --value="noreply@${domain}"
docker exec --user www-data nextcloud php occ config:system:set mail_smtppassword --value="$NOREPLY_PASS"
docker exec --user www-data nextcloud php occ config:system:set mail_from_address --value=noreply
docker exec --user www-data nextcloud php occ config:system:set mail_domain --value="${domain}"
success "Nextcloud outgoing mail set to noreply@${domain}."

