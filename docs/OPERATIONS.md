# Day-to-day operations

Assumes you are in the repo root (e.g. `/root/kmu-server` or your clone path) and `.env` exists.

## Start / stop

```bash
# Start everything
docker compose up -d

# Stop everything
docker compose down

# Restart a single service
docker compose restart authentikserver
```

## Logs

```bash
# All services, follow
docker compose logs -f

# One service
docker compose logs -f caddy
docker compose logs -f nextcloud
docker compose logs -f immich-server
docker compose logs -f vaultwarden

# Last 200 lines
docker compose logs --tail=200 authentikserver
```

## Status and health

```bash
docker compose ps
docker ps   # same, default format
```

Unhealthy containers: check logs, then restart. Common causes: dependency not ready (e.g. postgres), wrong env, or disk full.

## Admin URLs (replace `example.com` with your `DOMAIN`)

| Service | URL | Notes |
|---------|-----|--------|
| Authentik | https://auth.example.com | SSO admin; create users, groups, providers. |
| Nextcloud | https://cloud.example.com | Files, calendar; admin in Settings. |
| Matrix (Synapse) | https://matrix.example.com | Homeserver (admin via Synapse admin API or config). |
| Element | https://element.example.com | Chat client; protected by Authentik. |
| Jitsi Meet | https://meet.example.com | Video; login to create rooms. |
| Stalwart Mail | https://mail.example.com | Webmail / mail admin. |
| Dozzle | https://logs.example.com | Docker logs; protected by Authentik. |
| Admin panel | https://admin.example.com | User management (Authentik, Stalwart, Nextcloud); protected by Authentik. |
| Vaultwarden | https://vaultwarden.example.com | Passwords; use “Single sign-on” to log in with Authentik. |
| Immich | https://immich.example.com | Photos/videos; “Login with OAuth” for Authentik. |

## Adding a user

1. **Authentik**: https://auth.example.com → Directory → Users → Create. Set username, email, password (or send enrollment).
2. **Stalwart**: Either use the Admin panel (https://admin.example.com) to create a mailbox for the same user, or create mailbox in Stalwart and match the local part to the Authentik username if using LDAP.
3. **Nextcloud**: Users log in via “Log in with OAuth” (Authentik); no separate Nextcloud user creation if using OIDC-only.
4. **Vaultwarden / Immich**: Users sign in with SSO/OAuth (Authentik); first login may auto-create the account.

## First login after install

- **Authentik**: Log in with the user created by the admin-user blueprint (the one you passed to `02-system-setup.sh`). First time you may need to complete setup if the wizard was not skipped.
- **Nextcloud**: Use “Log in with OAuth” and the same Authentik user.
- **Element**: Open https://element.example.com; if SSO is configured you are redirected to Authentik, then into Element.
- **Vaultwarden**: Open https://vaultwarden.example.com → “Use single sign-on”.
- **Immich**: Open https://immich.example.com → “Login with OAuth”. First OAuth user often becomes admin.

## Common tasks

### Nextcloud: run occ

```bash
docker exec --user www-data nextcloud php occ status
docker exec --user www-data nextcloud php occ config:list
```

### Reload Caddy (after editing Caddyfile)

```bash
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
# or
docker compose restart caddy
```

### Postgres: connect

```bash
docker compose exec postgres psql -U postgres -d authentik -c "SELECT 1;"
# List databases: -d postgres then \l
```

### Backup (see README)

```bash
./backup.sh           # stop stack, snapshot, start stack
./backup.sh --online # snapshot while running (no downtime)
```

### Restore

```bash
./restore.sh backups/snapshots/20260227-120000
```

## Troubleshooting quick checks

- **502 / 503 from Caddy**: Backend container down or unhealthy. `docker compose ps` and `docker compose logs <service>`.
- **OAuth “redirect_uri mismatch”**: In Authentik, check the provider’s redirect URIs exactly match the URL (scheme, host, path). No trailing slash unless the app sends it.
- **Can’t log in to Nextcloud with OIDC**: Confirm `NC_CLIENT_ID` / `NC_CLIENT_SECRET` in `.env` match the Authentik provider; in Nextcloud, OIDC app redirect URLs must match.
- **Mail not received/sent**: Check Stalwart logs; ensure `LDAP_OUTPOST_TOKEN` is set and authentik-ldap is running; check DNS (MX, SPF, DKIM) if sending to the internet.

See also [README § Troubleshooting](../README.md#14-troubleshooting).
