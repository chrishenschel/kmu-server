# Updating the installation

This repo is a single installation: you run it once, then later you may pull updates (script fixes, new services, docs). Data lives on the server in `.env`, `./authentik`, `./nextcloud`, etc.—**nothing critical is stored in git**.

## 1. Backup before updating

```bash
./backup.sh
```

Keep the snapshot (e.g. on another disk or machine) until you have verified the update.

## 2. Pull latest code

```bash
git pull
# or, if you have local changes you don’t want to lose:
git stash
git pull
git stash pop
```

## 3. Re-read the docs and changelog

- Check [README](../README.md) and files in [docs/](.) for new steps or breaking changes.
- If the repo has a `CHANGELOG` or release notes, read them.

## 4. Apply config changes (if any)

- **Caddyfile**: If `Caddyfile` or routing changed, compare with your running config. Your `__DOMAIN__` will already be replaced; only add/change blocks if the update introduces new services or routes.
- **docker-compose.yaml**: New services or env vars may have been added. Do not blindly overwrite your `.env`; merge any new variables mentioned in the docs or `.env.example`.
- **Authentik blueprints**: New or updated blueprints under `authentik/blueprints/` might be added. The update process does **not** automatically re-run `02-system-setup.sh` (it would overwrite secrets). If the docs say “add blueprint X”, load it in Authentik (Customization → Blueprints) or apply the YAML manually.

## 5. Pull images and recreate containers

```bash
docker compose pull
docker compose up -d
```

If the compose file added new services, they will start. If env vars or volumes changed, fix any errors (e.g. add missing variables to `.env`) and run again.

## 6. Run migrations / post-update steps (if documented)

Some updates require one-off steps, e.g.:

- Nextcloud: `docker exec --user www-data nextcloud php occ upgrade`
- Authentik: usually automatic on startup.
- Immich / others: check the project’s release notes.

Do only what the update instructions or release notes say.

## 7. Smoke test

- Open Authentik, Nextcloud, Element, Vaultwarden, Immich (and any new service).
- Log in once with SSO/OAuth and with a test user.
- If something breaks, restore from the snapshot you took in step 1 and report or fix the issue.

## If you never use git again

You can keep running the same copy of the repo without ever pulling. For security and bugfixes it’s better to pull occasionally and follow the steps above. All your data is in:

- `.env`
- `backups/snapshots/`
- Service data dirs (see [backup.sh](../backup.sh): authentik, synapse, nextcloud, stalwart, vaultwarden, immich, caddy, jitsi, etc.)

So you can always restore from a backup on a fresh clone if needed.
