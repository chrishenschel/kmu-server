# Admin Panel

Small web app for non-technical admins to manage users without touching Authentik directly.

## What it does

- **List users** – Shows all Authentik users (internal, active).
- **Add user** – Creates the user in Authentik (with password), creates their mailbox in Stalwart immediately (no wait for user-sync), and **optionally creates the Mail account in Nextcloud** with the same password so the user doesn’t have to type it again. The same password is used for:
  - Authentik / Nextcloud (OIDC) login
  - Mail (Stalwart) – and, if the optional helper runs, the Nextcloud Mail app account is already set with this password.

## Access

- **URL:** `https://admin.<your-domain>` (e.g. `https://admin.tudels.com`)
- **Auth:** Protected by Authentik forward auth. Only users who can access the “Admin Panel” application in Authentik can open it. Assign the app to the “authentik Admins” group (or the group you use for admins) in Authentik so only admins see and use it.

## Setup

1. Run the main setup script so the admin blueprint is applied (adds the Admin Panel app in Authentik and Caddy route).
2. In Authentik: **Applications** → **Admin Panel** → **Policy / Group / User Bindings** → add a binding for the **authentik Admins** group (or your admin group) so only admins can open the panel.
3. Ensure `.env` has `DOMAIN`, `AUTHENTIK_BOOTSTRAP_TOKEN`, `PASSWORD` (Stalwart admin). The admin container reads these from the compose environment.

## Development

- **Backend:** `admin/backend/` – FastAPI app in `app/main.py`.
- **Frontend:** `admin/backend/static/index.html` – single HTML page with minimal JS.
- **Run:** `docker compose up -d admin-panel` (no build: uses `python:3.12-slim` with `./admin/backend` mounted as `/app`; deps are installed on container start, code changes are live).

## Optional: Nextcloud Mail account

When you add a user, the backend tries to create their Mail app account in Nextcloud with the same password (via a script run inside the Nextcloud container). This is optional: if it fails (e.g. Docker not available, Mail app not installed, or script error), the user is still created in Authentik and Stalwart; the response message will note that they can add the Mail account manually with the same password.

- **Requirements:** Admin-panel container must have the Docker socket mounted and the Nextcloud scripts volume (`admin/nextcloud-scripts` → `/usr/local/nextcloud-scripts` in the Nextcloud container). `NEXTCLOUD_CONTAINER_NAME` (default `nextcloud`) must match your Nextcloud service name.
- **Script:** `admin/nextcloud-scripts/create_mail_account.php` runs inside Nextcloud (`php /usr/local/nextcloud-scripts/create_mail_account.php`) and creates the Mail account for the user (IMAP/SMTP at `mail.<DOMAIN>`). Password is passed via stdin to avoid exposing it in process args.
