# Wiki.js Admin Bootstrap Automation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ensure Wiki.js is always auto-bootstrapped with an admin user from existing env vars, so the interactive "create admin" wizard never appears on first visit.

**Architecture:** Prefer Wiki.js's native env-based bootstrap when available. If it's unreliable or insufficient, add a small, idempotent bootstrap job that uses env vars to create an admin and mark setup complete, running once against a fresh Wiki.js database.

**Tech Stack:** Docker Compose, Wiki.js, Postgres, Bash/Python (for bootstrap job), existing `.env` secrets.

---

### Task 1: Inspect current Wiki.js behavior and version

**Files:**
- Modify: `docker-compose.yaml` (read-only for now, just to reference)

**Step 1:** Identify the exact Wiki.js image and version.
- Check `WIKI_IMAGE` in `.env` or wherever it is defined.

**Step 2:** Verify documentation for that version.
- Manually look up the official docs/changelog for supported env vars, especially admin/bootstrap-related ones (`ADMIN_EMAIL`, `ADMIN_PASS`, `DB_*`, any `SETUP*` flags).

**Step 3:** Note expected behavior.
- Write down what Wiki.js claims it does on first boot when those env vars are set and DB is empty.

---

### Task 2: Reproduce fresh-boot behavior in a controlled environment

**Files:**
- No code changes yet; use current `docker-compose.yaml`

**Step 1:** Stop the stack safely.
- Run: `docker compose down`

**Step 2:** Reset Wiki.js data in a controlled way.
- Remove the `wiki` database contents only if safe (e.g. `docker volume` or SQL drop of DB `wiki` in a dev/staging environment).
- Remove `./wiki/data` directory contents (or move them aside) in dev/staging, not in production.

**Step 3:** Bring stack back up.
- Run: `docker compose up -d wiki postgres`

**Step 4:** Observe first-visit experience.
- Visit Wiki.js via Caddy (e.g. `https://wiki.<domain>`).
- Confirm whether you see the admin-creation wizard or a fully initialized instance.

**Step 5:** Capture logs.
- Run: `docker logs wiki` and capture any bootstrap-related messages (admin creation, DB init).

---

### Task 3: Align env vars with Wiki.js native bootstrap (if supported)

**Files:**
- Modify: `docker-compose.yaml` (Wiki.js `wiki` service section)
- Modify: `.env` (if needed for `WIKI_ADMIN_EMAIL` or related vars)

**Step 1:** Update env names to match docs.
- If docs use different names (e.g. `WIKIJS_ADMIN_EMAIL` vs `ADMIN_EMAIL`), adjust the `environment:` section for `wiki` accordingly.
- Ensure `DB_TYPE`, `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME` match Wiki.js expectations.

**Step 2:** Ensure admin email/pass are wired from existing secrets.
- Use `WIKI_ADMIN_EMAIL` or `hostmaster@${DOMAIN}` for email.
- Reuse the common `PASSWORD` env var for `ADMIN_PASS`, unless docs recommend a separate secret.

**Step 3:** Re-run fresh-boot test.
- Repeat Task 2 steps (clean DB + `./wiki/data`, bring up `wiki` + `postgres`).
- Confirm whether the admin is now auto-created and the wizard is skipped.

**Step 4:** Decide if native bootstrap is sufficient.
- If the admin appears and the wizard is skipped, document this and consider the task done without extra bootstrap code.
- If behavior is still unreliable or incomplete, proceed to Tasks 4–7 to add an explicit bootstrap job.

---

### Task 4: Design the explicit Wiki.js bootstrap job

**Files:**
- Create: `scripts/wiki-bootstrap.sh` (or `.py` if using Python)
- Optional: `Dockerfile.wiki-bootstrap` for a dedicated bootstrap image

**Step 1:** Define bootstrap responsibilities.
- Wait for Postgres to be ready.
- Wait for Wiki.js HTTP endpoint (e.g. `http://wiki:3000`) to be reachable.
- Check whether an admin user already exists.
- If not, create an admin user with:
  - Email: `WIKI_ADMIN_EMAIL` or `hostmaster@${DOMAIN}`
  - Password: `PASSWORD` from `.env`
- Mark setup as complete so the wizard is never shown.

**Step 2:** Choose interaction method.
- Prefer using Wiki.js's API if it exposes user creation endpoints.
- If no API is suitable, fall back to direct DB access (using SQL) but keep it minimal and schema-aware.

**Step 3:** Define idempotency criteria.
- Ensure the script:
  - Exits cleanly with success if an admin already exists.
  - Fails fast with clear logs if admin creation fails.

---

### Task 5: Implement bootstrap logic against the Wiki.js data model/API

**Files:**
- Modify: `scripts/wiki-bootstrap.sh` (or `.py`)

**Step 1:** Implement readiness checks.
- Add a loop to poll Postgres (e.g. `pg_isready`) until it is healthy or times out.
- Add a loop to poll `http://wiki:3000` (or internal URL) until it returns a healthy response.

**Step 2:** Implement "admin exists?" check.
- If using API: call an endpoint that lists users or returns admin status, authenticating with a known bootstrap token/mechanism if available.
- If using DB:
  - Connect to `wiki` DB as `postgres`.
  - Query the users table to detect any row with admin role (per Wiki.js docs for your version).

**Step 3:** Implement admin creation.
- If using API: send a request to create an admin with the configured email/password and admin role.
- If using DB:
  - Insert a user row with proper password hash (using the method/algorithm Wiki.js expects).
  - Associate the admin role and mark any "setup completed" flag that the wizard checks.

**Step 4:** Implement logging and exit codes.
- Print clear logs for each stage (checking readiness, checking admin, creating admin).
- Exit with 0 on success, non-zero on failure.

---

### Task 6: Wire bootstrap job into Docker Compose

**Files:**
- Modify: `docker-compose.yaml` (add `wiki-bootstrap` service)

**Step 1:** Add `wiki-bootstrap` service definition.
- Use either:
  - An ad-hoc image (e.g. `alpine` with `psql` and `curl` + mounted script), or
  - A dedicated `wiki-bootstrap` image built from `Dockerfile.wiki-bootstrap`.
- Mount the script file and any needed config into the container.

**Step 2:** Configure environment for bootstrap.
- Pass in:
  - `DOMAIN`
  - `WIKI_ADMIN_EMAIL`
  - `PASSWORD`
  - `PG_PASS`
  - DB host/name/user for Wiki.js (`postgres`, `wiki`, `postgres`).

**Step 3:** Set proper dependencies.
- Make `wiki-bootstrap` depend on:
  - `postgres` (using `condition: service_healthy`).
  - `wiki` (if using the HTTP API).

**Step 4:** Ensure bootstrap runs once.
- Decide whether the service should:
  - Run to completion and stop (e.g. `restart: "no"`), or
  - Run periodically but be idempotent (generally less necessary; prefer one-shot).

---

### Task 7: End-to-end test of full stack behavior

**Files:**
- No new files; use full docker-compose stack

**Step 1:** Clean slate in a dev/staging environment.
- Drop the `wiki` DB and clear `./wiki/data` again in non-production.

**Step 2:** Bring up entire stack.
- Run: `docker compose up -d`

**Step 3:** Observe bootstrap logs.
- Run: `docker logs wiki-bootstrap` (or equivalent) to confirm:
  - Postgres ready
  - Wiki reachable
  - Admin existence check
  - Admin created (or detected as already present)

**Step 4:** Verify first user experience.
- Visit `https://wiki.<domain>` via Caddy.
- Confirm:
  - No "create admin" wizard appears.
  - You can log in with the configured admin credentials if needed.

**Step 5:** Verify Authentik/OIDC integration still works.
- Log in via SSO as a normal user and confirm access behaves as expected.

---

### Task 8: Documentation and security review

**Files:**
- Create/Modify: `docs/wiki-bootstrap.md` (or similar ops/infra doc)

**Step 1:** Document bootstrap behavior.
- Describe:
  - How the admin is created (native env vs bootstrap job).
  - Which env vars control admin email/password.
  - In which environments the bootstrap runs.

**Step 2:** Document operational considerations.
- Explain:
  - How to reset Wiki.js in dev/staging safely (DB + data clearing).
  - How to rotate the admin password if needed.
  - Any migration considerations on Wiki.js upgrades (e.g. schema/API changes).

**Step 3:** Review security posture.
- Confirm that:
  - Admin credentials come from secure env vars.
  - Local admin is rarely used; main access is via Authentik/OIDC.
  - Logs do not print secrets (only masked or high-level info).

**Step 4:** (Optional) Plan password rotation.
- Define a process to periodically rotate the bootstrap admin password and update `.env` / secrets storage accordingly.

