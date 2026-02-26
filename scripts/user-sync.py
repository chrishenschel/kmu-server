#!/usr/bin/env python3
"""Syncs users from Authentik to Stalwart Mail.
Runs in a loop, checking every SYNC_INTERVAL seconds (default 300 = 5 min).
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
import base64
import ssl

DOMAIN = os.environ.get("DOMAIN", "")
STALWART_URL = os.environ.get("STALWART_URL", f"http://stalwart-mail:8080")
STALWART_ADMIN_USER = os.environ.get("STALWART_ADMIN_USER", "admin")
STALWART_ADMIN_PASS = os.environ.get("STALWART_ADMIN_PASS", "")
AUTHENTIK_URL = os.environ.get("AUTHENTIK_URL", "http://authentik-server:9000")
AUTHENTIK_TOKEN = os.environ.get("AUTHENTIK_TOKEN", "")
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "300"))

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def stalwart_auth_header():
    creds = base64.b64encode(f"{STALWART_ADMIN_USER}:{STALWART_ADMIN_PASS}".encode()).decode()
    return f"Basic {creds}"


def api_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  GET {url} failed: {e}", flush=True)
        return None


def api_post(url, data, headers=None):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {}, method="POST")
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except:
            return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def get_authentik_users():
    url = f"{AUTHENTIK_URL}/api/v3/core/users/?is_active=true&type=internal&page_size=500"
    headers = {"Authorization": f"Bearer {AUTHENTIK_TOKEN}"}
    return api_get(url, headers)


def get_stalwart_users():
    url = f"{STALWART_URL}/api/principal?type=individual"
    headers = {"Authorization": stalwart_auth_header()}
    return api_get(url, headers)


def create_stalwart_user(username, email):
    url = f"{STALWART_URL}/api/principal"
    headers = {
        "Authorization": stalwart_auth_header(),
        "Content-Type": "application/json",
    }
    payload = {"type": "individual", "name": username, "emails": [email]}
    return api_post(url, payload, headers)


def sync():
    authentik_data = get_authentik_users()
    if not authentik_data or "results" not in authentik_data:
        print("Could not fetch users from Authentik", flush=True)
        return

    stalwart_data = get_stalwart_users()
    existing = set()
    if stalwart_data and "data" in stalwart_data:
        existing = {u["name"] for u in stalwart_data["data"].get("items", [])}

    created = 0
    for user in authentik_data["results"]:
        username = user.get("username", "")
        if not username or username == "akadmin":
            continue
        if username in existing:
            continue

        email = f"{username}@{DOMAIN}"
        result = create_stalwart_user(username, email)
        if result and "error" not in result:
            print(f"Created mailbox for {username} <{email}>", flush=True)
            created += 1
        else:
            print(f"Skipped {username}: {result}", flush=True)

    if created == 0:
        print(f"All {len(existing)} user(s) already synced.", flush=True)
    else:
        print(f"Synced {created} new mailbox(es).", flush=True)


def main():
    if not DOMAIN:
        print("ERROR: DOMAIN not set", flush=True)
        sys.exit(1)
    if not STALWART_ADMIN_PASS:
        print("ERROR: STALWART_ADMIN_PASS not set", flush=True)
        sys.exit(1)
    if not AUTHENTIK_TOKEN:
        print("ERROR: AUTHENTIK_TOKEN not set", flush=True)
        sys.exit(1)

    print(f"User sync started: Authentik ({AUTHENTIK_URL}) -> Stalwart ({STALWART_URL})", flush=True)
    print(f"Domain: {DOMAIN}, interval: {SYNC_INTERVAL}s", flush=True)

    while True:
        try:
            sync()
        except Exception as e:
            print(f"Sync error: {e}", flush=True)
        time.sleep(SYNC_INTERVAL)


if __name__ == "__main__":
    main()
