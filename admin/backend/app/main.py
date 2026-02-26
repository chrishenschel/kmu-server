"""
Admin panel backend: manage users in Authentik, Stalwart, and optionally Nextcloud Mail.
Protected by Authentik forward auth; only admins should have access.
"""
import os
import ssl
from contextlib import asynccontextmanager

import docker
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

load_dotenv()

AUTHENTIK_URL = os.environ.get("AUTHENTIK_URL", "http://authentik-server:9000").rstrip("/")
AUTHENTIK_TOKEN = os.environ.get("AUTHENTIK_TOKEN", "")
STALWART_URL = os.environ.get("STALWART_URL", "http://stalwart-mail:8080").rstrip("/")
STALWART_ADMIN_USER = os.environ.get("STALWART_ADMIN_USER", "admin")
STALWART_ADMIN_PASS = os.environ.get("STALWART_ADMIN_PASS", "")
DOMAIN = os.environ.get("DOMAIN", "")
NEXTCLOUD_CONTAINER = os.environ.get("NEXTCLOUD_CONTAINER_NAME", "nextcloud")

# Authentik admin group name (used for "set as admin" toggle)
ADMIN_GROUP_NAME = os.environ.get("AUTHENTIK_ADMIN_GROUP_NAME", "authentik Admins")

# Skip TLS verify for internal services
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def auth_headers():
    return {"Authorization": f"Bearer {AUTHENTIK_TOKEN}"}


async def _get_user_by_uuid(client: httpx.AsyncClient, uuid: str) -> tuple[int | None, dict | None]:
    """Return (pk, user_data) or (None, None) if not found."""
    r = await client.get(
        f"{AUTHENTIK_URL}/api/v3/core/users/",
        params={"uuid": uuid, "page_size": 1},
        headers=auth_headers(),
    )
    if r.status_code != 200:
        return None, None
    data = r.json()
    results = data.get("results", [])
    if not results:
        return None, None
    u = results[0]
    return u.get("pk"), u


async def _get_admin_group_uuid(client: httpx.AsyncClient) -> str | None:
    """Return the uuid of the group named ADMIN_GROUP_NAME, or None."""
    r = await client.get(
        f"{AUTHENTIK_URL}/api/v3/core/groups/",
        params={"search": ADMIN_GROUP_NAME, "page_size": 10},
        headers=auth_headers(),
    )
    if r.status_code != 200:
        return None
    for g in r.json().get("results", []):
        if g.get("name") == ADMIN_GROUP_NAME:
            return g.get("uuid")
    return None


async def _get_admin_group_member_pks(client: httpx.AsyncClient) -> set[int]:
    """Return set of user pks that are members of ADMIN_GROUP_NAME."""
    out: set[int] = set()
    r = await client.get(
        f"{AUTHENTIK_URL}/api/v3/core/groups/",
        params={"search": ADMIN_GROUP_NAME, "page_size": 10},
        headers=auth_headers(),
    )
    if r.status_code != 200:
        return out
    for g in r.json().get("results", []):
        if g.get("name") != ADMIN_GROUP_NAME:
            continue
        gd = await client.get(
            f"{AUTHENTIK_URL}/api/v3/core/groups/{g['pk']}/",
            headers=auth_headers(),
        )
        if gd.status_code != 200:
            continue
        members = gd.json().get("users") or gd.json().get("users_obj") or []
        for m in members:
            pk = m.get("pk") if isinstance(m, dict) else m
            if pk is not None:
                out.add(int(pk))
        break
    return out


def stalwart_auth():
    import base64
    creds = base64.b64encode(f"{STALWART_ADMIN_USER}:{STALWART_ADMIN_PASS}".encode()).decode()
    return f"Basic {creds}"


def create_nextcloud_mail_account(uid: str, email: str, password: str) -> tuple[bool, str]:
    """Run the create_mail_account.php script inside the Nextcloud container via Docker API. Returns (success, message)."""
    mail_host = f"mail.{DOMAIN}" if DOMAIN else "localhost"
    env = [
        f"NC_MAIL_UID={uid}",
        f"NC_MAIL_EMAIL={email}",
        f"NC_MAIL_PASSWORD={password}",
        f"NC_MAIL_HOST={mail_host}",
    ]
    cmd = ["php", "/usr/local/nextcloud-scripts/create_mail_account.php"]
    try:
        client = docker.from_env()
        container = client.containers.get(NEXTCLOUD_CONTAINER)
        exit_code, output = container.exec_run(cmd, environment=env, user="www-data", workdir="/var/www/html")
        out = (output or b"").decode("utf-8", errors="replace").strip()
        if exit_code == 0:
            return True, "Nextcloud Mail account created."
        return False, out or f"Exit code {exit_code}"
    except docker.errors.NotFound:
        return False, f"Container '{NEXTCLOUD_CONTAINER}' not found."
    except docker.errors.APIError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    # shutdown
    pass


app = FastAPI(title="Admin Panel", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files (mounted at /admin/static in container)
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR, html=True), name="static")


class UserCreate(BaseModel):
    username: str
    name: str = ""
    email: str = ""
    password: str


class UserUpdate(BaseModel):
    name: str | None = None
    email: str | None = None
    is_active: bool | None = None
    is_admin: bool | None = None


class UserSetPassword(BaseModel):
    password: str


class UserOut(BaseModel):
    uuid: str
    username: str
    name: str
    email: str
    is_active: bool
    is_admin: bool = False


@app.get("/api/users")
async def list_users():
    """List users from Authentik (internal type, active). Includes is_admin from group membership."""
    if not AUTHENTIK_TOKEN:
        raise HTTPException(status_code=503, detail="AUTHENTIK_TOKEN not configured")
    async with httpx.AsyncClient(verify=SSL_CTX, timeout=15.0) as client:
        r = await client.get(
            f"{AUTHENTIK_URL}/api/v3/core/users/",
            params={"is_active": "true", "type": "internal", "page_size": 500},
            headers=auth_headers(),
        )
        r.raise_for_status()
        data = r.json()
        users_list = data.get("results", [])

        # Resolve admin group and get member pks
        admin_pks: set[int] = set()
        if users_list:
            admin_pks = await _get_admin_group_member_pks(client)

        users = [
            UserOut(
                uuid=u["uuid"],
                username=u.get("username", ""),
                name=u.get("name", ""),
                email=u.get("email", ""),
                is_active=u.get("is_active", True),
                is_admin=u.get("pk") in admin_pks if u.get("pk") is not None else False,
            )
            for u in users_list
        ]
    return {"users": users}


@app.post("/api/users")
async def create_user(body: UserCreate):
    """
    Create user in Authentik (with password), then create mailbox in Stalwart.
    Nextcloud Mail: default account template is used; user enters same password once in Mail app.
    """
    if not AUTHENTIK_TOKEN:
        raise HTTPException(status_code=503, detail="AUTHENTIK_TOKEN not configured")
    if not DOMAIN:
        raise HTTPException(status_code=503, detail="DOMAIN not configured")
    username = (body.username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=400, detail="Username required")
    name = (body.name or "").strip() or username
    email = (body.email or "").strip() or f"{username}@{DOMAIN}"
    password = body.password
    if not password:
        raise HTTPException(status_code=400, detail="Password required")

    async with httpx.AsyncClient(verify=SSL_CTX, timeout=15.0) as client:
        # 1. Create user in Authentik
        create_payload = {
            "username": username,
            "name": name,
            "email": email,
            "path": "users",
            "type": "internal",
            "is_active": True,
        }
        r = await client.post(
            f"{AUTHENTIK_URL}/api/v3/core/users/",
            json=create_payload,
            headers={**auth_headers(), "Content-Type": "application/json"},
        )
        if r.status_code == 400 and "unique" in (r.text or "").lower():
            raise HTTPException(status_code=400, detail=f"User '{username}' already exists")
        r.raise_for_status()
        user_data = r.json()
        user_uuid = user_data.get("uuid")
        user_pk = user_data.get("pk")  # Authentik set_password may use pk
        if not user_uuid:
            raise HTTPException(status_code=500, detail="Authentik did not return user uuid")

        # 2. Set password in Authentik (endpoint may use pk)
        user_id = user_pk if user_pk is not None else user_uuid
        set_pw = await client.post(
            f"{AUTHENTIK_URL}/api/v3/core/users/{user_id}/set_password/",
            json={"password": password},
            headers={**auth_headers(), "Content-Type": "application/json"},
        )
        if set_pw.status_code not in (200, 204):
            await client.delete(f"{AUTHENTIK_URL}/api/v3/core/users/{user_uuid}/", headers=auth_headers())
            raise HTTPException(
                status_code=set_pw.status_code,
                detail=f"Failed to set password: {set_pw.text}",
            )

        # 3. Create mailbox in Stalwart (so no wait for user-sync)
        if STALWART_ADMIN_PASS:
            stalwart_payload = {"type": "individual", "name": username, "emails": [email]}
            s = await client.post(
                f"{STALWART_URL}/api/principal",
                json=stalwart_payload,
                headers={
                    "Authorization": stalwart_auth(),
                    "Content-Type": "application/json",
                },
            )
            if s.status_code not in (200, 201) and "already exists" not in (s.text or "").lower():
                # Non-fatal: user-sync will create it later
                pass

    # 4. Create Nextcloud Mail account with the same password (so user doesn't type it)
    nc_ok, nc_msg = create_nextcloud_mail_account(username, email, password)
    if not nc_ok:
        nc_msg = f"Nextcloud Mail: {nc_msg} (user can add account manually with this password)."

    return {
        "ok": True,
        "message": f"User '{username}' created. Mailbox at {email}. "
        + ("Nextcloud Mail account created with this password." if nc_ok else nc_msg),
        "user": {"username": username, "name": name, "email": email},
    }


@app.get("/api/users/{uuid}")
async def get_user(uuid: str):
    """Get one user by uuid."""
    if not AUTHENTIK_TOKEN:
        raise HTTPException(status_code=503, detail="AUTHENTIK_TOKEN not configured")
    async with httpx.AsyncClient(verify=SSL_CTX, timeout=15.0) as client:
        pk, user = await _get_user_by_uuid(client, uuid)
        if not user or pk is None:
            raise HTTPException(status_code=404, detail="User not found")
        admin_pks = await _get_admin_group_member_pks(client)
        return {
            "uuid": user["uuid"],
            "username": user.get("username", ""),
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "is_active": user.get("is_active", True),
            "is_admin": pk in admin_pks,
        }


@app.patch("/api/users/{uuid}")
async def update_user(uuid: str, body: UserUpdate):
    """Update user details and/or admin status."""
    if not AUTHENTIK_TOKEN:
        raise HTTPException(status_code=503, detail="AUTHENTIK_TOKEN not configured")
    async with httpx.AsyncClient(verify=SSL_CTX, timeout=15.0) as client:
        pk, user = await _get_user_by_uuid(client, uuid)
        if not user or pk is None:
            raise HTTPException(status_code=404, detail="User not found")

        payload: dict = {}
        if body.name is not None:
            payload["name"] = body.name
        if body.email is not None:
            payload["email"] = body.email
        if body.is_active is not None:
            payload["is_active"] = body.is_active

        if payload:
            pr = await client.patch(
                f"{AUTHENTIK_URL}/api/v3/core/users/{pk}/",
                json=payload,
                headers={**auth_headers(), "Content-Type": "application/json"},
            )
            if pr.status_code not in (200, 204):
                raise HTTPException(status_code=pr.status_code, detail=pr.text)

        if body.is_admin is not None:
            admin_uuid = await _get_admin_group_uuid(client)
            if not admin_uuid:
                raise HTTPException(status_code=503, detail=f"Admin group '{ADMIN_GROUP_NAME}' not found")
            if body.is_admin:
                ar = await client.post(
                    f"{AUTHENTIK_URL}/api/v3/core/groups/{admin_uuid}/add_user/",
                    json={"pk": pk},
                    headers={**auth_headers(), "Content-Type": "application/json"},
                )
            else:
                ar = await client.post(
                    f"{AUTHENTIK_URL}/api/v3/core/groups/{admin_uuid}/remove_user/",
                    json={"pk": pk},
                    headers={**auth_headers(), "Content-Type": "application/json"},
                )
            if ar.status_code not in (200, 204):
                raise HTTPException(status_code=ar.status_code, detail=ar.text or "Failed to update admin status")

    return {"ok": True, "message": "User updated."}


@app.delete("/api/users/{uuid}")
async def delete_user(uuid: str):
    """Delete user from Authentik."""
    if not AUTHENTIK_TOKEN:
        raise HTTPException(status_code=503, detail="AUTHENTIK_TOKEN not configured")
    async with httpx.AsyncClient(verify=SSL_CTX, timeout=15.0) as client:
        pk, _ = await _get_user_by_uuid(client, uuid)
        if pk is None:
            raise HTTPException(status_code=404, detail="User not found")
        r = await client.delete(
            f"{AUTHENTIK_URL}/api/v3/core/users/{pk}/",
            headers=auth_headers(),
        )
        if r.status_code not in (200, 204):
            raise HTTPException(status_code=r.status_code, detail=r.text)
    return {"ok": True, "message": "User deleted."}


@app.post("/api/users/{uuid}/set-password")
async def set_password(uuid: str, body: UserSetPassword):
    """Change user password in Authentik."""
    if not AUTHENTIK_TOKEN:
        raise HTTPException(status_code=503, detail="AUTHENTIK_TOKEN not configured")
    if not body.password:
        raise HTTPException(status_code=400, detail="Password required")
    async with httpx.AsyncClient(verify=SSL_CTX, timeout=15.0) as client:
        pk, _ = await _get_user_by_uuid(client, uuid)
        if pk is None:
            raise HTTPException(status_code=404, detail="User not found")
        r = await client.post(
            f"{AUTHENTIK_URL}/api/v3/core/users/{pk}/set_password/",
            json={"password": body.password},
            headers={**auth_headers(), "Content-Type": "application/json"},
        )
        if r.status_code not in (200, 204):
            raise HTTPException(status_code=r.status_code, detail=r.text)
    return {"ok": True, "message": "Password updated."}


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def index():
    """Serve the admin frontend."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.isfile(index_path):
        from fastapi.responses import FileResponse
        return FileResponse(index_path)
    return {"message": "Admin API. Mount /static for frontend.", "docs": "/docs"}
