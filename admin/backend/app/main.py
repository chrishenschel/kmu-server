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

# Skip TLS verify for internal services
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def auth_headers():
    return {"Authorization": f"Bearer {AUTHENTIK_TOKEN}"}


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


class UserOut(BaseModel):
    uuid: str
    username: str
    name: str
    email: str
    is_active: bool


@app.get("/api/users")
async def list_users():
    """List users from Authentik (internal type, active)."""
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
    users = [
        UserOut(
            uuid=u["uuid"],
            username=u.get("username", ""),
            name=u.get("name", ""),
            email=u.get("email", ""),
            is_active=u.get("is_active", True),
        )
        for u in data.get("results", [])
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
