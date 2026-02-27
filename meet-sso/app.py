"""
Jitsi Meet SSO bridge: when authenticated users hit meet.<domain>/login[/room],
we receive X-Authentik-* headers, issue a JWT, and redirect to meet.<domain>/[room]?jwt=...
so they join as moderator. Guests use meet.<domain>/room directly without /login.
"""
import os
import time
from urllib.parse import urlencode, urlunparse

import jwt
from flask import Flask, redirect, request

app = Flask(__name__)

JWT_APP_ID = os.environ.get("JWT_APP_ID", "jitsi")
JWT_APP_SECRET = os.environ.get("JWT_APP_SECRET", "")
MEET_DOMAIN = os.environ.get("MEET_DOMAIN", "")  # XMPP domain, e.g. meet.example.com
MEET_SCHEME = os.environ.get("MEET_SCHEME", "https")
TOKEN_VALIDITY_SECONDS = int(os.environ.get("TOKEN_VALIDITY_SECONDS", "86400"))  # 24h


def _get_display_name() -> str:
    """Prefer Authentik display name, fallback to username."""
    name = request.headers.get("X-Authentik-Name", "").strip()
    if name:
        return name
    return request.headers.get("X-Authentik-Username", "Authenticated User")


def _room_from_path(path: str) -> str:
    """Derive room name from path, e.g. /team-standup -> team-standup."""
    path = (path or "").strip("/")
    return path if path else "*"


def _build_redirect_url(path: str, query: dict, jwt_token: str) -> str:
    """Build full redirect URL with jwt parameter."""
    query = dict(query) if query else {}
    query["jwt"] = jwt_token
    # Host from request (Caddy forwards the original Host)
    host = request.headers.get("X-Forwarded-Host") or request.host
    return urlunparse((
        request.headers.get("X-Forwarded-Proto") or "https",
        host,
        path or "/",
        "",
        urlencode(query),
        "",
    ))


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def issue_jwt(path: str):
    if not JWT_APP_SECRET:
        return "JWT_APP_SECRET not configured", 500
    if not MEET_DOMAIN:
        return "MEET_DOMAIN not configured", 500

    # Caddy forward_auth ensures we only get here when authenticated
    username = request.headers.get("X-Authentik-Username", "user")
    room = _room_from_path("/" + path)
    now = int(time.time())
    payload = {
        "iss": JWT_APP_ID,
        "sub": MEET_DOMAIN,
        "aud": "jitsi",
        "room": room,
        "moderator": True,
        "exp": now + TOKEN_VALIDITY_SECONDS,
        "nbf": now,
        "context": {
            "user": {
                "name": _get_display_name(),
                "id": request.headers.get("X-Authentik-Uid", username),
            }
        },
    }
    token = jwt.encode(
        payload,
        JWT_APP_SECRET,
        algorithm="HS256",
    )
    if hasattr(token, "decode"):
        token = token.decode("utf-8")
    redirect_url = _build_redirect_url(request.path, request.args, token)
    return redirect(redirect_url, code=302)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
