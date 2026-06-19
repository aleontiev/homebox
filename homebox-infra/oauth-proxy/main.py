"""Homebox OAuth proxy — deployed at homebox.sh.

Holds the single Homebox-branded OAuth apps (GitHub, and optionally Google).
Each self-hosted Homebox installation redirects browsers here for the OAuth
dance, and we ship the resulting access_token back to the installation.

Two purposes share one round-trip:
  - connect : enumerate a user's GitHub orgs for deployment (broad GitHub scopes)
  - login   : prove an email identity for passwordless sign-in (minimal scopes,
              GitHub or Google)

Endpoints:
  GET /health                          – liveness (not /healthz; intercepted by Google's L7)
  GET /providers                       – which login providers are configured
  GET /start?installation=&state=&...  – redirects to the provider's login
  GET /callback?code=&state=           – exchanges code, redirects to <installation>/oauth/callback

The state cookie binds installation+csrf to prevent open-redirects. We never
persist tokens; they pass through to the installation only via the redirect.

Deploy:
  - Set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, PROXY_BASE_URL, INSTALLATION_ALLOWLIST
  - Optionally set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET to enable Google login
  - Register each OAuth app's callback URL = <PROXY_BASE_URL>/callback
  - Run with `uvicorn main:app` behind a TLS terminator at homebox.sh.
"""

import os
import secrets
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer


GITHUB_CLIENT_ID = os.environ["GITHUB_CLIENT_ID"]
GITHUB_CLIENT_SECRET = os.environ["GITHUB_CLIENT_SECRET"]
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
PROXY_BASE_URL = os.environ["PROXY_BASE_URL"].rstrip("/")
COOKIE_SECRET = os.environ.get("COOKIE_SECRET") or secrets.token_urlsafe(32)
ALLOWLIST = [s.strip() for s in os.environ.get("INSTALLATION_ALLOWLIST", "").split(",") if s.strip()]

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"

# Scopes requested per (provider, purpose). `connect` enumerates a GitHub user's
# orgs for deployment; `login` only needs a verified email/identity.
_SCOPES = {
    ("github", "connect"): "read:user read:org repo admin:org",
    ("github", "login"): "read:user user:email",
    ("google", "login"): "openid email profile",
}

app = FastAPI(title="Homebox OAuth Proxy")
serializer = URLSafeTimedSerializer(COOKIE_SECRET, salt="homebox-oauth-proxy")


def _is_allowed_installation(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    if not ALLOWLIST:
        return True  # If no allowlist set, allow all (use carefully)
    return any(parsed.netloc == a or parsed.netloc.endswith("." + a) for a in ALLOWLIST)


def _google_enabled() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


@app.get("/health")
async def health():
    # Not /healthz — Google's L7 frontend on Cloudflare Run intercepts that
    # path for its own health-check infrastructure and returns 404 before the
    # request ever reaches the container.
    return {"ok": True}


@app.get("/providers")
async def providers():
    """Which login providers this proxy can serve. Installations render their
    login buttons from this (Google only appears when its client is configured)."""
    return {"github": True, "google": _google_enabled()}


@app.get("/start")
async def start(installation: str, state: str, provider: str = "github", purpose: str = "connect"):
    if not _is_allowed_installation(installation):
        raise HTTPException(400, "Installation URL is not allowed.")
    provider = provider.lower()
    purpose = purpose.lower()
    scope = _SCOPES.get((provider, purpose))
    if scope is None:
        raise HTTPException(400, f"Unsupported provider/purpose: {provider}/{purpose}")
    if provider == "google" and not _google_enabled():
        raise HTTPException(400, "Google login is not configured on this proxy.")

    payload = serializer.dumps({
        "installation": installation,
        "downstream_state": state,
        "provider": provider,
    })
    redirect_uri = f"{PROXY_BASE_URL}/callback"
    if provider == "google":
        qs = urlencode({
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": payload,
            "access_type": "online",
            "prompt": "select_account",
        })
        return RedirectResponse(f"{GOOGLE_AUTHORIZE}?{qs}", status_code=302)

    qs = urlencode({
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": payload,
        "allow_signup": "false",
    })
    return RedirectResponse(f"{GITHUB_AUTHORIZE}?{qs}", status_code=302)


@app.get("/callback")
async def callback(request: Request):
    code = request.query_params.get("code") or ""
    state = request.query_params.get("state") or ""
    if not code or not state:
        raise HTTPException(400, "Missing code or state")
    try:
        payload = serializer.loads(state, max_age=600)
    except BadSignature:
        raise HTTPException(400, "Invalid state")

    installation = payload.get("installation")
    downstream_state = payload.get("downstream_state")
    provider = (payload.get("provider") or "github").lower()
    if not installation or not _is_allowed_installation(installation):
        raise HTTPException(400, "Installation URL is not allowed.")

    redirect_uri = f"{PROXY_BASE_URL}/callback"
    if provider == "google":
        token_url = GOOGLE_TOKEN
        data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        provider_label = "Google"
    else:
        token_url = GITHUB_TOKEN
        data = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        provider_label = "GitHub"

    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(token_url, data=data, headers={"Accept": "application/json"})
        if r.status_code != 200:
            raise HTTPException(502, f"{provider_label} token exchange failed: {r.status_code}")
        token_data = r.json()

    access_token = token_data.get("access_token")
    if not access_token:
        err = token_data.get("error_description") or token_data.get("error") or "no_token"
        raise HTTPException(502, f"{provider_label} did not return an access_token: {err}")

    qs = urlencode({"code": access_token, "state": downstream_state})
    return RedirectResponse(f"{installation.rstrip('/')}/oauth/callback?{qs}", status_code=302)
