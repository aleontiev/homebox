# Homebox OAuth Proxy

Single-purpose service that brokers OAuth between any self-hosted Homebox
installation and the Homebox-branded OAuth Apps (GitHub, and optionally Google).
Deployed publicly at `oauth.homebox.sh` so every Homebox install can offer
"Connect with GitHub" and passwordless "Continue with Google / GitHub" login
without each user registering their own OAuth App.

Two purposes share one round-trip, selected with the `purpose` query param on
`/start`:

- `connect` — enumerate a user's GitHub orgs for deployment (broad GitHub scopes)
- `login` — prove an email identity for passwordless sign-in (minimal scopes;
  GitHub or Google)

`GET /providers` reports which login providers are configured (`google` is only
advertised when its client credentials are set).

For the standard recipe (Cloud Run + Cloud DNS + Search Console verification)
use `scripts/setup_oauth.sh` at the repo root — it drives the entire flow
through gcloud. The notes below are for self-hosting the proxy elsewhere.

## Why a proxy

GitHub OAuth Apps require a fixed callback URL — but Homebox is self-hosted
at `homebox.<your-domain>`, so a single OAuth App can't redirect back to
every installation directly. The proxy registers `oauth.homebox.sh/callback`
as the only callback, exchanges the code for a token using the secret it
holds, and forwards the token to the originating installation.

## Deploy

1. Register a GitHub OAuth App at <https://github.com/settings/applications/new>:
   - Homepage URL: `https://homebox.sh`
   - Authorization callback URL: `https://oauth.homebox.sh/callback`
   - Note the client_id and generate a client_secret
2. (Optional, for Google login) Register a Google OAuth client at
   <https://console.cloud.google.com/apis/credentials> as a "Web application":
   - Authorized redirect URI: `https://oauth.homebox.sh/callback`
   - Note the client_id and client_secret
3. Run this service behind TLS at `https://oauth.homebox.sh`. Required env:
   - `GITHUB_CLIENT_ID`
   - `GITHUB_CLIENT_SECRET`
   - `PROXY_BASE_URL=https://oauth.homebox.sh`
   - `COOKIE_SECRET` (random 32+ byte string)
   - `INSTALLATION_ALLOWLIST` (optional, comma-separated host suffixes — e.g. `x100.dev,calmlogic.dev`; leave empty to allow any installation)
   - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` (optional — enables Google login)

```
docker build -t homebox-oauth-proxy .
docker run -d -p 8000:8000 \
  -e GITHUB_CLIENT_ID=... \
  -e GITHUB_CLIENT_SECRET=... \
  -e GOOGLE_CLIENT_ID=... \
  -e GOOGLE_CLIENT_SECRET=... \
  -e PROXY_BASE_URL=https://oauth.homebox.sh \
  -e COOKIE_SECRET=$(openssl rand -base64 32) \
  homebox-oauth-proxy
```

## Tokens are not persisted

The proxy never writes tokens to disk. They flow through:
provider → proxy (exchange) → installation redirect → installation stores
encrypted on its own host. If `oauth.homebox.sh` is compromised, in-flight
tokens during the brief window of an OAuth dance are exposed, but no
historical tokens are recoverable.
