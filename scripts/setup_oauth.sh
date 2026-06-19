#!/usr/bin/env bash
# End-to-end deploy of the Homebox OAuth proxy to Google Cloud Run.
#
# Assumes you've already run `gcloud auth login`. Drives the entire flow via
# the gcloud CLI: account/project picking, API enablement, Secret Manager,
# Cloud Run deploy from source, and domain mapping for oauth.<BASE_DOMAIN>.
#
# The proxy itself comes from homebox-infra/oauth-proxy/ in this repo. It's
# a stateless FastAPI app — Cloud Run scales it to zero between requests.
#
# Idempotent: re-running updates secrets / redeploys the service / leaves
# existing domain mapping alone.
#
# Requirements: gcloud, jq, curl, openssl.
#
# Usage:
#   scripts/setup_oauth.sh
#   scripts/setup_oauth.sh --base-domain homebox.sh --region us-central1
#
# Prereqs you handle outside this script:
#   - GitHub OAuth App registered with callback https://oauth.<BASE_DOMAIN>/callback
#     (you'll be prompted for its client_id / client_secret)
#   - Billing enabled on the chosen GCP project (script tells you if not)
#   - Domain verified in Google Search Console under the same Google account
#     (script pauses and points you at the verification URL when needed)

set -euo pipefail

# ---------- defaults / paths ----------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROXY_DIR="$REPO_ROOT/homebox-infra/oauth-proxy"

DEFAULT_BASE_DOMAIN="homebox.sh"
DEFAULT_REGION="us-central1"
DEFAULT_SERVICE="homebox-oauth-proxy"

REQUIRED_APIS=(
  run.googleapis.com
  cloudbuild.googleapis.com
  artifactregistry.googleapis.com
  secretmanager.googleapis.com
  siteverification.googleapis.com
)

SECRET_CLIENT_ID="homebox-oauth-github-client-id"
SECRET_CLIENT_SECRET="homebox-oauth-github-client-secret"
SECRET_COOKIE="homebox-oauth-cookie-secret"

# ---------- args ----------

BASE_DOMAIN="$DEFAULT_BASE_DOMAIN"
REGION=""
SERVICE_NAME="$DEFAULT_SERVICE"
INSTALL_ALLOWLIST=""
GITHUB_CLIENT_ID=""
GITHUB_CLIENT_SECRET=""
SKIP_HEALTH_WAIT=0

usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-domain)            BASE_DOMAIN="$2"; shift 2 ;;
    --region)                 REGION="$2"; shift 2 ;;
    --service-name)           SERVICE_NAME="$2"; shift 2 ;;
    --installation-allowlist) INSTALL_ALLOWLIST="$2"; shift 2 ;;
    --github-client-id)       GITHUB_CLIENT_ID="$2"; shift 2 ;;
    --github-client-secret)   GITHUB_CLIENT_SECRET="$2"; shift 2 ;;
    --skip-health-wait)       SKIP_HEALTH_WAIT=1; shift ;;
    -h|--help)                usage ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

HOST="oauth.$BASE_DOMAIN"
# Empty allowlist = allow any installation host. The proxy's installation= URL
# is signed into the OAuth state cookie either way, so an attacker can't cause
# a redirect to a host you didn't already trigger the flow from. See
# homebox-infra/oauth-proxy/main.py:_is_allowed_installation.
INSTALL_ALLOWLIST="${INSTALL_ALLOWLIST-}"

# ---------- terminal helpers ----------

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
  YELLOW=$'\033[33m'; BLUE=$'\033[34m'; RESET=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

step() { printf '\n%s==> %s%s\n' "${BOLD}${BLUE}" "$1" "${RESET}"; }
info() { printf '    %s\n' "$1"; }
ok()   { printf '    %s✓%s %s\n' "${GREEN}" "${RESET}" "$1"; }
warn() { printf '    %s!%s %s\n' "${YELLOW}" "${RESET}" "$1"; }
fail() { printf '\n%s✗ %s%s\n' "${RED}${BOLD}" "$1" "${RESET}" >&2; exit "${2:-1}"; }

ask() {
  # ask "prompt text" "default-or-empty" -> echoes value
  local prompt="$1" default="${2:-}" suffix="" reply
  [[ -n "$default" ]] && suffix=" [$default]"
  while :; do
    read -rp "    ${BOLD}?${RESET} ${prompt}${suffix}: " reply
    if [[ -n "$reply" ]]; then echo "$reply"; return; fi
    if [[ -n "$default" ]]; then echo "$default"; return; fi
  done
}

ask_yes() {
  # ask_yes "prompt" "Y" -> returns 0 for yes, 1 for no
  local prompt="$1" default="${2:-Y}" reply suffix
  if [[ "$default" =~ [Yy] ]]; then suffix=" [Y/n]"; else suffix=" [y/N]"; fi
  read -rp "    ${BOLD}?${RESET} ${prompt}${suffix}: " reply
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy] ]]
}

# pick_one prompt allow_new_label name_of_array_var name_of_result_var
# Sets RESULT_VAR to "@new@" if user picks the create-new entry, else array element.
pick_one() {
  local prompt="$1" allow_new="$2" arr_name="$3" result_name="$4"
  local -n arr="$arr_name"
  local -n result="$result_name"
  printf '    %s?%s %s\n' "${BOLD}" "${RESET}" "$prompt"
  local i=1
  for o in "${arr[@]}"; do
    printf '        %d. %s\n' "$i" "$o"
    i=$((i+1))
  done
  if [[ -n "$allow_new" ]]; then
    printf '        %d. %s%s%s\n' "$i" "${DIM}" "$allow_new" "${RESET}"
  fi
  while :; do
    read -rp "    Pick a number: " n
    [[ "$n" =~ ^[0-9]+$ ]] || continue
    if (( n >= 1 && n <= ${#arr[@]} )); then
      result="${arr[$((n-1))]}"
      return
    fi
    if [[ -n "$allow_new" ]] && (( n == ${#arr[@]} + 1 )); then
      result="@new@"
      return
    fi
  done
}

require() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing dependency: $1"
}

# ---------- steps ----------

ensure_tools() {
  require gcloud
  require jq
  require curl
  require openssl
  require dig
  [[ -f "$PROXY_DIR/Dockerfile" ]] || fail "Expected Dockerfile at $PROXY_DIR"
}

pick_account() {
  step "Pick a Google account"
  local accounts_json emails active default picked
  accounts_json="$(gcloud auth list --format=json)"
  mapfile -t emails < <(jq -r '.[].account' <<<"$accounts_json")
  [[ ${#emails[@]} -gt 0 ]] || fail "No gcloud accounts found. Run: gcloud auth login"

  if (( ${#emails[@]} == 1 )); then
    ok "Using ${emails[0]} (only account)"
    return
  fi

  active="$(jq -r '.[] | select(.status=="ACTIVE") | .account' <<<"$accounts_json" | head -n1)"
  default="${active:-${emails[0]}}"
  info "Currently active: $default"
  if ask_yes "Use $default?" Y; then
    if [[ "$active" != "$default" ]]; then
      gcloud config set account "$default" >/dev/null
    fi
    return
  fi
  pick_one "Which account?" "" emails picked
  gcloud config set account "$picked" >/dev/null
  ok "Switched to $picked"
}

create_project() {
  local pid name
  pid="$(ask "New project ID (lowercase, 6-30 chars, e.g. homebox-prod-7a3f)")"
  name="$(ask "Display name" "Homebox")"
  info "Creating project $pid ..."
  gcloud projects create "$pid" --name "$name"
  gcloud config set project "$pid" >/dev/null
  ok "Created $pid"

  local accounts_json
  accounts_json="$(gcloud beta billing accounts list --filter=open=true --format=json)"
  local count; count="$(jq 'length' <<<"$accounts_json")"
  if (( count == 0 )); then
    warn "No open billing accounts visible to this gcloud user."
    info "Open https://console.cloud.google.com/billing/linkedaccount?project=$pid"
    read -rp "    ${BOLD}?${RESET} Press Enter once billing is linked... "
    PROJECT_ID="$pid"; return
  fi

  local billing
  if (( count == 1 )); then
    billing="$(jq -r '.[0].name | split("/")[-1]' <<<"$accounts_json")"
    info "Linking billing account $billing ..."
  else
    local labels=() picked_label
    mapfile -t labels < <(jq -r '.[] | "\(.displayName)  (\(.name | split("/")[-1]))"' <<<"$accounts_json")
    pick_one "Which billing account?" "" labels picked_label
    billing="$(printf '%s' "$picked_label" | sed -E 's/.*\(([^)]+)\)$/\1/')"
  fi
  gcloud beta billing projects link "$pid" --billing-account "$billing" >/dev/null
  ok "Billing linked"
  PROJECT_ID="$pid"
}

pick_project() {
  step "Pick a GCP project"
  local projects_json labels=() picked
  projects_json="$(gcloud projects list --format=json)"
  if [[ "$(jq 'length' <<<"$projects_json")" == "0" ]]; then
    info "No existing projects."
    create_project
    return
  fi
  mapfile -t labels < <(jq -r '.[] | "\(.projectId)  (\(.name // ""))"' <<<"$projects_json")
  pick_one "Which project?" "Create a new project" labels picked
  if [[ "$picked" == "@new@" ]]; then
    create_project
    return
  fi
  PROJECT_ID="${picked%% *}"
  gcloud config set project "$PROJECT_ID" >/dev/null
  ok "Using project $PROJECT_ID"
}

enable_apis() {
  step "Enable required APIs"
  local enabled todo=()
  enabled="$(gcloud services list --enabled --project "$PROJECT_ID" --format='value(config.name)')"
  for api in "${REQUIRED_APIS[@]}"; do
    grep -qx "$api" <<<"$enabled" || todo+=("$api")
  done
  if (( ${#todo[@]} == 0 )); then
    ok "All required APIs already enabled"
    return
  fi
  info "Enabling: ${todo[*]}"
  gcloud services enable "${todo[@]}" --project "$PROJECT_ID"
  ok "APIs enabled"
}

pick_region() {
  step "Pick a Cloud Run region"
  if [[ -n "$REGION" ]]; then
    ok "Using region $REGION (from --region)"
    return
  fi
  info "Domain mappings are supported in: us-central1, us-east1, us-east4, us-west1,"
  info "europe-west1/2/4, europe-north1, asia-east1, asia-northeast1, asia-southeast1,"
  info "australia-southeast1, southamerica-east1."
  REGION="$(ask "Region" "$DEFAULT_REGION")"
}

secret_exists() {
  # secret_exists <name>; returns 0 if the secret has at least one enabled version.
  local name="$1"
  gcloud secrets describe "$name" --project "$PROJECT_ID" >/dev/null 2>&1
}

# Module-level flag set by get_github_credentials; consumed by store_secrets to
# decide whether to add new versions or leave existing ones alone.
REUSE_GITHUB_SECRETS=0

get_github_credentials() {
  step "GitHub OAuth App credentials"
  local callback="https://$HOST/callback"

  # If both flags were passed on the command line, that's an explicit override —
  # use them and overwrite whatever's stored.
  if [[ -n "$GITHUB_CLIENT_ID" && -n "$GITHUB_CLIENT_SECRET" ]]; then
    info "Using credentials from --github-client-id / --github-client-secret flags."
    return
  fi

  # Otherwise, if both secrets already exist in Secret Manager, offer to reuse.
  if secret_exists "$SECRET_CLIENT_ID" && secret_exists "$SECRET_CLIENT_SECRET"; then
    info "Found existing GitHub OAuth credentials in Secret Manager:"
    info "  $SECRET_CLIENT_ID"
    info "  $SECRET_CLIENT_SECRET"
    if ask_yes "Reuse them?" Y; then
      REUSE_GITHUB_SECRETS=1
      ok "Reusing stored credentials (skipping prompts)."
      return
    fi
    info "OK — paste new credentials below; existing secrets will get a new version."
  fi

  info "Register an OAuth App at https://github.com/settings/applications/new"
  info "  Homepage URL: https://$BASE_DOMAIN"
  info "  Authorization callback URL: $callback"
  info "Then paste the credentials below (or pass --github-client-id / --github-client-secret)."
  [[ -n "$GITHUB_CLIENT_ID" ]]     || GITHUB_CLIENT_ID="$(ask "GitHub Client ID")"
  [[ -n "$GITHUB_CLIENT_SECRET" ]] || GITHUB_CLIENT_SECRET="$(ask "GitHub Client Secret")"
}

upsert_secret() {
  # upsert_secret <name> <value>
  local name="$1" value="$2"
  if gcloud secrets describe "$name" --project "$PROJECT_ID" >/dev/null 2>&1; then
    info "Updating secret $name (adding new version) ..."
  else
    info "Creating secret $name ..."
    gcloud secrets create "$name" --replication-policy=automatic --project "$PROJECT_ID" >/dev/null
  fi
  printf '%s' "$value" \
    | gcloud secrets versions add "$name" --project "$PROJECT_ID" --data-file=- >/dev/null
}

store_secrets() {
  step "Store secrets in Secret Manager"

  if (( REUSE_GITHUB_SECRETS )); then
    info "Skipping GitHub client_id / client_secret (reusing stored versions)."
  else
    upsert_secret "$SECRET_CLIENT_ID" "$GITHUB_CLIENT_ID"
    upsert_secret "$SECRET_CLIENT_SECRET" "$GITHUB_CLIENT_SECRET"
  fi

  # Cookie secret: keep stable across runs so any in-flight OAuth states
  # signed by the running proxy stay valid. Only create one if missing.
  if secret_exists "$SECRET_COOKIE"; then
    info "Reusing existing cookie secret ($SECRET_COOKIE)."
  else
    info "Generating a new cookie secret ..."
    upsert_secret "$SECRET_COOKIE" "$(openssl rand -base64 48 | tr -d '\n')"
  fi

  ok "Secrets ready."
}

grant_secret_access() {
  step "Grant Cloud Run runtime access to secrets"
  local pnum sa
  pnum="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
  sa="${pnum}-compute@developer.gserviceaccount.com"
  info "Service account: $sa"
  for s in "$SECRET_CLIENT_ID" "$SECRET_CLIENT_SECRET" "$SECRET_COOKIE"; do
    gcloud secrets add-iam-policy-binding "$s" \
      --member "serviceAccount:$sa" \
      --role roles/secretmanager.secretAccessor \
      --project "$PROJECT_ID" \
      --condition=None >/dev/null
  done
  ok "Granted secretAccessor on all three secrets"
}

deploy_service() {
  step "Deploy $SERVICE_NAME to Cloud Run from homebox-infra/oauth-proxy"
  local proxy_base="https://$HOST"
  local env_vars="PROXY_BASE_URL=$proxy_base,INSTALLATION_ALLOWLIST=$INSTALL_ALLOWLIST"
  local secrets_arg="GITHUB_CLIENT_ID=${SECRET_CLIENT_ID}:latest,GITHUB_CLIENT_SECRET=${SECRET_CLIENT_SECRET}:latest,COOKIE_SECRET=${SECRET_COOKIE}:latest"

  # Streams Cloud Build + rollout output so the user sees progress.
  gcloud run deploy "$SERVICE_NAME" \
    --source "$PROXY_DIR" \
    --project "$PROJECT_ID" \
    --region "$REGION" \
    --platform managed \
    --allow-unauthenticated \
    --port 8000 \
    --set-env-vars "$env_vars" \
    --set-secrets "$secrets_arg" \
    --quiet

  SERVICE_URL="$(gcloud run services describe "$SERVICE_NAME" \
    --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"
  ok "Service URL: $SERVICE_URL"
}

# Verify ownership of $BASE_DOMAIN with Google via the Site Verification API.
# `gcloud auth login` doesn't accept --scopes (only the ADC variant does), so
# we drive Site Verification with Application Default Credentials, which can
# be re-authed with custom scopes without disturbing the user's main login.
verify_domain_via_api() {
  local root="$BASE_DOMAIN"
  step "Verify ownership of $root with Google"

  # Already verified for the active account?
  if gcloud domains list-user-verified --format='value(id)' 2>/dev/null | grep -qx "$root"; then
    ok "$root is already verified for this account."
    return 0
  fi

  local access_token
  access_token="$(gcloud auth application-default print-access-token 2>/dev/null || true)"

  local scopes=""
  if [[ -n "$access_token" ]]; then
    scopes="$(curl -sS "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${access_token}" \
                | jq -r '.scope // empty')"
  fi

  if [[ -z "$access_token" ]] || ! grep -q "siteverification" <<<"$scopes"; then
    warn "Application Default Credentials don't include the Site Verification scope yet."
    info "Run this in another terminal (it opens a browser; ADC is separate from"
    info "the gcloud user login, so it won't replace your active gcloud account):"
    info ""
    info "    gcloud auth application-default login \\"
    info "      --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/siteverification"
    info ""
    if ! ask_yes "Press Enter once you've re-authenticated, or 'n' to verify manually via Search Console" Y; then
      return 1
    fi
    access_token="$(gcloud auth application-default print-access-token 2>/dev/null || true)"
    if [[ -z "$access_token" ]]; then
      warn "Still no ADC token — falling back to manual flow."
      return 1
    fi
    scopes="$(curl -sS "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${access_token}" \
                | jq -r '.scope // empty')"
    if ! grep -q "siteverification" <<<"$scopes"; then
      warn "Still no siteverification scope — falling back to manual flow."
      return 1
    fi
  fi

  # Pin ADC's quota project to the Cloud Run project so user-cred ADC calls
  # have something to bill/quota against (otherwise the API rejects them
  # with PERMISSION_DENIED + accessNotConfigured). Idempotent — fine to run
  # every time. We also pass x-goog-user-project on each request as a belt-
  # and-suspenders fallback in case ADC isn't configured.
  gcloud auth application-default set-quota-project "$PROJECT_ID" >/dev/null 2>&1 || true

  # Step 1: Ask Google for the TXT token to prove we own the domain.
  local req resp txt_value
  req="$(jq -n --arg id "$root" '{verificationMethod: "DNS_TXT", site: {type: "INET_DOMAIN", identifier: $id}}')"
  resp="$(curl -sS -X POST "https://www.googleapis.com/siteVerification/v1/token" \
           -H "Authorization: Bearer ${access_token}" \
           -H "x-goog-user-project: ${PROJECT_ID}" \
           -H "Content-Type: application/json" \
           -d "$req")"
  txt_value="$(jq -r '.token // empty' <<<"$resp")"
  if [[ -z "$txt_value" ]]; then
    warn "Site Verification API didn't return a token. Response:"
    printf '%s\n' "$resp"
    return 1
  fi

  info "Add this TXT record on the DNS for $root, then we'll wait for it to propagate:"
  printf '\n'
  printf '        %sType%s   TXT\n' "$BOLD" "$RESET"
  printf '        %sName%s   @       (or %s)\n' "$BOLD" "$RESET" "$root"
  printf '        %sValue%s  %s\n' "$BOLD" "$RESET" "$txt_value"
  printf '        %sTTL%s    60s (or "Auto")\n' "$BOLD" "$RESET"
  printf '\n'
  info "In Cloudflare DNS this is: Add record → TXT → @ → paste value → Save."
  read -rp "    ${BOLD}?${RESET} Press Enter once you've added it... "

  # Step 2: Poll until the TXT record is visible. Use 1.1.1.1 to skip
  # whatever local resolver caching might delay propagation.
  info "Polling DNS for the TXT record (up to 5 minutes) ..."
  local deadline=$(( $(date +%s) + 300 ))
  while (( $(date +%s) < deadline )); do
    if dig +short TXT "$root" @1.1.1.1 2>/dev/null | grep -qF "$txt_value"; then
      ok "TXT record visible in DNS."
      break
    fi
    info "  $(date +%H:%M:%S)  not visible yet, retrying in 15s ..."
    sleep 15
  done
  if ! dig +short TXT "$root" @1.1.1.1 2>/dev/null | grep -qF "$txt_value"; then
    warn "TXT record never appeared in DNS. Double-check the value and retry."
    return 1
  fi

  # Step 3: Tell Google to (re)check and grant verification.
  req="$(jq -n --arg id "$root" '{site: {type: "INET_DOMAIN", identifier: $id}}')"
  resp="$(curl -sS -X POST "https://www.googleapis.com/siteVerification/v1/webResource?verificationMethod=DNS_TXT" \
           -H "Authorization: Bearer ${access_token}" \
           -H "x-goog-user-project: ${PROJECT_ID}" \
           -H "Content-Type: application/json" \
           -d "$req")"
  if jq -e '.id // empty' <<<"$resp" >/dev/null; then
    ok "$root verified."
    return 0
  fi
  warn "Verification API rejected the request:"
  printf '%s\n' "$resp"
  return 1
}

map_domain() {
  step "Map $HOST → $SERVICE_NAME"
  local existing
  existing="$(gcloud beta run domain-mappings list --project "$PROJECT_ID" --region "$REGION" --format=json)"
  if jq -e --arg h "$HOST" 'any(.metadata.name == $h)' <<<"$existing" >/dev/null; then
    ok "Domain mapping for $HOST already exists"
    return 0
  fi

  info "Creating domain mapping (this may fail until the domain is verified) ..."
  local err
  if err="$(gcloud beta run domain-mappings create \
                --service "$SERVICE_NAME" --domain "$HOST" \
                --project "$PROJECT_ID" --region "$REGION" 2>&1)"; then
    return 0
  fi
  printf '%s\n' "$err"

  if ! grep -qiE 'verif(y|ied)|domain ownership|not appear to be' <<<"$err"; then
    fail "Domain mapping failed for an unrecognized reason; see error above."
  fi

  # Try to do the verification automatically. On any failure (missing scope,
  # API error, DNS never propagating) fall back to pointing the user at
  # Search Console and waiting.
  if ! verify_domain_via_api; then
    local root="${BASE_DOMAIN}"
    warn "Falling back to manual verification."
    info "  1. Open https://search.google.com/search-console/welcome"
    info "  2. Add property '$root' (Domain type) and complete the TXT verification."
    info "  3. Verify with the same Google account this script is using."
    read -rp "    ${BOLD}?${RESET} Press Enter once verification is complete to retry... "
  fi

  gcloud beta run domain-mappings create \
    --service "$SERVICE_NAME" --domain "$HOST" \
    --project "$PROJECT_ID" --region "$REGION"
}

print_dns_instructions() {
  step "DNS records to add"
  local desc
  desc="$(gcloud beta run domain-mappings describe \
            --domain "$HOST" --project "$PROJECT_ID" --region "$REGION" --format=json)"
  local count; count="$(jq '.status.resourceRecords // [] | length' <<<"$desc")"
  if (( count == 0 )); then
    warn "Cloud Run reported no records (mapping may already be active)."
    return
  fi
  info "Add the following to the DNS for $BASE_DOMAIN:"
  printf '\n'
  jq -r '.status.resourceRecords[] | "        \(.type|tostring|.+ "     " | .[0:5])  \((.name//"") + "                              " | .[0:30])  →  \(.rrdata)"' <<<"$desc"
  printf '\n'
  info "Cloudflare-proxied (orange cloud) is fine; the cert is issued by Google at the Cloud Run edge."
}

wait_for_health() {
  if (( SKIP_HEALTH_WAIT )); then return; fi
  step "Wait for https://$HOST/health to return 200"
  info "This polls every 10s. DNS + cert provisioning typically takes 5-15 minutes."
  if ! ask_yes "Wait now?" Y; then
    info "Skipping. Verify later with: curl -fsS https://$HOST/health"
    return
  fi
  local url="https://$HOST/health"
  local deadline=$(( $(date +%s) + 600 ))
  while (( $(date +%s) < deadline )); do
    local code
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "$url" || true)"
    if [[ "$code" == "200" ]]; then
      ok "$url returned 200"
      return
    fi
    info "  $(date +%H:%M:%S)  HTTP ${code:-no response} — still waiting ..."
    sleep 10
  done
  warn "Timed out after 10 minutes. The mapping is created but DNS/TLS may need more time."
}

print_admin_wiring() {
  step "Done — admin will pick this up on next deploy"
  local proxy_url="https://$HOST"
  if [[ "$HOST" == "oauth.homebox.sh" ]]; then
    info "$proxy_url is the project default (admin/app/config.py:homebox_oauth_proxy_url)"
    info "and the docker-compose fallback for HOMEBOX_OAUTH_PROXY_URL — so any"
    info "Homebox install just runs:"
    info ""
    info "    cd <repo> && make admin"
    info ""
    info "and the 'OAuth proxy unreachable' banner clears with no .env changes."
  else
    info "You're running the proxy at $proxy_url, which isn't the project default."
    info "On the host running the Homebox admin:"
    cat <<EOF

        sudo sed -i 's|^HOMEBOX_OAUTH_PROXY_URL=.*|HOMEBOX_OAUTH_PROXY_URL=$proxy_url|' /opt/homebox/admin/.env
        grep -q '^HOMEBOX_OAUTH_PROXY_URL=' /opt/homebox/admin/.env \\
          || echo 'HOMEBOX_OAUTH_PROXY_URL=$proxy_url' | sudo tee -a /opt/homebox/admin/.env
        cd <repo> && make admin

EOF
  fi
}

# ---------- main ----------

trap 'echo; fail "Interrupted." 130' INT

printf '%sHomebox OAuth proxy → Cloud Run%s\n' "${BOLD}" "${RESET}"
printf '  Base domain:  %s\n' "$BASE_DOMAIN"
printf '  Proxy host:   %s\n' "$HOST"
printf '  Allowlist:    %s\n' "${INSTALL_ALLOWLIST:-(none — allow any homebox install)}"

ensure_tools
pick_account
pick_project
enable_apis
pick_region
get_github_credentials
store_secrets
grant_secret_access
deploy_service
map_domain
print_dns_instructions
wait_for_health
print_admin_wiring

printf '\n%s%sDone.%s Proxy: https://%s\n' "${GREEN}" "${BOLD}" "${RESET}" "$HOST"
