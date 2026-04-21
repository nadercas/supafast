#!/bin/bash
set -euo pipefail
cd /opt/supabase/docker
REQ=./upgrade/pin-request.json
RES=./upgrade/pin-result.json
LOG=./upgrade/pin.log
ENVFILE=./.env
COMPOSE=./docker-compose.yml
[ -f "$REQ" ] || exit 0
mkdir -p ./upgrade
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
REQ_ID=$(jq -r '.id // ""' "$REQ" 2>/dev/null || echo "")
echo "[$(ts)] pin-digests request id=$REQ_ID" >> "$LOG"

SERVICES=(
  "supabase-studio|IMAGE_STUDIO|"
  "supabase-kong|IMAGE_KONG|"
  "supabase-auth|IMAGE_AUTH|"
  "supabase-rest|IMAGE_REST|"
  "realtime-dev.supabase-realtime|IMAGE_REALTIME|"
  "supabase-storage|IMAGE_STORAGE|"
  "supabase-imgproxy|IMAGE_IMGPROXY|"
  "supabase-meta|IMAGE_META|"
  "supabase-edge-functions|IMAGE_FUNCTIONS|"
  "supabase-analytics|IMAGE_LOGFLARE|"
  "supabase-vector|IMAGE_VECTOR|"
  "supabase-pooler|IMAGE_SUPAVISOR|"
  "supabase-db||supabase/postgres"
  "caddy-container||caddy"
  "authelia||authelia/authelia"
  "redis||redis"
  "supabase-management||ghcr.io/nadercas/supafast"
  "docker-socket-proxy||lscr.io/linuxserver/socket-proxy"
)

cp .env .env.bak.pin
cp docker-compose.yml docker-compose.yml.bak.pin
CHANGED=0
FAILED=()

for ROW in "${SERVICES[@]}"; do
  IFS='|' read -r CNAME_ ENVKEY REPO_MATCH <<< "$ROW"

  # Get current image and compute expected RepoDigest
  IMG_ID=$(docker inspect -f '{{.Image}}' "$CNAME_" 2>/dev/null || echo "")
  if [ -z "$IMG_ID" ]; then FAILED+=("$CNAME_(no-container)"); continue; fi

  if [ -n "$ENVKEY" ]; then
    # Env-var-driven service: update .env
    CUR=$(grep "^$ENVKEY=" "$ENVFILE" | head -n1 | cut -d= -f2-)
    [ -n "$CUR" ] || { FAILED+=("$CNAME_(no-env)"); continue; }
    case "$CUR" in *"@sha256:"*) continue ;; esac
    REPO="${CUR%:*}"
    DIGEST=$(docker inspect -f '{{range .RepoDigests}}{{.}}{{"\n"}}{{end}}' "$IMG_ID" 2>/dev/null | grep "^$REPO@sha256:" | head -n1 || echo "")
    if [ -z "$DIGEST" ]; then FAILED+=("$CNAME_(no-digest)"); continue; fi
    sed -i.tmp "s|^$ENVKEY=.*|$ENVKEY=$DIGEST|" "$ENVFILE" && rm -f "$ENVFILE.tmp"
    echo "[$(ts)] pinned $ENVKEY → $DIGEST" >> "$LOG"
    CHANGED=$((CHANGED + 1))
  else
    # Hardcoded image in compose.yml: find the current "image: $REPO_MATCH..."
    # line and replace the value with the digest form.
    CURRENT_LINE=$(grep -E "^[[:space:]]*image:[[:space:]]*$REPO_MATCH" "$COMPOSE" | head -n1 || echo "")
    [ -n "$CURRENT_LINE" ] || { FAILED+=("$CNAME_(no-compose-match)"); continue; }
    # Already pinned?
    case "$CURRENT_LINE" in *"@sha256:"*) continue ;; esac
    # Build expected digest
    DIGEST=$(docker inspect -f '{{range .RepoDigests}}{{.}}{{"\n"}}{{end}}' "$IMG_ID" 2>/dev/null | grep -E "^${REPO_MATCH//./\.}(/[^@]*)?@sha256:" | head -n1 || echo "")
    if [ -z "$DIGEST" ]; then FAILED+=("$CNAME_(no-digest)"); continue; fi
    INDENT=$(echo "$CURRENT_LINE" | sed 's/[^ ].*//')
    NEW_LINE="${INDENT}image: $DIGEST"
    # Escape for sed: since the digest has no /, use | as delimiter and escape & and \ only
    ESC_OLD=$(printf '%s\n' "$CURRENT_LINE" | sed 's/[][\\.*^$()+?{}|/]/\\&/g')
    ESC_NEW=$(printf '%s\n' "$NEW_LINE" | sed 's/[\\&|]/\\&/g')
    sed -i.tmp "s|$ESC_OLD|$ESC_NEW|" "$COMPOSE" && rm -f "$COMPOSE.tmp"
    echo "[$(ts)] pinned compose $CNAME_ → $DIGEST" >> "$LOG"
    CHANGED=$((CHANGED + 1))
  fi
done

echo "[$(ts)] $CHANGED pins written; no restart" >> "$LOG"

STATUS="ok"
MSG="pinned $CHANGED services"
if [ "${#FAILED[@]}" -gt 0 ]; then
  MSG="$MSG; failed: ${FAILED[*]}"
  [ "$CHANGED" = "0" ] && STATUS="error"
fi
cat > "$RES" <<EOF
{"id":"$REQ_ID","status":"$STATUS","changed":$CHANGED,"failed":${#FAILED[@]},"message":"$MSG","at":"$(ts)"}
EOF
