#!/bin/bash
set -euo pipefail
cd /opt/supabase/docker
REQ=./upgrade/request.json
RES=./upgrade/result.json
LOG=./upgrade/upgrade.log
[ -f "$REQ" ] || exit 0

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
write_result() {
  cat > "$RES" <<EOF
{"id":"${REQ_ID:-}","status":"$1","service":"$2","from":"$3","to":"$4","message":"$5","at":"$(ts)"}
EOF
}

ACTION=$(jq -r '.action // "upgrade"' "$REQ")
SERVICE=$(jq -r '.service // ""' "$REQ")
TARGET=$(jq -r '.target // ""' "$REQ")
REQ_ID=$(jq -r '.id // ""' "$REQ")

echo "[$(ts)] request id=$REQ_ID action=$ACTION service=$SERVICE target=$TARGET" >> "$LOG"

if ! [[ "$TARGET" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]]; then
  write_result "error" "$SERVICE" "" "$TARGET" "invalid tag format"
  exit 0
fi

case "$SERVICE" in
  studio|kong|auth|rest|realtime|storage|imgproxy|meta|functions|analytics|vector|supavisor|management) ;;
  *) write_result "error" "$SERVICE" "" "$TARGET" "service not upgradable via panel"; exit 0 ;;
esac

case "$SERVICE" in
  studio)     ENVKEY=IMAGE_STUDIO;     COMPOSE_SVC=supabase-studio ;;
  kong)       ENVKEY=IMAGE_KONG;       COMPOSE_SVC=kong ;;
  auth)       ENVKEY=IMAGE_AUTH;       COMPOSE_SVC=auth ;;
  rest)       ENVKEY=IMAGE_REST;       COMPOSE_SVC=rest ;;
  realtime)   ENVKEY=IMAGE_REALTIME;   COMPOSE_SVC=realtime ;;
  storage)    ENVKEY=IMAGE_STORAGE;    COMPOSE_SVC=storage ;;
  imgproxy)   ENVKEY=IMAGE_IMGPROXY;   COMPOSE_SVC=imgproxy ;;
  meta)       ENVKEY=IMAGE_META;       COMPOSE_SVC=meta ;;
  functions)  ENVKEY=IMAGE_FUNCTIONS;  COMPOSE_SVC=functions ;;
  analytics)  ENVKEY=IMAGE_LOGFLARE;   COMPOSE_SVC=analytics ;;
  vector)     ENVKEY=IMAGE_VECTOR;     COMPOSE_SVC=vector ;;
  supavisor)  ENVKEY=IMAGE_SUPAVISOR;  COMPOSE_SVC=supavisor ;;
  management) ENVKEY=IMAGE_MANAGEMENT; COMPOSE_SVC=management ;;
esac

case "$SERVICE" in
  functions)  CNAME=supabase-edge-functions ;;
  realtime)   CNAME=realtime-dev.supabase-realtime ;;
  supavisor)  CNAME=supabase-pooler ;;
  management) CNAME=supabase-management ;;
  *)          CNAME="supabase-$SERVICE" ;;
esac

CURRENT=$(grep "^$ENVKEY=" .env | head -n1 | cut -d= -f2-)
[ -n "$CURRENT" ] || { write_result "error" "$SERVICE" "" "$TARGET" "current image not found in .env"; exit 0; }

case "$CURRENT" in
  *@sha256:*) REPO="${CURRENT%@sha256:*}" ;;
  *:*)        REPO="${CURRENT%:*}" ;;
  *)          REPO="$CURRENT" ;;
esac
if [ "$SERVICE" = "management" ]; then NEW_IMAGE="$REPO@sha256:$TARGET"; else NEW_IMAGE="$REPO:$TARGET"; fi

DUMP_PATH=""
if [ "$SERVICE" != "management" ]; then
  DUMP_DIR=/var/backups/supabase/pre-upgrade
  mkdir -p "$DUMP_DIR"
  find "$DUMP_DIR" -name '*.sql.gz' -mtime +14 -delete 2>/dev/null || true
  DUMP_PATH="$DUMP_DIR/$(date -u +%Y%m%dT%H%M%SZ)-$SERVICE-${TARGET//[^A-Za-z0-9._-]/_}.sql.gz"
  echo "[$(ts)] pg_dumpall → $DUMP_PATH" >> "$LOG"
  ( umask 077 && : > "$DUMP_PATH" )
  if ! docker exec -t supabase-db sh -c 'pg_dumpall -U postgres' 2>>"$LOG" | gzip > "$DUMP_PATH"; then
    rm -f "$DUMP_PATH"
    write_result "error" "$SERVICE" "$CURRENT" "$NEW_IMAGE" "pg_dumpall failed; aborting upgrade"
    exit 0
  fi
  chmod 600 "$DUMP_PATH"
fi

cp .env .env.bak.upgrade
sed -i.tmp "s|^$ENVKEY=.*|$ENVKEY=$NEW_IMAGE|" .env && rm -f .env.tmp

echo "[$(ts)] pulling $NEW_IMAGE" >> "$LOG"
PULL_ERR=./upgrade/last-failure.log
: > "$PULL_ERR"
if ! docker compose pull "$COMPOSE_SVC" > "$PULL_ERR" 2>&1; then
  cat "$PULL_ERR" >> "$LOG"
  mv .env.bak.upgrade .env
  HINT="docker pull failed"
  if grep -qi 'manifest.*not found\|manifest unknown\|not found: manifest' "$PULL_ERR"; then HINT="tag $TARGET not found on Docker Hub"
  elif grep -qi 'toomanyrequests\|rate limit' "$PULL_ERR"; then HINT="Docker Hub rate limit hit; retry in a few minutes"
  elif grep -qi 'no such host\|connection refused\|network' "$PULL_ERR"; then HINT="network error reaching Docker Hub"
  fi
  write_result "error" "$SERVICE" "$CURRENT" "$NEW_IMAGE" "$HINT"
  exit 0
fi

echo "[$(ts)] recreating $SERVICE" >> "$LOG"
docker compose up -d --no-deps "$COMPOSE_SVC" >> "$LOG" 2>&1 || true

DEADLINE=$(( $(date +%s) + 90 ))
HEALTHY=0
while [ $(date +%s) -lt $DEADLINE ]; do
  STATE=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealth{{end}}|{{.State.Status}}' "$CNAME" 2>/dev/null || echo "")
  case "$STATE" in
    healthy|*)          HEALTHY=1; break ;;
    nohealth|running)   # no HEALTHCHECK defined — require 10s of stable "running" before declaring healthy
      sleep 10
      STATE2=$(docker inspect -f '{{.State.Status}}' "$CNAME" 2>/dev/null || echo "")
      [ "$STATE2" = "running" ] && HEALTHY=1
      break ;;
    unhealthy|*|*|exited|*|dead) break ;;
  esac
  sleep 3
done

if [ "$HEALTHY" = "1" ]; then
  rm -f .env.bak.upgrade
  write_result "ok" "$SERVICE" "$CURRENT" "$NEW_IMAGE" "upgrade verified; pg_dump at $DUMP_PATH"
else
  {
    echo "=== docker inspect (final state) ==="
    docker inspect -f 'Status={{.State.Status}} Health={{if .State.Health}}{{.State.Health.Status}}{{else}}nohealth{{end}} ExitCode={{.State.ExitCode}} Error={{.State.Error}}' "$CNAME" 2>&1 || true
    echo
    echo "=== docker logs --tail=100 $CNAME ==="
    docker logs --tail=100 --timestamps "$CNAME" 2>&1 || true
  } > ./upgrade/last-failure.log
  echo "[$(ts)] healthcheck failed; rolling back (failure logs → upgrade/last-failure.log)" >> "$LOG"
  mv .env.bak.upgrade .env
  docker compose up -d --no-deps "$COMPOSE_SVC" >> "$LOG" 2>&1 || true
  write_result "rolled_back" "$SERVICE" "$CURRENT" "$NEW_IMAGE" "new image failed healthcheck; restored $CURRENT (see last-failure log)"
fi
