#!/bin/bash
# @summary: Bump all IMAGE_* tags in .env to match the current cloud-init stable set
# @touches: .env
# @restarts: studio, kong, auth, rest, realtime, storage, imgproxy, meta, functions, analytics, vector, supavisor
#
# Migration 003 — brings servers provisioned with older cloud-init image pins
# up to the current stable versions shipped with fresh deploys. Idempotent:
# only rewrites IMAGE_* keys whose value differs from the target. Services
# whose IMAGE_* is already digest-pinned (contains @sha256:) are left alone —
# you pinned those deliberately, don't second-guess it.
#
# Target set mirrors cloudInitGenerator.js .env defaults at the time this
# migration was authored. Bump this file when generator defaults change.

set -uo pipefail
cd /opt/supabase/docker

ENVFILE=./.env
[ -f "$ENVFILE" ] || { echo "[mig-003] ERROR: $ENVFILE not found"; exit 1; }

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "[$(ts)] [mig-003] $*"; }

declare -A TARGETS=(
  [IMAGE_STUDIO]="supabase/studio:2026.04.08-sha-205cbe7"
  [IMAGE_KONG]="kong/kong:3.9.1"
  [IMAGE_AUTH]="supabase/gotrue:v2.186.0"
  [IMAGE_REST]="postgrest/postgrest:v14.8"
  [IMAGE_REALTIME]="supabase/realtime:v2.86.3"
  [IMAGE_STORAGE]="supabase/storage-api:v1.48.26"
  [IMAGE_IMGPROXY]="darthsim/imgproxy:v3.30.1"
  [IMAGE_META]="supabase/postgres-meta:v0.96.3"
  [IMAGE_FUNCTIONS]="supabase/edge-runtime:v1.71.2"
  [IMAGE_LOGFLARE]="supabase/logflare:1.36.1"
  [IMAGE_VECTOR]="timberio/vector:0.28.1-alpine"
  [IMAGE_SUPAVISOR]="supabase/supavisor:2.7.4"
)

declare -A SERVICE_OF=(
  [IMAGE_STUDIO]="supabase-studio"
  [IMAGE_KONG]="kong"
  [IMAGE_AUTH]="auth"
  [IMAGE_REST]="rest"
  [IMAGE_REALTIME]="realtime"
  [IMAGE_STORAGE]="storage"
  [IMAGE_IMGPROXY]="imgproxy"
  [IMAGE_META]="meta"
  [IMAGE_FUNCTIONS]="functions"
  [IMAGE_LOGFLARE]="analytics"
  [IMAGE_VECTOR]="vector"
  [IMAGE_SUPAVISOR]="supavisor"
)

CHANGED=""
for key in "${!TARGETS[@]}"; do
  target="${TARGETS[$key]}"
  current=$(grep "^$key=" "$ENVFILE" | head -n1 | cut -d= -f2-)
  if [ -z "$current" ]; then
    log "WARN: $key not in .env, skipping"
    continue
  fi
  case "$current" in
    *@sha256:*) log "$key is digest-pinned, leaving alone"; continue ;;
  esac
  if [ "$current" = "$target" ]; then
    continue
  fi
  log "$key: $current → $target"
  sed -i.tmp "s|^$key=.*|$key=$target|" "$ENVFILE" && rm -f "$ENVFILE.tmp"
  CHANGED="$CHANGED ${SERVICE_OF[$key]}"
done

if [ -z "$CHANGED" ]; then
  log "all images already at target versions"
  exit 0
fi

log "pulling updated images"
docker compose pull $CHANGED >/dev/null 2>&1 || log "WARN: some pulls failed; see docker compose pull output"

log "recreating:$CHANGED"
docker compose up -d --force-recreate $CHANGED >/dev/null 2>&1 || \
  log "WARN: docker compose up exited non-zero; check container states"

log "migration 003 complete"
