#!/bin/bash
set -uo pipefail
cd /opt/supabase/docker

REQ=./upgrade/migrate-request.json
RES=./upgrade/migrate-result.json
LOG=./upgrade/migrate.log
VERSION_FILE=./.supafast-version
STAGING=./upgrade/migrations
BACKUP_DIR=./upgrade/migrations-backup
SNAPSHOT_FILES=(".env" "volumes/api/kong.yml" "docker-compose.yml")
RECREATE_SVCS="auth rest realtime storage meta kong"
[ -f "$REQ" ] || exit 0
mkdir -p "$BACKUP_DIR"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

REQ_ID=$(jq -r '.id // ""' "$REQ" 2>/dev/null || echo "")
MODE=$(jq -r '.mode // "apply"' "$REQ" 2>/dev/null || echo "apply")
echo "[$(ts)] migrate request id=$REQ_ID mode=$MODE" >> "$LOG"

current=0
if [ -f "$VERSION_FILE" ]; then
  v=$(cat "$VERSION_FILE" | tr -d '[:space:]')
  case "$v" in ''|*[!0-9]*) current=0 ;; *) current=$v ;; esac
fi

write_result() {
  local lb="${5:-}"
  cat > "$RES" <<EOF
{"id":"$REQ_ID","status":"$1","applied":$2,"version":$3,"message":"$4","last_backup":"$lb","at":"$(ts)"}
EOF
}

make_snapshot() {
  local mig="$1" prev="$2"
  local stamp; stamp=$(date -u +%Y%m%dT%H%M%SZ)
  local slug; slug=${mig%.sh}
  local tar="$BACKUP_DIR/${slug}-${stamp}.tar.gz"
  local manifest="$BACKUP_DIR/${slug}-${stamp}.json"
  tar -czf "$tar" "${SNAPSHOT_FILES[@]}" 2>>"$LOG" || return 1
  cat > "$manifest" <<EOF
{"migration":"$mig","pre_version":$prev,"tar":"$(basename "$tar")","at":"$(ts)"}
EOF
  echo "$tar"
}

restore_snapshot() {
  local tar="$1"
  [ -f "$tar" ] || return 1
  tar -xzf "$tar" -C . 2>>"$LOG"
}

recreate_services() {
  docker compose up -d --force-recreate $RECREATE_SVCS >>"$LOG" 2>&1 || true
}

if [ "$MODE" = "revert" ]; then
  manifest=$(ls -1t "$BACKUP_DIR"/*.json 2>/dev/null | head -n1 || true)
  if [ -z "$manifest" ]; then
    write_result "error" 0 "$current" "no snapshot to revert"
    exit 0
  fi
  tar=$(jq -r '.tar' "$manifest")
  prev=$(jq -r '.pre_version' "$manifest")
  echo "[$(ts)] reverting via $manifest (pre_version=$prev)" >> "$LOG"
  if ! restore_snapshot "$BACKUP_DIR/$tar"; then
    write_result "error" 0 "$current" "snapshot restore failed"
    exit 0
  fi
  echo "$prev" > "$VERSION_FILE"
  recreate_services
  mv "$manifest" "$manifest.consumed" 2>/dev/null || true
  write_result "ok" 0 "$prev" "reverted to version $prev"
  exit 0
fi

applied=0
failed_name=""
last_backup=""

# shellcheck disable=SC2012
scripts=$(ls "$STAGING" 2>/dev/null | grep -E '^[0-9]{3}_.*\.sh$' | sort -n || true)

for f in $scripts; do
  num=$(echo "$f" | sed -E 's/^0*([0-9]+)_.*/\1/')
  if [ "$num" -le "$current" ]; then continue; fi

  pre_version=$current
  if ! snap=$(make_snapshot "$f" "$pre_version"); then
    echo "[$(ts)] snapshot failed for $f" >> "$LOG"
    failed_name=$f
    break
  fi
  last_backup=$(basename "$snap")

  echo "[$(ts)] applying $f (current=$current → $num); snapshot=$last_backup" >> "$LOG"
  chmod +x "$STAGING/$f" 2>/dev/null || true
  if bash "$STAGING/$f" >> "$LOG" 2>&1; then
    echo "$num" > "$VERSION_FILE"
    current=$num
    applied=$((applied + 1))
    echo "[$(ts)] applied $f; version now $num" >> "$LOG"
  else
    echo "[$(ts)] FAILED: $f — restoring snapshot" >> "$LOG"
    restore_snapshot "$snap" || echo "[$(ts)] WARNING: restore failed" >> "$LOG"
    recreate_services
    failed_name=$f
    break
  fi
done

if [ -n "$failed_name" ]; then
  write_result "error" "$applied" "$current" "migration $failed_name failed; rolled back" "$last_backup"
else
  write_result "ok" "$applied" "$current" "applied $applied migration(s)" "$last_backup"
fi
