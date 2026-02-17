#!/bin/bash
###############################################################################
# supabase-backup.sh  v2 — multi-server edition
# ---------------------------------------------------------------------------
# Comprehensive, encrypted, deduplicated backup for self-hosted Supabase.
# Designed for multiple Supabase instances backing up to ONE Hetzner
# Storage Box (or S3-compatible target).
#
# Backs up:
#   1. Postgres database (pg_dumpall — full consistent snapshot)
#   2. Storage objects   (MinIO / local volume — deduplicated by restic)
#   3. Config files      (.env, compose, caddy/nginx, authelia)
#
# Multi-server layout on Storage Box:
#   /backups/
#     ├── supabase-prod/        ← SERVER_NAME=supabase-prod
#     │   └── restic-repo
#     ├── supabase-staging/     ← SERVER_NAME=supabase-staging
#     │   └── restic-repo
#     └── supabase-client-x/    ← SERVER_NAME=supabase-client-x
#         └── restic-repo
#
# Each server has its own restic repo + encryption key.
# One compromised server cannot read another's backups.
#
# Setup (per server):
#   1. Install restic:          sudo apt install restic
#   2. Copy config:             cp backup.env.example backup.env
#   3. Edit config:             nano backup.env  (set SERVER_NAME + creds)
#   4. Init repo:               ./supabase-backup.sh --init
#   5. Test:                    ./supabase-backup.sh --now
#   6. Install cron:            sudo ./supabase-backup.sh --install-cron
#
# Commands:
#   --init              Initialize restic repository for this server
#   --now               Run backup immediately
#   --list              List snapshots for this server
#   --stats             Show repository size and snapshot count
#   --verify            Verify repository integrity (10% sample)
#   --restore SNAP      Restore a snapshot interactively
#   --restore-db SNAP   Restore only the database from a snapshot
#   --install-cron      Install daily 3am cron + log rotation
#   --uninstall-cron    Remove the cron job
#   --test-notify       Test the health-check notification
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_CONF="${SCRIPT_DIR}/backup.env"

# ── Colors ──────────────────────────────────────────────────────────────────
NO_COLOR='' RED='' CYAN='' GREEN='' YELLOW=''
if [ -t 1 ]; then
    nc=$(tput colors 2>/dev/null || echo 0)
    if [ "$nc" -ge 8 ]; then
        NO_COLOR='\033[0m'; RED='\033[0;31m'; CYAN='\033[0;36m'
        GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    fi
fi

ts() { date '+%Y-%m-%d %H:%M:%S'; }
info()  { echo -e "${CYAN}[INFO]${NO_COLOR}  $(ts)  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NO_COLOR}  $(ts)  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NO_COLOR}  $(ts)  $*"; }
fail()  { echo -e "${RED}[FAIL]${NO_COLOR}  $(ts)  $*"; exit 1; }

# ── Load config ─────────────────────────────────────────────────────────────
if [ ! -f "$BACKUP_CONF" ]; then
    fail "Config not found: $BACKUP_CONF\n  Run: cp backup.env.example backup.env && nano backup.env"
fi

# shellcheck disable=SC1090
source "$BACKUP_CONF"

# ── Validate required vars ──────────────────────────────────────────────────
: "${SERVER_NAME:?Set SERVER_NAME in backup.env (e.g. supabase-prod)}"
: "${BACKUP_BACKEND:?Set BACKUP_BACKEND in backup.env (hetzner or s3)}"
: "${RESTIC_PASSWORD:?Set RESTIC_PASSWORD in backup.env}"
: "${SUPABASE_DOCKER_DIR:?Set SUPABASE_DOCKER_DIR in backup.env}"

# Defaults
: "${POSTGRES_CONTAINER:=supabase-db}"
: "${POSTGRES_USER:=postgres}"
: "${RETENTION_DAILY:=7}"
: "${RETENTION_WEEKLY:=4}"
: "${RETENTION_MONTHLY:=6}"
: "${HEALTHCHECK_URL:=}"
: "${HEALTHCHECK_METHOD:=simple}"

# Validate SERVER_NAME (alphanumeric, hyphens, underscores only)
if [[ ! "$SERVER_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    fail "SERVER_NAME must be alphanumeric with hyphens/underscores only. Got: $SERVER_NAME"
fi

# ── Build restic repo URL ───────────────────────────────────────────────────
export RESTIC_PASSWORD

case "$BACKUP_BACKEND" in
    hetzner)
        : "${HETZNER_STORAGEBOX_USER:?Set HETZNER_STORAGEBOX_USER}"
        : "${HETZNER_STORAGEBOX_HOST:?Set HETZNER_STORAGEBOX_HOST}"
        : "${HETZNER_STORAGEBOX_BASE:=/backups}"
        export RESTIC_REPOSITORY="sftp:${HETZNER_STORAGEBOX_USER}@${HETZNER_STORAGEBOX_HOST}:${HETZNER_STORAGEBOX_BASE}/${SERVER_NAME}"
        ;;
    s3)
        : "${AWS_ACCESS_KEY_ID:?Set AWS_ACCESS_KEY_ID}"
        : "${AWS_SECRET_ACCESS_KEY:?Set AWS_SECRET_ACCESS_KEY}"
        : "${S3_BUCKET:?Set S3_BUCKET}"
        : "${S3_ENDPOINT:=}"
        export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
        if [ -n "$S3_ENDPOINT" ]; then
            export RESTIC_REPOSITORY="s3:${S3_ENDPOINT}/${S3_BUCKET}/${SERVER_NAME}"
        else
            export RESTIC_REPOSITORY="s3:s3.amazonaws.com/${S3_BUCKET}/${SERVER_NAME}"
        fi
        ;;
    *)
        fail "BACKUP_BACKEND must be 'hetzner' or 's3'"
        ;;
esac

# ── Verify dependencies ────────────────────────────────────────────────────
command -v restic &>/dev/null || fail "restic not installed. Run: sudo apt install restic"
command -v docker &>/dev/null || fail "docker not installed"

# Staging area — cleaned up on exit
STAGING_DIR=""
cleanup() {
    [ -n "$STAGING_DIR" ] && rm -rf "$STAGING_DIR"
}
trap cleanup EXIT

# ── Health-check notification ───────────────────────────────────────────────
# Supports:
#   - simple:    GET request on success, /fail on failure (healthchecks.io, uptime kuma push)
#   - ntfy:      POST to ntfy.sh topic
#   - slack:     POST to Slack webhook
#   - discord:   POST to Discord webhook
#   - none:      disabled
notify() {
    local status="$1"  # "ok" or "fail"
    local message="$2"

    [ -z "$HEALTHCHECK_URL" ] && return 0

    case "$HEALTHCHECK_METHOD" in
        simple)
            if [ "$status" = "ok" ]; then
                curl -fsS -m 10 --retry 3 "$HEALTHCHECK_URL" >/dev/null 2>&1 || true
            else
                curl -fsS -m 10 --retry 3 "$HEALTHCHECK_URL/fail" >/dev/null 2>&1 || true
            fi
            ;;
        ntfy)
            local priority="3"
            local tags="white_check_mark"
            if [ "$status" = "fail" ]; then priority="5"; tags="x"; fi
            curl -fsS -m 10 \
                -H "Title: Backup ${status}: ${SERVER_NAME}" \
                -H "Priority: $priority" \
                -H "Tags: $tags" \
                -d "$message" \
                "$HEALTHCHECK_URL" >/dev/null 2>&1 || true
            ;;
        slack|discord)
            local color="#36a64f"
            [ "$status" = "fail" ] && color="#ff0000"
            local payload
            if [ "$HEALTHCHECK_METHOD" = "slack" ]; then
                payload=$(cat <<EOJSON
{"attachments":[{"color":"$color","title":"Backup ${status}: ${SERVER_NAME}","text":"$message","ts":$(date +%s)}]}
EOJSON
)
            else
                payload="{\"content\":\"**Backup ${status}: ${SERVER_NAME}**\n${message}\"}"
            fi
            curl -fsS -m 10 -H "Content-Type: application/json" \
                -d "$payload" "$HEALTHCHECK_URL" >/dev/null 2>&1 || true
            ;;
        *)
            # Silently skip unknown methods
            ;;
    esac
}

# ── Functions ───────────────────────────────────────────────────────────────

do_init() {
    info "Initializing restic repository for '$SERVER_NAME'"
    info "Repository: $RESTIC_REPOSITORY"
    restic init
    ok "Repository initialized for '$SERVER_NAME'"
    echo ""
    echo "  SAVE YOUR RESTIC_PASSWORD SOMEWHERE SAFE!"
    echo "  Without it, your backups are UNRECOVERABLE."
    echo ""
    echo "  Repository: $RESTIC_REPOSITORY"
    echo "  Server:     $SERVER_NAME"
}

do_backup() {
    local start_time
    start_time=$(date +%s)

    STAGING_DIR=$(mktemp -d /tmp/supabase-backup-${SERVER_NAME}.XXXXXX)

    info "[$SERVER_NAME] Starting backup..."

    # ── 1. Postgres dump ────────────────────────────────────────────────
    info "[$SERVER_NAME] Dumping Postgres from container '$POSTGRES_CONTAINER'..."
    local dump_file="$STAGING_DIR/postgres_dump.sql.gz"

    # Write server metadata alongside the dump for easier restore identification
    cat > "$STAGING_DIR/backup_metadata.json" <<EOJSON
{
    "server_name": "$SERVER_NAME",
    "timestamp": "$(date -Iseconds)",
    "postgres_container": "$POSTGRES_CONTAINER",
    "supabase_dir": "$SUPABASE_DOCKER_DIR",
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')"
}
EOJSON

    if ! docker exec "$POSTGRES_CONTAINER" pg_dumpall -U "$POSTGRES_USER" --clean 2>/dev/null | gzip > "$dump_file"; then
        local errmsg="[$SERVER_NAME] Postgres dump FAILED"
        notify "fail" "$errmsg"
        fail "$errmsg"
    fi

    local dump_size
    dump_size=$(du -sh "$dump_file" | cut -f1)
    ok "[$SERVER_NAME] Postgres dump: $dump_size"

    # ── 2. Stage config files ───────────────────────────────────────────
    local config_staging="$STAGING_DIR/config"
    mkdir -p "$config_staging"
    local config_count=0

    for f in \
        "$SUPABASE_DOCKER_DIR/.env" \
        "$SUPABASE_DOCKER_DIR/docker-compose.yml" \
        "$SUPABASE_DOCKER_DIR/docker-compose.override.yml" \
        "$SUPABASE_DOCKER_DIR/volumes/caddy/Caddyfile" \
        "$SUPABASE_DOCKER_DIR/volumes/nginx/nginx.template" \
        "$SUPABASE_DOCKER_DIR/volumes/authelia/configuration.yml" \
        "$SUPABASE_DOCKER_DIR/volumes/authelia/users_database.yml"; do
        if [ -f "$f" ]; then
            local rel="${f#"$SUPABASE_DOCKER_DIR"/}"
            mkdir -p "$config_staging/$(dirname "$rel")"
            cp "$f" "$config_staging/$rel"
            config_count=$((config_count + 1))
        fi
    done

    # Also grab snippet directories if they exist
    for dir in \
        "$SUPABASE_DOCKER_DIR/volumes/caddy/snippets" \
        "$SUPABASE_DOCKER_DIR/volumes/nginx/snippets"; do
        if [ -d "$dir" ]; then
            local rel="${dir#"$SUPABASE_DOCKER_DIR"/}"
            mkdir -p "$config_staging/$rel"
            cp -r "$dir/"* "$config_staging/$rel/" 2>/dev/null || true
        fi
    done

    ok "[$SERVER_NAME] Config files staged ($config_count files)"

    # ── 3. Collect paths to back up ─────────────────────────────────────
    local backup_paths=("$STAGING_DIR")

    local storage_volume="$SUPABASE_DOCKER_DIR/volumes/storage"
    if [ -d "$storage_volume" ] && [ "$(ls -A "$storage_volume" 2>/dev/null)" ]; then
        backup_paths+=("$storage_volume")
        local storage_size
        storage_size=$(du -sh "$storage_volume" | cut -f1)
        info "[$SERVER_NAME] Including storage objects ($storage_size)"
    else
        warn "[$SERVER_NAME] No storage volume at $storage_volume — skipping"
    fi

    # ── 4. Run restic backup ────────────────────────────────────────────
    info "[$SERVER_NAME] Uploading to $BACKUP_BACKEND..."

    if ! restic backup \
        --tag supabase \
        --tag "$SERVER_NAME" \
        --tag "$(date +%Y%m%d)" \
        --host "$SERVER_NAME" \
        --verbose \
        "${backup_paths[@]}" 2>&1; then

        local errmsg="[$SERVER_NAME] Restic backup FAILED"
        notify "fail" "$errmsg"
        fail "$errmsg"
    fi

    ok "[$SERVER_NAME] Backup uploaded"

    # ── 5. Prune old snapshots ──────────────────────────────────────────
    info "[$SERVER_NAME] Pruning (keep: ${RETENTION_DAILY}d / ${RETENTION_WEEKLY}w / ${RETENTION_MONTHLY}m)..."
    restic forget \
        --host "$SERVER_NAME" \
        --tag supabase \
        --keep-daily "$RETENTION_DAILY" \
        --keep-weekly "$RETENTION_WEEKLY" \
        --keep-monthly "$RETENTION_MONTHLY" \
        --prune 2>&1

    local elapsed=$(( $(date +%s) - start_time ))
    local summary="Completed in ${elapsed}s. DB dump: ${dump_size}. Configs: ${config_count} files."
    ok "[$SERVER_NAME] Backup complete ($summary)"

    notify "ok" "$summary"
}

do_list() {
    info "[$SERVER_NAME] Listing snapshots..."
    restic snapshots --host "$SERVER_NAME" --tag supabase
}

do_stats() {
    info "[$SERVER_NAME] Repository statistics..."
    echo ""
    echo "  Snapshots:"
    restic snapshots --host "$SERVER_NAME" --tag supabase --compact
    echo ""
    echo "  Repository size:"
    restic stats --mode raw-data
}

do_verify() {
    info "[$SERVER_NAME] Verifying repository integrity (10% sample)..."
    restic check --read-data-subset=10%
    ok "[$SERVER_NAME] Repository integrity verified"
}

do_restore() {
    local snapshot_id="${1:-latest}"
    local restore_dir="${2:-/tmp/supabase-restore-${SERVER_NAME}-$(date +%s)}"

    echo ""
    info "[$SERVER_NAME] Restore plan:"
    echo "  Snapshot:    $snapshot_id"
    echo "  Restore to:  $restore_dir"
    echo ""

    if [ "$snapshot_id" = "latest" ]; then
        info "Fetching latest snapshot..."
        restic snapshots --host "$SERVER_NAME" --tag supabase --latest 1
        echo ""
    fi

    read -rp "Proceed with restore? [y/N] " answer
    [[ "${answer,,}" == "y" ]] || { echo "Aborted."; return 0; }

    mkdir -p "$restore_dir"
    restic restore "$snapshot_id" --host "$SERVER_NAME" --target "$restore_dir"

    ok "[$SERVER_NAME] Restored to $restore_dir"
    echo ""
    echo "  Contents:"
    ls -la "$restore_dir"/tmp/supabase-backup-*/ 2>/dev/null || ls -la "$restore_dir"/
    echo ""
    echo "  Next steps:"
    echo "  1. Review backup_metadata.json to confirm this is the right server/snapshot"
    echo "  2. Restore DB:     ./supabase-backup.sh --restore-db $snapshot_id"
    echo "  3. Restore config: copy files from $restore_dir/.../config/ to $SUPABASE_DOCKER_DIR/"
    echo "  4. Restore storage: copy from $restore_dir/.../storage/ to $SUPABASE_DOCKER_DIR/volumes/storage/"
    echo ""
}

do_restore_db() {
    local snapshot_id="${1:-latest}"
    local restore_dir
    restore_dir=$(mktemp -d /tmp/supabase-dbrestore-${SERVER_NAME}.XXXXXX)

    info "[$SERVER_NAME] Extracting database dump from snapshot $snapshot_id..."

    # Restore only the dump file
    restic restore "$snapshot_id" \
        --host "$SERVER_NAME" \
        --include "postgres_dump.sql.gz" \
        --include "backup_metadata.json" \
        --target "$restore_dir"

    # Find the dump file
    local dump_file
    dump_file=$(find "$restore_dir" -name "postgres_dump.sql.gz" -type f | head -1)

    if [ -z "$dump_file" ]; then
        rm -rf "$restore_dir"
        fail "No postgres_dump.sql.gz found in snapshot $snapshot_id"
    fi

    # Show metadata
    local meta_file
    meta_file=$(find "$restore_dir" -name "backup_metadata.json" -type f | head -1)
    if [ -n "$meta_file" ]; then
        echo ""
        echo "  Backup metadata:"
        cat "$meta_file" | jq . 2>/dev/null || cat "$meta_file"
        echo ""
    fi

    local dump_size
    dump_size=$(du -sh "$dump_file" | cut -f1)
    info "Found dump: $dump_file ($dump_size)"

    echo ""
    warn "This will DROP and recreate all databases in container '$POSTGRES_CONTAINER'!"
    read -rp "Are you absolutely sure? Type 'yes' to confirm: " answer

    if [ "$answer" != "yes" ]; then
        echo "Aborted. Dump is still available at: $dump_file"
        return 0
    fi

    info "Restoring database..."
    if gunzip < "$dump_file" | docker exec -i "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" 2>&1; then
        ok "[$SERVER_NAME] Database restored successfully"
    else
        warn "Restore completed with warnings (some errors are normal for pg_dumpall --clean)"
    fi

    rm -rf "$restore_dir"
}

do_install_cron() {
    local cron_schedule="${1:-0 3 * * *}"
    local script_path
    script_path=$(readlink -f "$0")

    local log_file="/var/log/supabase-backup-${SERVER_NAME}.log"
    local cron_id="supabase-backup-${SERVER_NAME}"
    local cron_cmd="$cron_schedule $script_path --now >> $log_file 2>&1  # $cron_id"

    # Check for existing
    if crontab -l 2>/dev/null | grep -q "$cron_id"; then
        warn "Cron already exists for '$SERVER_NAME':"
        crontab -l | grep "$cron_id"
        read -rp "Replace? [y/N] " answer
        [[ "${answer,,}" == "y" ]] || { echo "Keeping existing."; return 0; }
        crontab -l 2>/dev/null | grep -v "$cron_id" | crontab -
    fi

    (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab -
    ok "Cron installed for '$SERVER_NAME': $cron_schedule"

    # Log rotation
    cat > "/etc/logrotate.d/supabase-backup-${SERVER_NAME}" <<EOF
$log_file {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 640 root root
}
EOF
    ok "Log rotation: $log_file"
}

do_uninstall_cron() {
    local cron_id="supabase-backup-${SERVER_NAME}"
    if crontab -l 2>/dev/null | grep -q "$cron_id"; then
        crontab -l | grep -v "$cron_id" | crontab -
        ok "Cron removed for '$SERVER_NAME'"
    else
        warn "No cron found for '$SERVER_NAME'"
    fi
}

do_test_notify() {
    if [ -z "$HEALTHCHECK_URL" ]; then
        fail "HEALTHCHECK_URL not set in backup.env"
    fi
    info "Testing notification ($HEALTHCHECK_METHOD)..."
    notify "ok" "Test notification from $SERVER_NAME at $(ts)"
    ok "Notification sent — check your endpoint"
}

# ── Usage ───────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Supabase Backup v2 — multi-server edition

Server:     $SERVER_NAME
Repository: $RESTIC_REPOSITORY

Commands:
  --init              Initialize restic repo for this server
  --now               Run backup now
  --list              List snapshots
  --stats             Show repo size and snapshot count
  --verify            Verify integrity (10% sample)
  --restore [SNAP]    Full restore (default: latest)
  --restore-db [SNAP] Restore only database (default: latest)
  --install-cron      Install daily 3am cron
  --uninstall-cron    Remove cron
  --test-notify       Test health-check notification
  -h, --help          Show this message
EOF
}

# ── Main ────────────────────────────────────────────────────────────────────
case "${1:---help}" in
    --init)            do_init ;;
    --now)             do_backup ;;
    --list)            do_list ;;
    --stats)           do_stats ;;
    --verify)          do_verify ;;
    --restore)         do_restore "${2:-latest}" "${3:-}" ;;
    --restore-db)      do_restore_db "${2:-latest}" ;;
    --install-cron)    do_install_cron "${2:-}" ;;
    --uninstall-cron)  do_uninstall_cron ;;
    --test-notify)     do_test_notify ;;
    -h|--help)         usage ;;
    *)                 fail "Unknown command: $1. Run with --help" ;;
esac