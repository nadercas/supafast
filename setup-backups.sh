#!/bin/bash
###############################################################################
# setup-backups.sh
# ---------------------------------------------------------------------------
# Run ONCE per Supabase server as the deploy user (with sudo).
# Automates all of Phase 4: SSH key, Storage Box connection, restic init,
# backup script installation, first backup, and cron scheduling.
#
# Usage:
#   ./setup-backups.sh
#
# Prerequisites:
#   - Storage Box ordered and SSH enabled in Hetzner Robot panel
#   - supabase-backup.sh and backup.env.example in the same directory
#     OR the script will create them for you
###############################################################################

set -euo pipefail

NO_COLOR='' RED='' CYAN='' GREEN='' YELLOW=''
if [ -t 1 ]; then
    nc=$(tput colors 2>/dev/null || echo 0)
    if [ "$nc" -ge 8 ]; then
        NO_COLOR='\033[0m'; RED='\033[0;31m'; CYAN='\033[0;36m'
        GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    fi
fi

info()  { echo -e "${CYAN}[INFO]${NO_COLOR}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NO_COLOR}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NO_COLOR}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NO_COLOR}  $*"; exit 1; }
prompt() { echo -en "${GREEN}$1${NO_COLOR}"; }

echo ""
echo "======================================================="
echo "  Supabase Backup Setup — Phase 4 Automation"
echo "======================================================="
echo ""

# ── Step 1: Gather information ──────────────────────────────────────────────
info "I'll need a few details about your setup."
echo ""

# Server name
read -rp "$(prompt 'Server name (e.g. supabase-prod): ')" SERVER_NAME
while [[ ! "$SERVER_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; do
    warn "Only letters, numbers, hyphens, underscores allowed"
    read -rp "$(prompt 'Server name: ')" SERVER_NAME
done

# Supabase docker directory
DEFAULT_DOCKER_DIR="$HOME/supabase-automated-self-host/docker"
read -rp "$(prompt "Supabase docker directory [$DEFAULT_DOCKER_DIR]: ")" SUPABASE_DOCKER_DIR
SUPABASE_DOCKER_DIR="${SUPABASE_DOCKER_DIR:-$DEFAULT_DOCKER_DIR}"

if [ ! -d "$SUPABASE_DOCKER_DIR" ]; then
    fail "Directory not found: $SUPABASE_DOCKER_DIR"
fi

if [ ! -f "$SUPABASE_DOCKER_DIR/docker-compose.yml" ]; then
    fail "No docker-compose.yml in $SUPABASE_DOCKER_DIR — is this the right directory?"
fi

# Postgres container name
DEFAULT_PG_CONTAINER="supabase-db"
read -rp "$(prompt "Postgres container name [$DEFAULT_PG_CONTAINER]: ")" POSTGRES_CONTAINER
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-$DEFAULT_PG_CONTAINER}"

# Verify container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${POSTGRES_CONTAINER}$"; then
    warn "Container '$POSTGRES_CONTAINER' is not currently running."
    read -rp "$(prompt 'Continue anyway? [y/N]: ')" answer
    [[ "${answer,,}" == "y" ]] || exit 0
fi

echo ""
info "Storage Box details (from Hetzner Robot panel):"

read -rp "$(prompt 'Storage Box username (e.g. u123456): ')" SB_USER
while [ -z "$SB_USER" ]; do
    read -rp "$(prompt 'Storage Box username: ')" SB_USER
done

read -rp "$(prompt 'Storage Box hostname (e.g. u123456.your-storagebox.de): ')" SB_HOST
while [ -z "$SB_HOST" ]; do
    read -rp "$(prompt 'Storage Box hostname: ')" SB_HOST
done

SB_PORT=23
read -rp "$(prompt "Storage Box SSH port [$SB_PORT]: ")" input_port
SB_PORT="${input_port:-$SB_PORT}"

# Notification (optional)
echo ""
info "Health-check notifications (optional — press Enter to skip)"
echo "  Supported: healthchecks.io URL, ntfy.sh topic URL, Slack/Discord webhook"
read -rp "$(prompt 'Health-check URL []: ')" HEALTHCHECK_URL

HEALTHCHECK_METHOD="simple"
if [ -n "$HEALTHCHECK_URL" ]; then
    if [[ "$HEALTHCHECK_URL" == *"ntfy"* ]]; then
        HEALTHCHECK_METHOD="ntfy"
    elif [[ "$HEALTHCHECK_URL" == *"slack"* ]]; then
        HEALTHCHECK_METHOD="slack"
    elif [[ "$HEALTHCHECK_URL" == *"discord"* ]]; then
        HEALTHCHECK_METHOD="discord"
    fi
    info "Auto-detected notification method: $HEALTHCHECK_METHOD"
fi

# ── Step 2: Generate restic password ────────────────────────────────────────
echo ""
RESTIC_PASSWORD=$(openssl rand -base64 32)
ok "Generated unique RESTIC_PASSWORD for this server"
echo ""
echo -e "  ${RED}╔══════════════════════════════════════════════════════════════╗${NO_COLOR}"
echo -e "  ${RED}║  SAVE THIS PASSWORD — without it, backups are UNRECOVERABLE ║${NO_COLOR}"
echo -e "  ${RED}╠══════════════════════════════════════════════════════════════╣${NO_COLOR}"
echo -e "  ${RED}║${NO_COLOR}  Server:   $SERVER_NAME"
echo -e "  ${RED}║${NO_COLOR}  Password: $RESTIC_PASSWORD"
echo -e "  ${RED}╚══════════════════════════════════════════════════════════════╝${NO_COLOR}"
echo ""
read -rp "$(prompt 'I have saved this password somewhere safe [y/N]: ')" saved
if [[ "${saved,,}" != "y" ]]; then
    warn "Please save the password above before continuing!"
    read -rp "$(prompt 'Ready now? [y/N]: ')" saved2
    [[ "${saved2,,}" == "y" ]] || fail "Aborted — save your password first"
fi

# ── Step 3: Generate SSH key for Storage Box ────────────────────────────────
echo ""
SB_KEY="$HOME/.ssh/storagebox_${SERVER_NAME}"

if [ -f "$SB_KEY" ]; then
    warn "SSH key already exists: $SB_KEY — reusing"
else
    info "Generating SSH key for Storage Box..."
    mkdir -p "$HOME/.ssh"
    ssh-keygen -t ed25519 -f "$SB_KEY" -N "" -C "backup-${SERVER_NAME}-$(hostname)"
    ok "SSH key generated: $SB_KEY"
fi

# ── Step 4: Install SSH key on Storage Box ──────────────────────────────────
echo ""
info "Now I need to install the SSH key on your Storage Box."
echo ""
echo "  Your public key:"
echo -e "  ${CYAN}$(cat "${SB_KEY}.pub")${NO_COLOR}"
echo ""
echo "  Two options:"
echo "  1. I'll try ssh-copy-id (you'll need the Storage Box password once)"
echo "  2. You paste the key manually in Hetzner Robot panel"
echo ""
read -rp "$(prompt 'Try ssh-copy-id? [Y/n]: ')" method

if [[ "${method,,}" != "n" ]]; then
    info "Running ssh-copy-id (enter your Storage Box password when prompted)..."
    if ssh-copy-id -p "$SB_PORT" -i "${SB_KEY}.pub" "${SB_USER}@${SB_HOST}" 2>&1; then
        ok "SSH key installed on Storage Box"
    else
        warn "ssh-copy-id failed. Please add the key manually in Hetzner Robot."
        echo "  Key: $(cat "${SB_KEY}.pub")"
        read -rp "$(prompt 'Press Enter once you have added the key...')"
    fi
else
    echo "  Please add this key in Hetzner Robot → Storage Box → SSH Keys:"
    echo "  $(cat "${SB_KEY}.pub")"
    read -rp "$(prompt 'Press Enter once you have added the key...')"
fi

# ── Step 5: Configure SSH config ────────────────────────────────────────────
SSH_CONFIG="$HOME/.ssh/config"
SB_ALIAS="storagebox-${SERVER_NAME}"

if grep -q "Host $SB_ALIAS" "$SSH_CONFIG" 2>/dev/null; then
    warn "SSH config entry '$SB_ALIAS' already exists — skipping"
else
    info "Adding Storage Box to SSH config..."
    cat >> "$SSH_CONFIG" <<EOF

Host $SB_ALIAS
    HostName $SB_HOST
    User $SB_USER
    Port $SB_PORT
    IdentityFile $SB_KEY
    StrictHostKeyChecking accept-new
EOF
    chmod 600 "$SSH_CONFIG"
    ok "SSH config updated (alias: $SB_ALIAS)"
fi

# ── Step 6: Test Storage Box connection ─────────────────────────────────────
echo ""
info "Testing Storage Box connection..."
if ssh -o ConnectTimeout=10 "$SB_ALIAS" "echo connection_ok" 2>/dev/null | grep -q "connection_ok"; then
    ok "Storage Box connection successful"
else
    # Storage Boxes don't always support shell — try sftp
    if echo "ls" | sftp -o ConnectTimeout=10 "$SB_ALIAS" >/dev/null 2>&1; then
        ok "Storage Box SFTP connection successful"
    else
        fail "Cannot connect to Storage Box. Check credentials and that SSH is enabled in Hetzner Robot."
    fi
fi

# ── Step 7: Install restic ─────────────────────────────────────────────────
echo ""
if command -v restic &>/dev/null; then
    ok "restic already installed ($(restic version 2>&1 | head -1))"
else
    info "Installing restic..."
    sudo apt-get update -qq && sudo apt-get install -y -qq restic
    ok "restic installed"
fi

# ── Step 8: Create backup.env ──────────────────────────────────────────────
BACKUP_DIR="$SUPABASE_DOCKER_DIR"
BACKUP_ENV="$BACKUP_DIR/backup.env"

if [ -f "$BACKUP_ENV" ]; then
    warn "$BACKUP_ENV already exists"
    read -rp "$(prompt 'Overwrite? [y/N]: ')" overwrite
    [[ "${overwrite,,}" == "y" ]] || fail "Aborted — edit backup.env manually if needed"
fi

info "Writing backup.env..."
cat > "$BACKUP_ENV" <<EOF
# Auto-generated by setup-backups.sh on $(date -Iseconds)
# Server: $SERVER_NAME

SERVER_NAME="$SERVER_NAME"
RESTIC_PASSWORD="$RESTIC_PASSWORD"
BACKUP_BACKEND="hetzner"
SUPABASE_DOCKER_DIR="$SUPABASE_DOCKER_DIR"

POSTGRES_CONTAINER="$POSTGRES_CONTAINER"
POSTGRES_USER="postgres"

RETENTION_DAILY=7
RETENTION_WEEKLY=4
RETENTION_MONTHLY=6

HETZNER_STORAGEBOX_USER="$SB_USER"
HETZNER_STORAGEBOX_HOST="$SB_HOST"
HETZNER_STORAGEBOX_BASE="/backups"

HEALTHCHECK_URL="$HEALTHCHECK_URL"
HEALTHCHECK_METHOD="$HEALTHCHECK_METHOD"
EOF

chmod 600 "$BACKUP_ENV"
ok "backup.env created"

# ── Step 9: Install supabase-backup.sh if not present ───────────────────────
BACKUP_SCRIPT="$BACKUP_DIR/supabase-backup.sh"

if [ ! -f "$BACKUP_SCRIPT" ]; then
    # Check if it's in the same directory as this setup script
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/supabase-backup.sh" ]; then
        cp "$SCRIPT_DIR/supabase-backup.sh" "$BACKUP_SCRIPT"
        ok "Copied supabase-backup.sh to $BACKUP_DIR"
    else
        fail "supabase-backup.sh not found. Place it in $BACKUP_DIR or $(dirname "$0")/"
    fi
fi
chmod +x "$BACKUP_SCRIPT"

# ── Step 10: Override RESTIC_REPOSITORY to use SSH alias ────────────────────
# The backup script builds the repo URL from backup.env, but we need to
# make sure restic uses our SSH config alias for the port/key.
# We do this by setting the SFTP command in the SSH config (already done above).
# However, restic's sftp backend needs the host to match our SSH config.
# Let's update backup.env to use the alias.
sed -i "s|HETZNER_STORAGEBOX_HOST=.*|HETZNER_STORAGEBOX_HOST=\"$SB_ALIAS\"|" "$BACKUP_ENV"
ok "Updated backup.env to use SSH alias '$SB_ALIAS'"

# ── Step 11: Initialize restic repository ───────────────────────────────────
echo ""
info "Initializing restic repository for '$SERVER_NAME'..."
cd "$BACKUP_DIR"

if ./supabase-backup.sh --init 2>&1; then
    ok "Restic repository initialized"
else
    # May already be initialized
    warn "Init returned an error — repository may already exist. Continuing..."
fi

# ── Step 12: Run first backup ───────────────────────────────────────────────
echo ""
read -rp "$(prompt 'Run first backup now? (Supabase must be running) [Y/n]: ')" run_now

if [[ "${run_now,,}" != "n" ]]; then
    info "Running first backup..."
    if ./supabase-backup.sh --now; then
        ok "First backup completed!"
        echo ""
        info "Verifying snapshot:"
        ./supabase-backup.sh --list
    else
        warn "Backup had issues — check the output above"
    fi
fi

# ── Step 13: Install cron ──────────────────────────────────────────────────
echo ""
read -rp "$(prompt 'Install daily 3am backup cron? [Y/n]: ')" install_cron

if [[ "${install_cron,,}" != "n" ]]; then
    sudo "$BACKUP_SCRIPT" --install-cron
    ok "Daily backup cron installed"
fi

# ── Step 14: Test notification ──────────────────────────────────────────────
if [ -n "$HEALTHCHECK_URL" ]; then
    echo ""
    read -rp "$(prompt 'Test health-check notification? [Y/n]: ')" test_notify
    if [[ "${test_notify,,}" != "n" ]]; then
        ./supabase-backup.sh --test-notify
    fi
fi

# ── Done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}=======================================================${NO_COLOR}"
echo -e "${GREEN}  Backup setup complete for: $SERVER_NAME${NO_COLOR}"
echo -e "${GREEN}=======================================================${NO_COLOR}"
echo ""
echo "  Storage Box:  $SB_USER@$SB_HOST"
echo "  Repository:   /backups/$SERVER_NAME"
echo "  Schedule:     Daily at 3:00 AM"
echo "  Log:          /var/log/supabase-backup-${SERVER_NAME}.log"
echo ""
echo "  Useful commands:"
echo "    cd $BACKUP_DIR"
echo "    ./supabase-backup.sh --now         # manual backup"
echo "    ./supabase-backup.sh --list        # list snapshots"
echo "    ./supabase-backup.sh --stats       # repo size"
echo "    ./supabase-backup.sh --restore     # restore latest"
echo "    ./supabase-backup.sh --restore-db  # restore only database"
echo ""
echo -e "  ${RED}Remember: your RESTIC_PASSWORD is stored in backup.env${NO_COLOR}"
echo -e "  ${RED}Make sure you have a copy somewhere safe outside this server!${NO_COLOR}"
echo ""