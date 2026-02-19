#!/bin/bash
# migrate-server.sh
# Run as root on your existing Supabase server.
# Handles two independent tasks:
#   1. Migrate backups from Hetzner Storage Box → AWS S3
#   2. Change the domain (Caddyfile + Authelia + .env)

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m' C='\033[0;36m' B='\033[1m' N='\033[0m'
else
  R='' G='' Y='' C='' B='' N=''
fi

info()  { echo -e "${C}[INFO]${N}  $*"; }
ok()    { echo -e "${G}[ OK ]${N}  $*"; }
warn()  { echo -e "${Y}[WARN]${N}  $*"; }
die()   { echo -e "${R}[FAIL]${N}  $*"; exit 1; }
ask()   { echo -en "${G}$1${N}"; }
header() {
  echo ""
  echo -e "${B}${C}══════════════════════════════════════════════════════${N}"
  echo -e "${B}${C}  $*${N}"
  echo -e "${B}${C}══════════════════════════════════════════════════════${N}"
  echo ""
}

# ── Detect Supabase dir ───────────────────────────────────────────────────────
SUPABASE_DIR="/root/supabase/docker"
if [ ! -f "$SUPABASE_DIR/docker-compose.yml" ]; then
  ask "Supabase docker dir not found at $SUPABASE_DIR. Enter path: "
  read -r SUPABASE_DIR
  [ -f "$SUPABASE_DIR/docker-compose.yml" ] || die "No docker-compose.yml found at $SUPABASE_DIR"
fi

ENV_FILE="$SUPABASE_DIR/.env"
COMPOSE_FILE="$SUPABASE_DIR/docker-compose.yml"
BACKUP_ENV="$SUPABASE_DIR/backup.env"
CADDYFILE="$SUPABASE_DIR/volumes/caddy/Caddyfile"
AUTHELIA_CFG="$SUPABASE_DIR/volumes/authelia/configuration.yml"

[ -f "$ENV_FILE" ] || die ".env not found at $ENV_FILE"

# ── Helper: upsert a KEY=VALUE line in a file ─────────────────────────────────
upsert_env() {
  local file="$1" key="$2" value="$3"
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

# ── Menu ──────────────────────────────────────────────────────────────────────
clear
echo ""
echo -e "${B}${C}  Supabase Server Migration Script${N}"
echo -e "  Working directory: ${C}$SUPABASE_DIR${N}"
echo ""
echo "  What do you want to do?"
echo "    1) Migrate backups to AWS S3  (remove Hetzner Storage Box)"
echo "    2) Change domain"
echo "    3) Install MCP server         (Claude / Cursor integration)"
echo "    4) All of the above"
echo ""
ask "Choice [1/2/3/4]: "; read -r CHOICE
[[ "$CHOICE" =~ ^[1234]$ ]] || die "Invalid choice"

DO_S3=false; DO_DOMAIN=false; DO_MCP=false
[[ "$CHOICE" == "1" || "$CHOICE" == "4" ]] && DO_S3=true
[[ "$CHOICE" == "2" || "$CHOICE" == "4" ]] && DO_DOMAIN=true
[[ "$CHOICE" == "3" || "$CHOICE" == "4" ]] && DO_MCP=true

# ══════════════════════════════════════════════════════════════════════════════
# TASK 1: S3 BACKUP MIGRATION
# ══════════════════════════════════════════════════════════════════════════════
if $DO_S3; then
  header "Task 1: Migrate Backups to AWS S3"

  # Detect server name from .env
  SERVER_NAME=$(grep "^SERVER_NAME=" "$ENV_FILE" | cut -d= -f2 | tr -d '"' || true)
  if [ -z "$SERVER_NAME" ]; then
    ask "Server name (used as S3 prefix, e.g. supabase-prod): "; read -r SERVER_NAME
  else
    info "Detected server name from .env: ${B}$SERVER_NAME${N}"
    ask "Use '$SERVER_NAME' as S3 prefix? [Y/n]: "; read -r yn
    if [[ "${yn,,}" == "n" ]]; then
      ask "Enter S3 prefix: "; read -r SERVER_NAME
    fi
  fi

  # Collect S3 credentials
  echo ""
  info "Enter your AWS S3 credentials:"
  echo "  (IAM user needs: s3:PutObject, s3:GetObject, s3:ListBucket, s3:DeleteObject)"
  echo ""
  ask "S3 Bucket name: "; read -r S3_BUCKET
  [ -n "$S3_BUCKET" ] || die "Bucket name required"

  ask "AWS Region [us-east-1]: "; read -r S3_REGION
  S3_REGION="${S3_REGION:-us-east-1}"

  ask "AWS Access Key ID: "; read -r S3_ACCESS_KEY
  [ -n "$S3_ACCESS_KEY" ] || die "Access key required"

  ask "AWS Secret Access Key: "; read -rs S3_SECRET_KEY; echo ""
  [ -n "$S3_SECRET_KEY" ] || die "Secret key required"

  S3_REPO="s3:s3.${S3_REGION}.amazonaws.com/${S3_BUCKET}/${SERVER_NAME}"

  echo ""
  info "S3 repository will be: ${B}${S3_REPO}${N}"
  ask "Confirm? [Y/n]: "; read -r yn
  [[ "${yn,,}" != "n" ]] || die "Aborted"

  # ── 1. Install restic ──────────────────────────────────────────────────────
  echo ""
  if command -v restic &>/dev/null; then
    ok "restic already installed ($(restic version 2>&1 | head -1))"
  else
    info "Installing restic..."
    apt-get update -qq && apt-get install -y -qq restic
    ok "restic installed"
  fi

  # ── 2. Init S3 repository ──────────────────────────────────────────────────
  echo ""
  info "Initializing restic repository at ${S3_REPO}..."
  export RESTIC_REPOSITORY="$S3_REPO"
  export RESTIC_PASSWORD
  RESTIC_PASSWORD=$(grep "^RESTIC_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || \
                    grep "^RESTIC_PASSWORD=" "$BACKUP_ENV" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)

  if [ -z "$RESTIC_PASSWORD" ]; then
    warn "RESTIC_PASSWORD not found in .env or backup.env."
    ask "Enter your existing restic password (or leave blank to generate a new one): "; read -rs RESTIC_PASSWORD; echo ""
    if [ -z "$RESTIC_PASSWORD" ]; then
      RESTIC_PASSWORD=$(openssl rand -hex 24)
      echo ""
      echo -e "  ${R}╔══════════════════════════════════════════════════════════════╗${N}"
      echo -e "  ${R}║  NEW RESTIC_PASSWORD — SAVE THIS NOW, BACKUPS ARE LOST W/O  ║${N}"
      echo -e "  ${R}║  Password: ${RESTIC_PASSWORD}  ║${N}"
      echo -e "  ${R}╚══════════════════════════════════════════════════════════════╝${N}"
      echo ""
      ask "I've saved the password [y/N]: "; read -r saved
      [[ "${saved,,}" == "y" ]] || die "Save the password first, then re-run"
    fi
  else
    ok "Using existing RESTIC_PASSWORD from config"
  fi

  AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY"
  AWS_SECRET_ACCESS_KEY="$S3_SECRET_KEY"
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

  if restic init 2>&1; then
    ok "S3 repository initialized"
  else
    warn "restic init returned non-zero — repository may already exist, continuing"
  fi

  # ── 3. Update backup.env ───────────────────────────────────────────────────
  echo ""
  info "Updating backup.env..."
  # Write fresh backup.env (preserve non-S3 keys if file exists)
  if [ -f "$BACKUP_ENV" ]; then
    # Remove old storage box + repo lines, then we'll append
    sed -i '/^RESTIC_REPOSITORY=/d' "$BACKUP_ENV"
    sed -i '/^AWS_ACCESS_KEY_ID=/d' "$BACKUP_ENV"
    sed -i '/^AWS_SECRET_ACCESS_KEY=/d' "$BACKUP_ENV"
    sed -i '/^BACKUP_BACKEND=/d' "$BACKUP_ENV"
    sed -i '/^HETZNER_/d' "$BACKUP_ENV"
    # Add RESTIC_PASSWORD if missing
    if ! grep -q "^RESTIC_PASSWORD=" "$BACKUP_ENV"; then
      echo "RESTIC_PASSWORD=\"$RESTIC_PASSWORD\"" >> "$BACKUP_ENV"
    fi
    {
      echo "RESTIC_REPOSITORY=\"$S3_REPO\""
      echo "AWS_ACCESS_KEY_ID=\"$S3_ACCESS_KEY\""
      echo "AWS_SECRET_ACCESS_KEY=\"$S3_SECRET_KEY\""
    } >> "$BACKUP_ENV"
  else
    cat > "$BACKUP_ENV" <<BENV
SERVER_NAME="${SERVER_NAME}"
RESTIC_PASSWORD="${RESTIC_PASSWORD}"
SUPABASE_DOCKER_DIR="${SUPABASE_DIR}"
POSTGRES_CONTAINER="supabase-db"
POSTGRES_USER="postgres"
RESTIC_REPOSITORY="${S3_REPO}"
AWS_ACCESS_KEY_ID="${S3_ACCESS_KEY}"
AWS_SECRET_ACCESS_KEY="${S3_SECRET_KEY}"
RETENTION_DAILY=7
RETENTION_WEEKLY=4
RETENTION_MONTHLY=6
HEALTHCHECK_URL=""
BENV
  fi
  chmod 600 "$BACKUP_ENV"
  ok "backup.env updated"

  # ── 4. Update .env ─────────────────────────────────────────────────────────
  info "Updating .env..."
  upsert_env "$ENV_FILE" "RESTIC_REPOSITORY" "\"$S3_REPO\""
  upsert_env "$ENV_FILE" "AWS_ACCESS_KEY_ID" "\"$S3_ACCESS_KEY\""
  upsert_env "$ENV_FILE" "AWS_SECRET_ACCESS_KEY" "\"$S3_SECRET_KEY\""
  # Remove old local repo line if present
  sed -i '/^RESTIC_REPOSITORY=\/backups/d' "$ENV_FILE" 2>/dev/null || true
  ok ".env updated"

  # ── 5. Patch docker-compose.yml ────────────────────────────────────────────
  info "Patching docker-compose.yml..."
  # Remove old local /backup volume mount
  sed -i '/\${RESTIC_REPOSITORY:-\/backups}:\/backup/d' "$COMPOSE_FILE"
  sed -i '/RESTIC_REPOSITORY:-\/backups/d' "$COMPOSE_FILE"
  # Fix RESTIC_REPOSITORY pointing to hardcoded /backup
  sed -i 's|RESTIC_REPOSITORY: /backup$|RESTIC_REPOSITORY: ${RESTIC_REPOSITORY}|' "$COMPOSE_FILE"
  # Add AWS vars after RESTIC_PASSWORD line if not already present
  if ! grep -q "AWS_ACCESS_KEY_ID" "$COMPOSE_FILE"; then
    sed -i '/RESTIC_PASSWORD: \${RESTIC_PASSWORD}/a\      AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID}\n      AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY}' "$COMPOSE_FILE"
  fi
  ok "docker-compose.yml patched"

  # ── 6. Restart management container ───────────────────────────────────────
  echo ""
  info "Restarting management container to pick up new env vars..."
  cd "$SUPABASE_DIR"
  docker compose up -d --no-deps --force-recreate management
  ok "Management container restarted"

  # ── 7. Run first backup ────────────────────────────────────────────────────
  echo ""
  ask "Run first S3 backup now? [Y/n]: "; read -r run_now
  if [[ "${run_now,,}" != "n" ]]; then
    info "Running first backup (this may take a few minutes)..."
    if "$SUPABASE_DIR/supabase-backup.sh"; then
      ok "First backup to S3 complete!"
    else
      warn "Backup script returned an error — check output above"
    fi
  fi

  # ── 8. Clean up old Hetzner Storage Box mess ──────────────────────────────
  echo ""
  info "Cleaning up old Hetzner Storage Box files..."

  # Remove storagebox SSH keys
  REMOVED_KEYS=0
  for key in /root/.ssh/storagebox_* /root/.ssh/storagebox_*.pub; do
    [ -f "$key" ] || continue
    rm -f "$key"
    REMOVED_KEYS=$((REMOVED_KEYS + 1))
  done
  [ "$REMOVED_KEYS" -gt 0 ] && ok "Removed $REMOVED_KEYS SSH key file(s)" || info "No storagebox SSH keys found"

  # Remove storagebox entries from SSH config
  if [ -f /root/.ssh/config ] && grep -q "storagebox" /root/.ssh/config; then
    python3 - <<'PYEOF'
import re, sys
with open('/root/.ssh/config', 'r') as f:
    content = f.read()
# Remove Host storagebox-* blocks
content = re.sub(r'\n*Host storagebox-[^\n]+(\n    [^\n]+)*', '', content)
with open('/root/.ssh/config', 'w') as f:
    f.write(content.lstrip('\n'))
PYEOF
    ok "Removed storagebox entries from /root/.ssh/config"
  fi

  # Remove old local backup repos
  for old_dir in "/backups/$SERVER_NAME" "/root/backups/$SERVER_NAME" "/backups"; do
    if [ -d "$old_dir" ] && restic -r "$old_dir" cat config >/dev/null 2>&1; then
      ask "Found old local restic repo at $old_dir. Delete it? [y/N]: "; read -r del
      if [[ "${del,,}" == "y" ]]; then
        rm -rf "$old_dir"
        ok "Removed $old_dir"
      fi
    fi
  done

  # Remove sshpass if installed (no longer needed)
  if dpkg -l sshpass &>/dev/null 2>&1; then
    ask "Remove sshpass (no longer needed)? [Y/n]: "; read -r rm_sshpass
    if [[ "${rm_sshpass,,}" != "n" ]]; then
      apt-get remove -y -qq sshpass
      ok "sshpass removed"
    fi
  fi

  echo ""
  ok "S3 backup migration complete"
  echo -e "  Repository: ${C}${S3_REPO}${N}"
  echo -e "  Cron:       Daily 3 AM → /var/log/supabase-backup-${SERVER_NAME}.log"
  echo -e "  Admin panel Backups tab now shows S3 snapshots"
fi

# ══════════════════════════════════════════════════════════════════════════════
# TASK 2: DOMAIN CHANGE
# ══════════════════════════════════════════════════════════════════════════════
if $DO_DOMAIN; then
  header "Task 2: Change Domain"

  # Detect current domain from .env
  CURRENT_DOMAIN=$(grep "^SUPABASE_PUBLIC_URL=" "$ENV_FILE" | cut -d= -f2 | tr -d '"' || true)
  CURRENT_HOST="${CURRENT_DOMAIN#https://}"
  CURRENT_HOST="${CURRENT_HOST#http://}"

  if [ -n "$CURRENT_DOMAIN" ]; then
    info "Current domain: ${B}$CURRENT_DOMAIN${N}"
  else
    warn "Could not detect current domain from .env"
    ask "Current domain (with https://): "; read -r CURRENT_DOMAIN
    CURRENT_HOST="${CURRENT_DOMAIN#https://}"
  fi

  ask "New domain (with https://): "; read -r NEW_DOMAIN
  [ -n "$NEW_DOMAIN" ] || die "New domain required"
  NEW_HOST="${NEW_DOMAIN#https://}"
  NEW_HOST="${NEW_HOST#http://}"

  # Derive registered domain (last two parts: e.g. streamshop.me)
  CURRENT_REG=$(echo "$CURRENT_HOST" | awk -F. '{print $(NF-1)"."$NF}')
  NEW_REG=$(echo "$NEW_HOST" | awk -F. '{print $(NF-1)"."$NF}')

  echo ""
  echo -e "  ${CURRENT_DOMAIN}  →  ${G}${NEW_DOMAIN}${N}"
  ask "Confirm domain change? [Y/n]: "; read -r yn
  [[ "${yn,,}" != "n" ]] || die "Aborted"

  # ── 1. Update .env ─────────────────────────────────────────────────────────
  info "Updating .env..."
  sed -i "s|${CURRENT_DOMAIN}|${NEW_DOMAIN}|g" "$ENV_FILE"
  ok ".env updated"

  # ── 2. Update Caddyfile (uses {$DOMAIN} from env — only host references) ──
  if [ -f "$CADDYFILE" ]; then
    if grep -q "$CURRENT_HOST" "$CADDYFILE"; then
      info "Updating Caddyfile..."
      sed -i "s|${CURRENT_HOST}|${NEW_HOST}|g" "$CADDYFILE"
      ok "Caddyfile updated"
    else
      info 'Caddyfile uses env var {$DOMAIN} — no host literals to replace'
    fi
  else
    warn "Caddyfile not found at $CADDYFILE — skipping"
  fi

  # ── 3. Update Authelia configuration ───────────────────────────────────────
  if [ -f "$AUTHELIA_CFG" ]; then
    info "Updating Authelia configuration..."
    # Replace all occurrences of old host/domain/registered-domain
    sed -i "s|${CURRENT_HOST}|${NEW_HOST}|g" "$AUTHELIA_CFG"
    sed -i "s|${CURRENT_REG}|${NEW_REG}|g" "$AUTHELIA_CFG"
    # Also replace full URL occurrences
    sed -i "s|${CURRENT_DOMAIN}|${NEW_DOMAIN}|g" "$AUTHELIA_CFG"
    ok "Authelia configuration updated"
  else
    warn "Authelia config not found at $AUTHELIA_CFG — skipping (Authelia may not be enabled)"
  fi

  # ── 4. Clear Caddy TLS certs for old domain ────────────────────────────────
  CADDY_DATA="$SUPABASE_DIR/volumes/caddy/caddy_data"
  if [ -d "$CADDY_DATA" ]; then
    info "Clearing cached Caddy TLS data so it issues a new cert for $NEW_HOST..."
    rm -rf "${CADDY_DATA:?}/caddy/certificates"
    ok "Caddy TLS cache cleared"
  fi

  # ── 5. Restart affected containers ────────────────────────────────────────
  echo ""
  info "Restarting caddy and authelia..."
  cd "$SUPABASE_DIR"
  docker compose up -d --no-deps --force-recreate caddy authelia 2>/dev/null || \
    docker compose up -d --no-deps --force-recreate caddy
  ok "Containers restarted"

  echo ""
  ok "Domain change complete"
  echo -e "  ${Y}DNS:${N} Point your A record for ${B}${NEW_HOST}${N} to this server's IP"
  echo -e "  ${Y}TLS:${N} Caddy will auto-provision a Let's Encrypt cert once DNS propagates"
  echo ""
  warn "If using Cloudflare, set SSL mode to Full (not Full Strict) or use DNS-only mode"
fi

# ══════════════════════════════════════════════════════════════════════════════
# TASK 3: MCP SERVER INSTALLATION
# ══════════════════════════════════════════════════════════════════════════════
if $DO_MCP; then
  header "Task 3: Install MCP Server (Claude Integration)"

  # Detect deploy user from .env or prompt
  DEPLOY_USER=$(grep "^DEPLOY_USER=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
  if [ -z "$DEPLOY_USER" ]; then
    DEPLOY_USER="deploy"
    ask "Deploy user (default: deploy): "; read -r _u
    [ -n "$_u" ] && DEPLOY_USER="$_u"
  else
    info "Detected deploy user: ${B}$DEPLOY_USER${N}"
  fi

  id "$DEPLOY_USER" &>/dev/null || die "User '$DEPLOY_USER' does not exist"

  # Collect secrets from .env
  SUPABASE_URL=$(grep "^API_EXTERNAL_URL=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
  [ -z "$SUPABASE_URL" ] && SUPABASE_URL=$(grep "^SUPABASE_PUBLIC_URL=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
  SERVICE_ROLE_KEY=$(grep "^SERVICE_ROLE_KEY=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
  ANON_KEY=$(grep "^ANON_KEY=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
  JWT_SECRET=$(grep "^JWT_SECRET=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
  POSTGRES_PASSWORD=$(grep "^POSTGRES_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || true)

  [ -z "$SUPABASE_URL" ] && { ask "Supabase URL (e.g. https://api.example.com): "; read -r SUPABASE_URL; }
  [ -z "$SERVICE_ROLE_KEY" ] && { ask "Service Role Key: "; read -r SERVICE_ROLE_KEY; }
  [ -z "$POSTGRES_PASSWORD" ] && { ask "Postgres Password: "; read -r POSTGRES_PASSWORD; }

  # Install Node.js 20 if not present
  if ! command -v node &>/dev/null; then
    info "Installing Node.js 20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
    apt-get install -y -qq nodejs
    ok "Node.js installed: $(node --version)"
  else
    ok "Node.js already installed: $(node --version)"
  fi

  # Install git if missing
  command -v git &>/dev/null || apt-get install -y -qq git

  # Clone and build MCP server
  MCP_DIR="/home/${DEPLOY_USER}/mcp-server"
  info "Cloning mcp-supabase-self-hosted..."
  rm -rf "$MCP_DIR"
  git clone --depth 1 https://github.com/nadercas/supafast-mcp.git "$MCP_DIR" >/dev/null 2>&1
  ok "Repository cloned"

  info "Building MCP server..."
  cd "$MCP_DIR"
  npm install --quiet 2>/dev/null || true
  npm run build 2>/dev/null
  npm prune --omit=dev --quiet 2>/dev/null || true
  ok "MCP server built"

  # Write .mcp.env
  cat > "/home/${DEPLOY_USER}/.mcp.env" <<MCPENV
SUPABASE_URL="${SUPABASE_URL}"
SUPABASE_SERVICE_ROLE_KEY="${SERVICE_ROLE_KEY}"
SUPABASE_ANON_KEY="${ANON_KEY}"
SUPABASE_JWT_SECRET="${JWT_SECRET}"
POOLER_TENANT=$(grep "^POOLER_TENANT_ID=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "$SERVER_NAME")
SUPABASE_DB_URL="postgresql://postgres.${POOLER_TENANT}:${POSTGRES_PASSWORD}@localhost:5432/postgres"
MCPENV
  chmod 600 "/home/${DEPLOY_USER}/.mcp.env"
  chown "${DEPLOY_USER}:${DEPLOY_USER}" "/home/${DEPLOY_USER}/.mcp.env"
  ok "Environment file written"

  # Create wrapper script
  mkdir -p "/home/${DEPLOY_USER}/bin"
  cat > "/home/${DEPLOY_USER}/bin/supabase-mcp" <<'MCPWRAP'
#!/bin/bash
set -a
source "$HOME/.mcp.env"
set +a
exec node "$HOME/mcp-server/dist/server.js"
MCPWRAP
  chmod +x "/home/${DEPLOY_USER}/bin/supabase-mcp"
  chown -R "${DEPLOY_USER}:${DEPLOY_USER}" "$MCP_DIR" "/home/${DEPLOY_USER}/bin"
  ok "Wrapper script created at /home/${DEPLOY_USER}/bin/supabase-mcp"

  # Detect server IP and SSH key name for the .mcp.json hint
  SERVER_IP=$(hostname -I | awk '{print $1}')
  SERVER_NAME_HINT=$(grep "^SERVER_NAME=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "supabase-server")

  echo ""
  ok "MCP server installed."
  echo ""
  echo -e "  ${C}Add this to your local${N} ${B}~/.claude/mcp.json${N}${C} (or Cursor / Windsurf settings):${N}"
  echo ""
  cat <<MCPJSON
{
  "mcpServers": {
    "supabase-${SERVER_NAME_HINT}": {
      "command": "ssh",
      "args": [
        "-i", "~/.ssh/${SERVER_NAME_HINT}",
        "-o", "StrictHostKeyChecking=accept-new",
        "${DEPLOY_USER}@${SERVER_IP}",
        "/home/${DEPLOY_USER}/bin/supabase-mcp"
      ]
    }
  }
}
MCPJSON
  echo ""
  warn "Update the -i path to match your actual SSH key location."
fi

# ══════════════════════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${G}${B}All done.${N}"
echo ""
