#!/bin/bash
# migration_to_v1.1.sh
#
# One-shot upgrade script for SupaFast servers deployed before the migration
# infrastructure (pre-6ed886c). Brings them up to a state where the Upgrades
# tab in the management panel works and bundled migrations 001–004 can be
# applied from the UI.
#
# What this script does (host-side, idempotent):
#   1. Adds `./upgrade:/supabase/upgrade:rw` volume to the management service
#      in docker-compose.yml — the panel needs it writable to queue migrations.
#   2. Pulls the latest management image, recreates the container, restarts
#      Caddy (which caches container DNS).
#   3. Runs the management container's bootstrap endpoint to install the host
#      runners (/usr/local/bin/supafast-migrate.sh, supabase-pin-digests.sh)
#      and their systemd path units, and to seed /opt/supabase/docker/.supafast-version.
#
# What this script does NOT do:
#   - Apply the migrations themselves. After this script finishes, open the
#     management panel → Upgrades tab → "Apply pending". The runner will apply
#     001–004 in order and snapshot-roll-back on failure.
#
# Critical note for servers <8GB RAM: your kernel has fs.nr_open = 131072
# (time bomb — reboot will brick containerd). Migration 004 fixes it live.
# Do NOT reboot between running this script and applying migrations.
#
# Usage (run on the SupaFast server):
#   curl -fsSL https://raw.githubusercontent.com/nadercas/supafast/main/migration_to_v1.1.sh | sudo bash
# or:
#   sudo bash migration_to_v1.1.sh

set -euo pipefail

SUPABASE_DIR=/opt/supabase/docker
COMPOSE="$SUPABASE_DIR/docker-compose.yml"

log() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
ok()  { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }
warn(){ printf '    \033[1;33m!\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash $0)"
[ -f "$COMPOSE" ] || die "$COMPOSE not found — is this a SupaFast server?"
command -v docker >/dev/null || die "docker not installed"
docker compose version >/dev/null 2>&1 || die "docker compose plugin not installed"

cd "$SUPABASE_DIR"

# ── Step 1: Ensure writable upgrade mount on management service ──────────────
log "Step 1/3  Ensuring ./upgrade:/supabase/upgrade:rw on management service"

if grep -q './upgrade:/supabase/upgrade' "$COMPOSE"; then
  ok "mount already present — skipping"
else
  cp "$COMPOSE" "${COMPOSE}.pre-v1.1-backup"
  python3 - "$COMPOSE" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
new = re.sub(
    r'(  management:\n(?:[^\n]*\n)*?    volumes:\n((?:      - [^\n]+\n)+))',
    lambda m: m.group(1) + '      - ./upgrade:/supabase/upgrade:rw\n',
    s, count=1,
)
if new == s:
    sys.exit("ERROR: could not locate management.volumes block in docker-compose.yml")
open(p, 'w').write(new)
PY
  ok "mount added (backup: ${COMPOSE}.pre-v1.1-backup)"
fi

mkdir -p "$SUPABASE_DIR/upgrade"

# ── Step 2: Pull + recreate management, restart caddy ────────────────────────
log "Step 2/3  Pulling new management image and recreating"

docker compose pull management
docker compose up -d management
ok "management recreated"

docker compose restart caddy
ok "caddy restarted (DNS cache cleared)"

# Give the management container a moment to bind :3001
sleep 3

# ── Step 3: Install migration runners via bootstrap endpoint ─────────────────
log "Step 3/3  Installing host runners + systemd path units (bootstrap)"

MGMT_ID=$(docker compose ps -q management)
[ -n "$MGMT_ID" ] || die "management container not running"

MGMT_IP=$(docker inspect "$MGMT_ID" \
  --format '{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' \
  | awk '{print $1}')
[ -n "$MGMT_IP" ] || die "could not read management container IP"

curl -fsSL "http://$MGMT_IP:3001/api/migrations/bootstrap.sh" | bash

# ── Verify ───────────────────────────────────────────────────────────────────
log "Verifying installation"

[ -x /usr/local/bin/supafast-migrate.sh ]     && ok "supafast-migrate.sh installed"    || warn "supafast-migrate.sh missing"
[ -x /usr/local/bin/supabase-pin-digests.sh ] && ok "supabase-pin-digests.sh installed" || warn "supabase-pin-digests.sh missing"

systemctl is-enabled --quiet supafast-migrate.path && ok "supafast-migrate.path enabled" || warn "supafast-migrate.path NOT enabled"
systemctl is-enabled --quiet supabase-pin.path     && ok "supabase-pin.path enabled"     || warn "supabase-pin.path NOT enabled"

VERSION=$(cat "$SUPABASE_DIR/.supafast-version" 2>/dev/null || echo missing)
ok ".supafast-version = $VERSION"

# ── Done ─────────────────────────────────────────────────────────────────────
cat <<'DONE'

────────────────────────────────────────────────────────────────────
 Host-side upgrade complete.

 Next step → open the management panel → Upgrades tab → "Apply pending".

 The panel will apply migrations 001 → 004 in order. Each snapshots
 state before running and auto-rolls-back on failure.

 Summary of what the migrations do:
   001  ES256 JWT + new API keys   (additive, no downtime)
   002  Structural parity          (~30s downtime on most services)
   003  Bump image versions        (~30–60s downtime on most services)
   004  fs.nr_open kernel-limit    (critical — prevents next-reboot brick)

 If a migration fails, check:   sudo tail -100 /opt/supabase/docker/upgrade/migrate.log
────────────────────────────────────────────────────────────────────
DONE
