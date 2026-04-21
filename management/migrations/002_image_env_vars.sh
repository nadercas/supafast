#!/bin/bash
# @summary: Structural parity for pre-6ed886c servers (upgrade mount, socket-proxy swap, image env vars)
# @touches: .env, docker-compose.yml
# @restarts: docker-socket-proxy, management, studio, kong, auth, rest, realtime, storage, imgproxy, meta, functions, analytics, vector, supavisor
#
# Migration 002 — bring pre-6ed886c servers to structural parity with fresh
# deploys. Idempotent. Does three independent steps:
#
#   1. Ensure ./upgrade:/supabase/upgrade rw mount on the management service
#      (needed for migrations/rotate/upgrade/pin trigger files).
#   2. Switch docker-socket-proxy to lscr.io/linuxserver/socket-proxy — the
#      tecnativa image denies all POST globally when POST=0, which breaks
#      the restart/stop buttons in the panel.
#   3. Extract hardcoded image: tags from compose into IMAGE_* env vars in
#      .env and rewrite the compose lines to ${IMAGE_*} so the per-service
#      Upgrade buttons (and their "current tag" display) work — including
#      'management' which becomes upgradable from the Service Upgrades list.

set -uo pipefail
cd /opt/supabase/docker

ENVFILE=./.env
COMPOSE=./docker-compose.yml

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "[$(ts)] [mig-002] $*"; }

[ -f "$ENVFILE" ]  || { log "ERROR: $ENVFILE not found"; exit 1; }
[ -f "$COMPOSE" ]  || { log "ERROR: $COMPOSE not found"; exit 1; }

CHANGED_COMPOSE=0
RECREATE_SVCS=""

# ── 1. upgrade/ rw mount on management ───────────────────────────────────────
if grep -qE '^\s*-\s*\./upgrade:/supabase/upgrade\s*$' "$COMPOSE"; then
  log "upgrade mount already present"
else
  log "adding ./upgrade:/supabase/upgrade rw mount to management service"
  mkdir -p ./upgrade
  # Insert after the functions .env mount line on the management block.
  sed -i '/- \.\/volumes\/functions\/\.env:\/supabase\/volumes\/functions\/\.env/a\      - ./upgrade:/supabase/upgrade' "$COMPOSE"
  CHANGED_COMPOSE=1
  RECREATE_SVCS="$RECREATE_SVCS management"
fi

# ── 2. docker-socket-proxy → linuxserver fork ────────────────────────────────
if grep -qE '^\s*image:\s*lscr\.io/linuxserver/socket-proxy' "$COMPOSE"; then
  log "socket-proxy already on linuxserver fork"
else
  log "switching docker-socket-proxy image to lscr.io/linuxserver/socket-proxy:latest"
  # Replace only the image line inside the docker-socket-proxy block.
  python3 - "$COMPOSE" <<'PY'
import sys, re
from pathlib import Path
p = sys.argv[1]
txt = Path(p).read_text()
txt = re.sub(
    r'(^  docker-socket-proxy:\n(?:(?! {0,2}\S).*\n)*?)(    image:\s*)\S+\n',
    r'\1\2lscr.io/linuxserver/socket-proxy:latest\n',
    txt, count=1, flags=re.MULTILINE,
)
Path(p).write_text(txt)
PY
  CHANGED_COMPOSE=1
  RECREATE_SVCS="$RECREATE_SVCS docker-socket-proxy management"
fi

# ── 3. parameterize image tags ───────────────────────────────────────────────
if grep -q '^IMAGE_AUTH=' "$ENVFILE"; then
  log "image tags already parameterized"
else
  log "parameterizing image tags in docker-compose.yml"
  python3 - "$COMPOSE" "$ENVFILE" <<'PY'
import sys, re
from pathlib import Path

compose_path, env_path = sys.argv[1], sys.argv[2]
txt = Path(compose_path).read_text()

mapping = [
    ('supabase-studio', 'IMAGE_STUDIO'),
    ('kong',            'IMAGE_KONG'),
    ('auth',            'IMAGE_AUTH'),
    ('rest',            'IMAGE_REST'),
    ('realtime',        'IMAGE_REALTIME'),
    ('storage',         'IMAGE_STORAGE'),
    ('imgproxy',        'IMAGE_IMGPROXY'),
    ('meta',            'IMAGE_META'),
    ('functions',       'IMAGE_FUNCTIONS'),
    ('analytics',       'IMAGE_LOGFLARE'),
    ('vector',          'IMAGE_VECTOR'),
    ('supavisor',       'IMAGE_SUPAVISOR'),
    ('management',      'IMAGE_MANAGEMENT'),
]

pinned = {}
for svc, envkey in mapping:
    svc_re = re.compile(
        r'(^  ' + re.escape(svc) + r':\n(?:(?! {0,2}\S).*\n)*?)(    image:\s*)(\S+)\n',
        re.MULTILINE,
    )
    m = svc_re.search(txt)
    if not m:
        continue
    head, image_prefix, current = m.group(1), m.group(2), m.group(3)
    if current.startswith('${') and current.endswith('}'):
        continue
    pinned[envkey] = current
    repl = head + image_prefix + '${' + envkey + '}\n'
    txt = txt[:m.start()] + repl + txt[m.end():]

Path(compose_path).write_text(txt)

if pinned:
    env = Path(env_path).read_text()
    additions = ["", "############",
                 "# Service image pins (added by supafast migration 002)",
                 "############"]
    for k, v in pinned.items():
        additions.append(f"{k}={v}")
    with open(env_path, 'a') as f:
        f.write("\n".join(additions) + "\n")
PY
  chmod 600 "$ENVFILE"
  CHANGED_COMPOSE=1
  RECREATE_SVCS="$RECREATE_SVCS supabase-studio kong auth rest realtime storage imgproxy meta functions analytics vector supavisor management"
fi

[ "$CHANGED_COMPOSE" = "1" ] && chmod 644 "$COMPOSE"

# ── 4. recreate affected services ────────────────────────────────────────────
# Deduplicate service list while preserving order.
RECREATE_SVCS=$(echo $RECREATE_SVCS | tr ' ' '\n' | awk '!seen[$0]++' | tr '\n' ' ')
if [ -n "$RECREATE_SVCS" ]; then
  log "recreating: $RECREATE_SVCS"
  docker compose up -d --force-recreate $RECREATE_SVCS >/dev/null 2>&1 || \
    log "WARN: docker compose recreate exited non-zero; check logs"
else
  log "no services to recreate"
fi

log "migration 002 complete"
