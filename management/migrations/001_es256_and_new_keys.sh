#!/bin/bash
# @summary: ES256 JWT + new-format API keys + rotation/upgrade/pin host scripts
# @touches: .env, volumes/api/kong.yml, docker-compose.yml, /usr/local/bin/supabase-*.sh, systemd units
# @restarts: auth, rest, realtime, storage, meta, kong
#
# Migration 001 — ES256 JWT + new-format API keys + rotation/upgrade/pin hostbin
# Idempotent. Brings pre-6ed886c servers up to that commit's feature set.
#
# Runs as root from /opt/supabase/docker. Assets (frozen host scripts) live in
# the sibling directory 001_es256_and_new_keys/ next to this file.

set -uo pipefail
cd /opt/supabase/docker

ENVFILE=./.env
KONGFILE=./volumes/api/kong.yml
COMPOSE=./docker-compose.yml
ASSETS="$(dirname "$(readlink -f "$0")")/001_es256_and_new_keys"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "[$(ts)] [mig-001] $*"; }

[ -f "$ENVFILE" ]   || { log "ERROR: $ENVFILE not found"; exit 1; }
[ -f "$KONGFILE" ]  || { log "ERROR: $KONGFILE not found"; exit 1; }
[ -f "$COMPOSE" ]   || { log "ERROR: $COMPOSE not found"; exit 1; }
[ -d "$ASSETS" ]    || { log "ERROR: assets dir $ASSETS not found"; exit 1; }

# ── 1. ES256 keypair + new-format API keys in .env ───────────────────────────
if grep -q '^JWT_KEYS=' "$ENVFILE"; then
  log ".env already has JWT_KEYS — skipping key generation"
else
  log "generating ES256 keypair + sb_publishable_*/sb_secret_* keys"
  python3 - "$ENVFILE" <<'PY'
import sys, os, json, secrets, base64, re, subprocess, tempfile
from pathlib import Path

env_path = sys.argv[1]
env = {}
for line in Path(env_path).read_text().splitlines():
    s = line.strip()
    if not s or s.startswith('#') or '=' not in s: continue
    k, v = s.split('=', 1)
    if (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
        v = v[1:-1]
    env[k] = v

# Generate P-256 key via openssl, parse d/x/y from -text output.
with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as f:
    tmp = f.name
try:
    subprocess.check_call(
        ['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', tmp],
        stderr=subprocess.DEVNULL,
    )
    text = subprocess.check_output(
        ['openssl', 'ec', '-in', tmp, '-text', '-noout'],
        stderr=subprocess.DEVNULL,
    ).decode()
finally:
    os.unlink(tmp)

def grab(label):
    m = re.search(label + r'\s*:\s*\n((?:\s+[0-9a-f:\s]+\n)+)', text)
    if not m: return None
    return bytes.fromhex(re.sub(r'[:\s]', '', m.group(1)))

priv = grab('priv')
pub  = grab('pub')
if not priv or not pub or pub[0] != 0x04:
    sys.exit("failed to parse EC keypair")
# P-256 scalar is 32 bytes; left-pad if openssl stripped leading zeros.
priv = priv.rjust(32, b'\x00')
x, y = pub[1:33], pub[33:65]

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

kid = 'k' + secrets.token_hex(6)
priv_jwk = {"kty":"EC","crv":"P-256","kid":kid,"alg":"ES256","key_ops":["sign"],
            "d":b64u(priv),"x":b64u(x),"y":b64u(y)}
pub_jwk  = {"kty":"EC","crv":"P-256","kid":kid,"alg":"ES256","key_ops":["verify"],
            "x":b64u(x),"y":b64u(y)}

jwt_keys = [priv_jwk]
jwt_jwks = [pub_jwk]
# Keep verify-only legacy HS256 so pre-rotation anon/service_role tokens still work.
if env.get('JWT_SECRET'):
    legacy = {"kty":"oct","kid":"legacy","alg":"HS256","key_ops":["verify"],
              "k": b64u(env['JWT_SECRET'].encode())}
    jwt_keys.append(legacy)
    jwt_jwks.append(legacy)

# New-format opaque API keys. Format mirrors Supabase cloud: sb_publishable_ / sb_secret_
# followed by 32+ urlsafe-b64 chars (no padding).
def random_token(nbytes):
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).rstrip(b'=').decode()
pub_api = 'sb_publishable_' + random_token(24)[:32]
sec_api = 'sb_secret_'      + random_token(32)[:40]

additions = []
additions.append(f"JWT_KEYS='{json.dumps(jwt_keys, separators=(',',':'))}'")
additions.append(f"JWT_JWKS='{json.dumps({'keys': jwt_jwks}, separators=(',',':'))}'")
if 'SUPABASE_PUBLISHABLE_KEY' not in env:
    additions.append(f"SUPABASE_PUBLISHABLE_KEY={pub_api}")
if 'SUPABASE_SECRET_KEY' not in env:
    additions.append(f"SUPABASE_SECRET_KEY={sec_api}")

with open(env_path, 'a') as f:
    f.write("\n# Added by supafast migration 001 (ES256 + new-format API keys)\n")
    f.write("\n".join(additions) + "\n")
PY
  chmod 600 "$ENVFILE"
fi

# ── 2. kong.yml: SUPAFAST_CONSUMERS block ────────────────────────────────────
if grep -q 'SUPAFAST_CONSUMERS_BEGIN' "$KONGFILE"; then
  log "kong.yml already has SUPAFAST_CONSUMERS block — skipping"
else
  log "injecting SUPAFAST_CONSUMERS block into kong.yml"
  PUB_KEY=$(grep -E '^SUPABASE_PUBLISHABLE_KEY=' "$ENVFILE" | head -n1 | cut -d= -f2-)
  SEC_KEY=$(grep -E '^SUPABASE_SECRET_KEY='      "$ENVFILE" | head -n1 | cut -d= -f2-)
  python3 - "$KONGFILE" "$PUB_KEY" "$SEC_KEY" <<'PY'
import sys, re
from pathlib import Path
path, pub, sec = sys.argv[1:4]
txt = Path(path).read_text()
block = f"""
# SUPAFAST_CONSUMERS_BEGIN — managed by supabase-rotate-keys.sh; do not edit by hand
  - username: anon_pub
    keyauth_credentials:
      - key: {pub}
    acls:
      - group: anon
  - username: service_role_sec
    keyauth_credentials:
      - key: {sec}
    acls:
      - group: admin
# SUPAFAST_CONSUMERS_END
"""
m = re.search(r'^consumers:\s*\n', txt, re.MULTILINE)
if m:
    tail = txt[m.end():]
    nxt = re.search(r'^[A-Za-z][A-Za-z0-9_-]*:', tail, re.MULTILINE)
    insert_at = m.end() + (nxt.start() if nxt else len(tail))
    new = txt[:insert_at] + block + txt[insert_at:]
else:
    new = txt.rstrip() + "\n\nconsumers:\n" + block
Path(path).write_text(new)
PY
  chmod 644 "$KONGFILE"
fi

# ── 3. docker-compose.yml: add JWT_KEYS / JWT_JWKS env vars to services ──────
if grep -q 'GOTRUE_JWT_KEYS' "$COMPOSE"; then
  log "docker-compose.yml already patched — skipping"
else
  log "patching docker-compose.yml env vars for auth/rest/realtime/storage/meta"
  cp -a "$COMPOSE" "$COMPOSE.mig001.bak"
  python3 - "$COMPOSE" <<'PY'
import sys, re
from pathlib import Path
path = sys.argv[1]
txt = Path(path).read_text()

def add_env(text, service, env_line):
    # Find '  service:\n' then the first '    environment:\n' inside its block.
    svc_re = re.compile(r'(^  ' + re.escape(service) + r':\n(?:(?! {0,2}\S).*\n)*?    environment:\n)', re.MULTILINE)
    m = svc_re.search(text)
    if not m: return text
    end = m.end()
    # Determine the environment block extent (lines indented by 6+ spaces or blank).
    tail = text[end:]
    blk_end = 0
    for line in tail.split('\n'):
        if line.startswith('      ') or line.strip() == '':
            blk_end += len(line) + 1
        else:
            break
    block = text[end:end+blk_end]
    key = env_line.split(':')[0].strip()
    if re.search(r'^      ' + re.escape(key) + r'\s*:', block, re.MULTILINE):
        return text
    return text[:end] + f"      {env_line}\n" + text[end:]

txt = add_env(txt, 'auth',     'GOTRUE_JWT_KEYS: ${JWT_KEYS}')
txt = add_env(txt, 'rest',     'PGRST_JWT_SECRET: ${JWT_JWKS}')
txt = add_env(txt, 'realtime', 'API_JWT_JWKS: ${JWT_JWKS}')
txt = add_env(txt, 'storage',  'JWT_JWKS: ${JWT_JWKS}')
txt = add_env(txt, 'meta',     'JWT_JWKS: ${JWT_JWKS}')
Path(path).write_text(txt)
PY
fi

# ── 4. Install hostbin scripts + systemd units ───────────────────────────────
mkdir -p ./hostbin
for s in supabase-rotate-keys.sh supabase-upgrade.sh supabase-pin-digests.sh; do
  src="$ASSETS/$s"
  [ -f "$src" ] || { log "WARN: asset $s missing; skipping"; continue; }
  if ! cmp -s "$src" "/usr/local/bin/$s" 2>/dev/null; then
    log "installing /usr/local/bin/$s"
    install -D -m 755 "$src" "/usr/local/bin/$s"
  fi
  cp -f "$src" "./hostbin/$s"
  chmod 755 "./hostbin/$s"
done

install_unit() {
  local name=$1 trigger=$2 svc_bin=$3 desc=$4
  if [ -f "/etc/systemd/system/$name.path" ] && [ -f "/etc/systemd/system/$name.service" ]; then
    return 0
  fi
  log "creating systemd unit $name (watches $trigger)"
  cat > "/etc/systemd/system/$name.service" <<SVC
[Unit]
Description=$desc executor
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=/opt/supabase/docker
ExecStart=/usr/local/bin/$svc_bin
SVC
  cat > "/etc/systemd/system/$name.path" <<PU
[Unit]
Description=Watch $desc trigger file

[Path]
PathModified=/opt/supabase/docker/upgrade/$trigger
Unit=$name.service

[Install]
WantedBy=multi-user.target
PU
  systemctl daemon-reload
  systemctl enable --now "$name.path"
}

mkdir -p ./upgrade
install_unit supabase-rotate  rotate-request.json  supabase-rotate-keys.sh  "SupaFast key rotation"
install_unit supabase-upgrade request.json         supabase-upgrade.sh      "SupaFast service upgrade"
install_unit supabase-pin     pin-request.json     supabase-pin-digests.sh  "SupaFast image pin"

# ── 5. Recreate services so new env vars take effect ─────────────────────────
log "recreating auth, rest, realtime, storage, meta, kong"
docker compose up -d --force-recreate auth rest realtime storage meta kong >> /dev/null 2>&1 || \
  log "WARN: docker compose recreate exited non-zero; check logs"

log "migration 001 complete"
