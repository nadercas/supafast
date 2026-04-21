#!/bin/bash
set -euo pipefail
cd /opt/supabase/docker
REQ=./upgrade/rotate-request.json
RES=./upgrade/rotate-result.json
STATE=./upgrade/rotation-state.json
LOG=./upgrade/rotate.log
ENVFILE=./.env
KONGFILE=./volumes/api/kong.yml
[ -f "$REQ" ] || exit 0

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
write_result() {
  cat > "$RES" <<EOF
{"id":"${REQ_ID:-}","status":"$1","action":"${ACTION:-}","kid":"${KID:-}","message":"$2","at":"$(ts)"}
EOF
}

REQ_ID=$(jq -r '.id // ""' "$REQ")
ACTION=$(jq -r '.action // ""' "$REQ")
KID=$(jq -r '.kid // .bundle.kid // ""' "$REQ")
echo "[$(ts)] id=$REQ_ID action=$ACTION kid=$KID" >> "$LOG"

if [ ! -f "$STATE" ]; then
  python3 - "$ENVFILE" "$STATE" <<'SEEDPY'
import sys, json, re
env_path, state_path = sys.argv[1], sys.argv[2]
env = {}
for line in open(env_path):
    s = line.strip()
    if not s or s.startswith('#') or '=' not in s: continue
    k, v = s.split('=', 1)
    if (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
        v = v[1:-1]
    env[k] = v
jwt_keys = json.loads(env.get('JWT_KEYS', '[]'))
ec = next((k for k in jwt_keys if k.get('kty') == 'EC'), None)
jwks_all = json.loads(env.get('JWT_JWKS', '{"keys":[]}')).get('keys', [])
ec_pub = next((k for k in jwks_all if k.get('kty') == 'EC'), None)
active = []
if ec and ec_pub:
    active.append({
        'kid': ec.get('kid'),
        'private_jwk': ec,
        'public_jwk': ec_pub,
        'publishable_key': env.get('SUPABASE_PUBLISHABLE_KEY', ''),
        'secret_key': env.get('SUPABASE_SECRET_KEY', ''),
        'created_at': 'deploy',
    })
state = {
    'active_keys': active,
    'legacy': {
        'jwt_secret': env.get('JWT_SECRET', ''),
        'anon_key': env.get('ANON_KEY', ''),
        'service_role_key': env.get('SERVICE_ROLE_KEY', ''),
    },
}
open(state_path, 'w').write(json.dumps(state, indent=2))
SEEDPY
  chmod 600 "$STATE"
  echo "[$(ts)] seeded state from .env" >> "$LOG"
fi

python3 - "$REQ" "$STATE" "$ENVFILE" "$KONGFILE" <<'ROTATEPY' || { write_result "error" "rotation script failed"; exit 0; }
import sys, json, re, base64, os, tempfile

req_path, state_path, env_path, kong_path = sys.argv[1:5]
req = json.load(open(req_path))
state = json.load(open(state_path))
action = req.get('action')

if action == 'rotate':
    bundle = req.get('bundle') or {}
    if not bundle.get('kid'):
        print('rotate: missing bundle.kid', file=sys.stderr); sys.exit(1)
    if any(k['kid'] == bundle['kid'] for k in state['active_keys']):
        print('rotate: kid already active', file=sys.stderr); sys.exit(1)
    state['active_keys'].append({
        'kid': bundle['kid'],
        'private_jwk': bundle['private_jwk'],
        'public_jwk': bundle['public_jwk'],
        'publishable_key': bundle['publishable_key'],
        'secret_key': bundle['secret_key'],
        'created_at': bundle.get('created_at') or '',
    })
elif action == 'finalize':
    kid = req.get('kid')
    if not kid:
        print('finalize: missing kid', file=sys.stderr); sys.exit(1)
    if len(state['active_keys']) <= 1:
        print('finalize: refusing to remove the only active key', file=sys.stderr); sys.exit(1)
    before = len(state['active_keys'])
    state['active_keys'] = [k for k in state['active_keys'] if k['kid'] != kid]
    if len(state['active_keys']) == before:
        print('finalize: kid not found', file=sys.stderr); sys.exit(1)
else:
    print(f'unknown action: {action}', file=sys.stderr); sys.exit(1)

def hs256_jwk(secret):
    raw = secret.encode('utf-8')
    k = base64.urlsafe_b64encode(raw).decode().rstrip('=')
    return {'kty': 'oct', 'k': k, 'alg': 'HS256', 'kid': 'legacy'}

legacy = state['legacy']
hs = hs256_jwk(legacy['jwt_secret'])
# GoTrue JWT_KEYS: exactly one key with key_ops ["sign"] (newest active),
# all others verify-only. HS256 stays out of this set (handled by GOTRUE_JWT_SECRET).
active = state['active_keys']
priv_keys = []
for i, k in enumerate(active):
    jwk = dict(k['private_jwk']) if i == len(active) - 1 else dict(k['public_jwk'])
    jwk['key_ops'] = ['sign'] if i == len(active) - 1 else ['verify']
    priv_keys.append(jwk)
# Verification JWKS for PostgREST/Storage/Realtime: public EC keys + HS256 oct.
pub_keys = [k['public_jwk'] for k in active] + [hs]

jwt_keys_val = json.dumps(priv_keys, separators=(',', ':'))
jwt_jwks_val = json.dumps({'keys': pub_keys}, separators=(',', ':'))

newest = state['active_keys'][-1]
publishable = newest['publishable_key']
secret = newest['secret_key']

def update_env(path, updates):
    lines = open(path).read().split('\n')
    seen = set()
    out = []
    for line in lines:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if m and m.group(1) in updates:
            k = m.group(1)
            v = updates[k]
            if v.startswith('[') or v.startswith('{'):
                out.append(f"{k}='{v}'")
            else:
                out.append(f"{k}={v}")
            seen.add(k)
        else:
            out.append(line)
    for k, v in updates.items():
        if k not in seen:
            if v.startswith('[') or v.startswith('{'):
                out.append(f"{k}='{v}'")
            else:
                out.append(f"{k}={v}")
    open(path, 'w').write('\n'.join(out))

update_env(env_path, {
    'JWT_KEYS': jwt_keys_val,
    'JWT_JWKS': jwt_jwks_val,
    'SUPABASE_PUBLISHABLE_KEY': publishable,
    'SUPABASE_SECRET_KEY': secret,
})

kong = open(kong_path).read()
anon_creds = [f"      - key: {legacy['anon_key']}"]
service_creds = [f"      - key: {legacy['service_role_key']}"]
for k in state['active_keys']:
    anon_creds.append(f"      - key: {k['publishable_key']}")
    service_creds.append(f"      - key: {k['secret_key']}")

block = "# SUPAFAST_CONSUMERS_BEGIN — managed by supabase-rotate-keys.sh; do not edit by hand\n"
block += "  - username: anon\n    keyauth_credentials:\n" + "\n".join(anon_creds) + "\n"
block += "  - username: service_role\n    keyauth_credentials:\n" + "\n".join(service_creds) + "\n"
block += "# SUPAFAST_CONSUMERS_END"

new_kong = re.sub(
    r"# SUPAFAST_CONSUMERS_BEGIN.*?# SUPAFAST_CONSUMERS_END",
    lambda _: block,
    kong,
    count=1,
    flags=re.DOTALL,
)
if new_kong == kong:
    print('kong.yml: markers not found', file=sys.stderr); sys.exit(1)

fd, tmp = tempfile.mkstemp(dir=os.path.dirname(kong_path))
os.write(fd, new_kong.encode('utf-8'))
os.close(fd)
os.chmod(tmp, 0o644)
os.replace(tmp, kong_path)

fd, tmp = tempfile.mkstemp(dir=os.path.dirname(state_path))
os.write(fd, json.dumps(state, indent=2).encode('utf-8'))
os.close(fd)
os.replace(tmp, state_path)
ROTATEPY

chmod 600 "$STATE" "$ENVFILE"
chmod 644 "$KONGFILE"

echo "[$(ts)] reloading services" >> "$LOG"
docker compose up -d --no-deps --force-recreate kong auth rest realtime storage >> "$LOG" 2>&1 || true

write_result "ok" "rotation applied; ${ACTION} complete"
