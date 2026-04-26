#!/bin/bash
# supabase-audit-jwt.sh — check that a supafast-managed Supabase box has the
# post-ES256-rotation env wiring correct. Fixes in-place when --fix is passed.
#
# Checks:
#   1. rest.PGRST_JWT_SECRET resolves to ${JWT_JWKS} (not ${JWT_SECRET})
#   2. realtime.METRICS_JWT_SECRET is present (required by realtime >= v2.86)
#   3. JWT_JWKS contains both an ES256 verify key and the legacy HS256 key
#
# Usage: sudo supabase-audit-jwt.sh [--fix]
set -euo pipefail
cd /opt/supabase/docker
COMPOSE=./docker-compose.yml
ENVFILE=./.env
FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

fail=0
say() { echo "[audit] $*"; }
bad() { echo "[audit] FAIL: $*"; fail=1; }
fix() { echo "[audit] FIX:  $*"; }

# --- 1. rest.PGRST_JWT_SECRET ------------------------------------------------
rest_line=$(awk '
  /^  rest:/ {in_svc=1}
  in_svc && /^  [a-z]/ && !/^  rest:/ {in_svc=0}
  in_svc && /PGRST_JWT_SECRET:/ {print; exit}
' "$COMPOSE")

if [[ "$rest_line" != *'${JWT_JWKS}'* ]]; then
  bad "rest.PGRST_JWT_SECRET should be \${JWT_JWKS}, found: ${rest_line:-<missing>}"
  if [ "$FIX" = 1 ]; then
    cp -a "$COMPOSE" "$COMPOSE.audit.bak.$(date +%s)"
    python3 - "$COMPOSE" <<'PY'
import sys, re
from pathlib import Path
p = Path(sys.argv[1]); t = p.read_text()
svc = re.compile(r'(^  rest:\n(?:(?! {0,2}\S).*\n)*?    environment:\n)', re.M)
m = svc.search(t)
if m:
    start = m.end(); tail = t[start:]; blk_end = 0
    for line in tail.split('\n'):
        if line.startswith('      ') or line.strip() == '':
            blk_end += len(line) + 1
        else: break
    block = t[start:start+blk_end]
    pat = re.compile(r'^      PGRST_JWT_SECRET\s*:.*\n', re.M)
    new = pat.sub('      PGRST_JWT_SECRET: ${JWT_JWKS}\n', block, count=1) \
          if pat.search(block) else '      PGRST_JWT_SECRET: ${JWT_JWKS}\n' + block
    p.write_text(t[:start] + new + t[start+blk_end:])
PY
    fix "set rest.PGRST_JWT_SECRET = \${JWT_JWKS}"
  fi
fi

# --- 2. realtime.METRICS_JWT_SECRET -----------------------------------------
rt_metrics=$(awk '
  /^  realtime:/ {in_svc=1}
  in_svc && /^  [a-z]/ && !/^  realtime:/ {in_svc=0}
  in_svc && /METRICS_JWT_SECRET:/ {print; exit}
' "$COMPOSE")

if [ -z "$rt_metrics" ]; then
  bad "realtime.METRICS_JWT_SECRET missing (realtime >= v2.86 will crash at boot)"
  if [ "$FIX" = 1 ]; then
    cp -a "$COMPOSE" "$COMPOSE.audit.bak.$(date +%s)"
    python3 - "$COMPOSE" <<'PY'
import sys, re
from pathlib import Path
p = Path(sys.argv[1]); t = p.read_text()
svc = re.compile(r'(^  realtime:\n(?:(?! {0,2}\S).*\n)*?    environment:\n)', re.M)
m = svc.search(t)
if m:
    p.write_text(t[:m.end()] + '      METRICS_JWT_SECRET: ${JWT_SECRET}\n' + t[m.end():])
PY
    fix "added realtime.METRICS_JWT_SECRET"
  fi
fi

# --- 3. .env JWT_JWKS shape --------------------------------------------------
if ! sudo -n grep -q '^JWT_JWKS=' "$ENVFILE" 2>/dev/null; then
  bad ".env missing JWT_JWKS (ES256 rotation never completed on this box)"
else
  jwks=$(sudo grep '^JWT_JWKS=' "$ENVFILE" | sed "s/^JWT_JWKS=//; s/^'//; s/'$//")
  echo "$jwks" | python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
ks = d.get('keys', [])
has_es = any(k.get('alg')=='ES256' and 'verify' in k.get('key_ops',[]) for k in ks)
has_hs = any(k.get('alg')=='HS256' and 'verify' in k.get('key_ops',[]) for k in ks)
sys.exit(0 if has_es and has_hs else 1)
" || bad "JWT_JWKS must contain both an ES256 verify key and a legacy HS256 key"
fi

if [ "$fail" = 0 ]; then
  say "OK — JWT env wiring is consistent"
  exit 0
fi

if [ "$FIX" = 1 ]; then
  say "applied fixes — run: docker compose up -d rest realtime"
  exit 0
fi

echo "[audit] rerun with --fix to repair, then: docker compose up -d rest realtime"
exit 1
